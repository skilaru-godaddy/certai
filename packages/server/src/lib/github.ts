import { Octokit } from '@octokit/rest';
import type { RepoRef, RepoFile, RepoSnapshot, CveFinding, SemgrepFinding } from '../types.js';

// ─── URL parsing ─────────────────────────────────────────────────────────────

export function parseRepoUrl(raw: string): RepoRef {
  const cleaned = raw.replace(/^https?:\/\//, '').replace(/\/$/, '');
  const parts = cleaned.split('/');
  if (parts.length < 3) throw new Error(`Invalid repo URL: ${raw}`);
  const [host, owner, repo] = parts;
  return { host, owner, repo };
}

// ─── File prioritization ──────────────────────────────────────────────────────

const PRIORITY_PATTERNS: Array<(p: string) => boolean> = [
  (p) => /^readme\.md$/i.test(p),
  (p) => /^(package\.json|requirements\.txt|go\.mod|pom\.xml|build\.gradle)$/.test(p),
  (p) => /^(dockerfile|docker-compose\.yml|docker-compose\.yaml)$/i.test(p),
  (p) => /\.(tf|tfvars)$/.test(p) || /cdk-stack\.(ts|js)$/.test(p) || /template\.ya?ml$/.test(p),
  (p) => /(auth|middleware)\.(ts|js|py|go|rb)$/.test(p),
  (p) => /(route|router|api|controller)\.(ts|js|py|go|rb)$/.test(p),
  (p) => /^\.env\.example$/.test(p),
  (p) => /(model|schema|db|database|migration)\.(ts|js|py|go|rb)$/.test(p),
];

export function prioritizeFiles(allPaths: string[]): string[] {
  const buckets: string[][] = PRIORITY_PATTERNS.map(() => []);
  const rest: string[] = [];

  for (const p of allPaths) {
    let matched = false;
    for (let i = 0; i < PRIORITY_PATTERNS.length; i++) {
      if (PRIORITY_PATTERNS[i](p)) {
        buckets[i].push(p);
        matched = true;
        break;
      }
    }
    if (!matched) rest.push(p);
  }

  const ordered = [...buckets.flat(), ...rest];
  return ordered.slice(0, 14);
}

// ─── GitHub client ────────────────────────────────────────────────────────────

export function createGitHubClient(pat: string, baseUrl: string) {
  return new Octokit({
    auth: pat,
    baseUrl,
  });
}

export async function fetchRepoSnapshot(ref: RepoRef): Promise<RepoSnapshot> {
  const pat = process.env.GITHUB_PAT!;
  const baseUrl = process.env.GITHUB_API_URL!;
  const octokit = createGitHubClient(pat, baseUrl);

  // Get full file tree
  const { data: commit } = await octokit.repos.getCommit({
    owner: ref.owner,
    repo: ref.repo,
    ref: 'HEAD',
  });
  const treeSha = commit.commit.tree.sha;

  const { data: tree } = await octokit.git.getTree({
    owner: ref.owner,
    repo: ref.repo,
    tree_sha: treeSha,
    recursive: '1',
  });

  const allPaths = (tree.tree ?? [])
    .filter((item) => item.type === 'blob' && item.path)
    .map((item) => item.path!);

  const priorityPaths = prioritizeFiles(allPaths);

  // Fetch priority files in parallel (max 14)
  const priorityFiles = await Promise.all(
    priorityPaths.map(async (path): Promise<RepoFile> => {
      try {
        const { data } = await octokit.repos.getContent({
          owner: ref.owner,
          repo: ref.repo,
          path,
        });
        if (Array.isArray(data) || data.type !== 'file') {
          return { path, content: '[directory or non-file]', sizeBytes: 0 };
        }
        const content = Buffer.from(data.content, 'base64').toString('utf-8');
        return { path, content: content.slice(0, 8000), sizeBytes: data.size };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes('404')) {
          return { path, content: '[file not found — may have been deleted]', sizeBytes: 0 };
        }
        if (msg.includes('403')) {
          return { path, content: '[access denied — check PAT scopes]', sizeBytes: 0 };
        }
        return { path, content: `[fetch error: ${msg}]`, sizeBytes: 0 };
      }
    })
  );

  // Human-readable tree (up to 500 paths for Claude triage pass)
  const treeText = allPaths.slice(0, 500).join('\n');

  return { ref, allPaths, priorityFiles, treeText };
}

export async function fetchDependabotAlerts(ref: RepoRef): Promise<CveFinding[]> {
  const pat = process.env.GITHUB_PAT!;
  const baseUrl = process.env.GITHUB_API_URL!;
  const octokit = createGitHubClient(pat, baseUrl);

  try {
    // Check if dependabot.yml exists as a proxy for Dependabot being active
    await octokit.repos.getContent({
      owner: ref.owner,
      repo: ref.repo,
      path: '.github/dependabot.yml',
    });

    const { data: alerts } = await octokit.rest.dependabot.listAlertsForRepo({
      owner: ref.owner,
      repo: ref.repo,
      state: 'open',
      per_page: 50,
    });

    return alerts.map((alert): CveFinding => ({
      packageName: alert.dependency.package?.name ?? 'unknown',
      version: alert.dependency.manifest_path ?? 'unknown',
      ecosystem: alert.dependency.package?.ecosystem ?? 'unknown',
      vulnId: alert.security_advisory.cve_id ?? alert.security_advisory.ghsa_id,
      summary: alert.security_advisory.summary,
      severity: alert.security_advisory.severity,
      fixedVersion: alert.security_advisory.vulnerabilities?.[0]?.first_patched_version?.identifier ?? null,
    }));
  } catch {
    return [];
  }
}

export async function fetchCodeScanningAlerts(ref: RepoRef): Promise<SemgrepFinding[]> {
  const pat = process.env.GITHUB_PAT!;
  const baseUrl = process.env.GITHUB_API_URL!;
  const octokit = createGitHubClient(pat, baseUrl);

  try {
    const { data: alerts } = await octokit.request(
      'GET /repos/{owner}/{repo}/code-scanning/alerts',
      {
        owner: ref.owner,
        repo: ref.repo,
        state: 'open',
        per_page: 100,
      }
    );

    return (alerts as Array<{
      rule: { id: string; description: string; tags?: string[] };
      most_recent_instance: {
        location?: { path?: string; start_line?: number };
      };
      tool: { name: string };
      state: string;
    }>).map((alert): SemgrepFinding => {
      const cweTag = alert.rule.tags?.find((t) => t.startsWith('cwe/'));
      return {
        rule: alert.rule.id ?? 'unknown',
        severity: 'Medium', // Code scanning API doesn't expose severity directly in older endpoints
        description: alert.rule.description ?? '',
        file: alert.most_recent_instance?.location?.path ?? '',
        line: alert.most_recent_instance?.location?.start_line ?? 0,
        cweId: cweTag?.replace('cwe/', 'CWE-'),
      };
    });
  } catch {
    return [];
  }
}

export async function fetchSpecificFiles(ref: RepoRef, paths: string[]): Promise<RepoFile[]> {
  const pat = process.env.GITHUB_PAT!;
  const baseUrl = process.env.GITHUB_API_URL!;
  const octokit = createGitHubClient(pat, baseUrl);

  return Promise.all(
    paths.map(async (path): Promise<RepoFile> => {
      try {
        const { data } = await octokit.repos.getContent({ owner: ref.owner, repo: ref.repo, path });
        if (Array.isArray(data) || data.type !== 'file') {
          return { path, content: '[directory or non-file]', sizeBytes: 0 };
        }
        const content = Buffer.from(data.content, 'base64').toString('utf-8');
        return { path, content: content.slice(0, 8000), sizeBytes: data.size };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { path, content: `[fetch error: ${msg}]`, sizeBytes: 0 };
      }
    })
  );
}
