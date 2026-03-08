import { Octokit } from '@octokit/rest';
import type { RepoRef, RepoFile, RepoSnapshot } from '../types.js';

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
