import type { CveFinding, SbomComponent } from '../types.js';
import type { RepoFile } from '../types.js';

// ─── Dependency parsing ───────────────────────────────────────────────────────

export function parseDependencies(files: RepoFile[]): SbomComponent[] {
  const components: SbomComponent[] = [];

  for (const file of files) {
    if (file.path.endsWith('package.json') && !file.path.includes('node_modules')) {
      try {
        const pkg = JSON.parse(file.content);
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
        for (const [name, rawVersion] of Object.entries(allDeps)) {
          const version = String(rawVersion).replace(/^[\^~>=<]/, '');
          components.push({
            name,
            version,
            ecosystem: 'npm',
            purl: `pkg:npm/${name}@${version}`,
          });
        }
      } catch { /* skip malformed */ }
    }

    if (file.path.endsWith('requirements.txt')) {
      for (const line of file.content.split('\n')) {
        const match = line.match(/^([A-Za-z0-9_.-]+)[=~><]+([^\s;]+)/);
        if (match) {
          const [, name, version] = match;
          components.push({
            name, version, ecosystem: 'PyPI',
            purl: `pkg:pypi/${name.toLowerCase()}@${version}`,
          });
        }
      }
    }

    if (file.path.endsWith('go.mod')) {
      for (const line of file.content.split('\n')) {
        const match = line.match(/^\s+([^\s]+)\s+v([^\s]+)/);
        if (match) {
          const [, name, version] = match;
          components.push({
            name, version, ecosystem: 'Go',
            purl: `pkg:golang/${name}@v${version}`,
          });
        }
      }
    }
  }

  return components;
}

// ─── OSV batch query ──────────────────────────────────────────────────────────

interface OsvQuery {
  version: string;
  package: { name: string; ecosystem: string };
}

interface OsvVuln {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    ranges?: Array<{
      events?: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
}

const ECOSYSTEM_MAP: Record<string, string> = {
  npm: 'npm',
  PyPI: 'PyPI',
  Go: 'Go',
  maven: 'Maven',
};

export async function scanWithOsv(components: SbomComponent[]): Promise<CveFinding[]> {
  if (components.length === 0) return [];

  const batch = components.slice(0, 200);
  const queries: OsvQuery[] = batch.map((c) => ({
    version: c.version,
    package: { name: c.name, ecosystem: ECOSYSTEM_MAP[c.ecosystem] ?? c.ecosystem },
  }));

  try {
    const res = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) return [];
    const data = await res.json() as { results: Array<{ vulns?: OsvVuln[] }> };

    const findings: CveFinding[] = [];
    for (let i = 0; i < data.results.length; i++) {
      const result = data.results[i];
      const component = batch[i];
      if (!result.vulns) continue;

      for (const vuln of result.vulns) {
        let fixedVersion: string | null = null;
        for (const affected of vuln.affected ?? []) {
          for (const range of affected.ranges ?? []) {
            const fixedEvent = range.events?.find((e) => e.fixed);
            if (fixedEvent?.fixed) { fixedVersion = fixedEvent.fixed; break; }
          }
          if (fixedVersion) break;
        }

        let severity = 'Unknown';
        if (vuln.severity?.[0]?.score) {
          const score = parseFloat(vuln.severity[0].score);
          if (score >= 9) severity = 'Critical';
          else if (score >= 7) severity = 'High';
          else if (score >= 4) severity = 'Medium';
          else severity = 'Low';
        }

        findings.push({
          packageName: component.name,
          version: component.version,
          ecosystem: component.ecosystem,
          vulnId: vuln.id,
          summary: vuln.summary ?? 'No description available',
          severity,
          fixedVersion,
        });
      }
    }

    const seen = new Set<string>();
    return findings.filter((f) => {
      const key = `${f.vulnId}:${f.packageName}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  } catch {
    return [];
  }
}
