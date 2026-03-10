import type { SupplyChainRisk, SbomComponent } from '../types.js';

// ─── Supply chain risk analysis ───────────────────────────────────────────────

interface NpmPackageInfo {
  maintainers?: Array<{ name: string }>;
  time?: Record<string, string>;
  downloads?: number;
}

/** Simple Levenshtein distance for typosquatting heuristic */
function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

// Well-known popular packages for typosquatting check
const POPULAR_PACKAGES = [
  'react', 'react-dom', 'express', 'lodash', 'axios', 'moment',
  'webpack', 'babel', 'typescript', 'jest', 'eslint', 'prettier',
  'next', 'vue', 'angular', 'svelte', 'fastify', 'koa', 'hapi',
  'mongoose', 'sequelize', 'prisma', 'typeorm', 'knex',
  'jsonwebtoken', 'bcrypt', 'passport', 'cors', 'helmet',
];

async function analyzeNpmPackage(name: string): Promise<string[]> {
  const signals: string[] = [];

  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {
      signal: AbortSignal.timeout(8000),
      headers: { 'Accept': 'application/json' },
    });

    if (!res.ok) return signals;

    const data = await res.json() as NpmPackageInfo;

    // Single maintainer check
    const maintainerCount = data.maintainers?.length ?? 0;
    if (maintainerCount === 1) {
      signals.push('Single maintainer — bus factor risk');
    }

    // Stale package check (> 2 years since last publish)
    if (data.time) {
      const times = Object.values(data.time)
        .filter((t) => typeof t === 'string')
        .map((t) => new Date(t).getTime())
        .filter((t) => !isNaN(t));

      if (times.length > 0) {
        const lastPublish = new Date(Math.max(...times));
        const twoYearsAgo = new Date();
        twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);
        if (lastPublish < twoYearsAgo) {
          const months = Math.floor(
            (Date.now() - lastPublish.getTime()) / (1000 * 60 * 60 * 24 * 30)
          );
          signals.push(`Last published ${months} months ago — potentially abandoned`);
        }
      }
    }
  } catch {
    // Network failure — skip this package
  }

  // Typosquatting heuristic
  for (const popular of POPULAR_PACKAGES) {
    const distance = levenshtein(name.toLowerCase(), popular.toLowerCase());
    if (distance > 0 && distance <= 2 && name.toLowerCase() !== popular.toLowerCase()) {
      signals.push(`Name very similar to popular package "${popular}" (edit distance: ${distance}) — possible typosquatting`);
      break;
    }
  }

  return signals;
}

function riskLevel(signals: string[]): SupplyChainRisk['riskLevel'] {
  if (signals.length >= 2) return 'high';
  if (signals.length === 1) return 'medium';
  return 'low';
}

export async function analyzeSupplyChainRisks(
  components: SbomComponent[]
): Promise<SupplyChainRisk[]> {
  if (components.length === 0) return [];

  // Only analyze npm packages, limit to first 30
  const npmPackages = components
    .filter((c) => c.ecosystem === 'npm')
    .slice(0, 30);

  const results = await Promise.allSettled(
    npmPackages.map(async (component): Promise<SupplyChainRisk | null> => {
      const signals = await analyzeNpmPackage(component.name);
      if (signals.length === 0) return null;
      return {
        packageName: component.name,
        signals,
        riskLevel: riskLevel(signals),
      };
    })
  );

  return results
    .filter((r): r is PromiseFulfilledResult<SupplyChainRisk | null> => r.status === 'fulfilled')
    .map((r) => r.value)
    .filter((r): r is SupplyChainRisk => r !== null);
}
