import type { LicenseFinding, SbomComponent } from '../types.js';

// ─── License detection via deps.dev API ───────────────────────────────────────
// https://api.deps.dev/v3alpha/purl/{url-encoded-purl}

const PERMISSIVE = new Set([
  'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC',
  'Unlicense', '0BSD', 'BlueOak-1.0.0', 'CC0-1.0',
]);

const WEAK_COPYLEFT = new Set([
  'LGPL-2.0', 'LGPL-2.0-only', 'LGPL-2.0-or-later',
  'LGPL-2.1', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
  'LGPL-3.0', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
  'MPL-2.0', 'CDDL-1.0', 'EPL-1.0', 'EPL-2.0',
]);

const STRONG_COPYLEFT = new Set([
  'GPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later',
  'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later',
  'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later',
  'SSPL-1.0', 'EUPL-1.1', 'EUPL-1.2',
]);

type RiskCategory = LicenseFinding['riskCategory'];

function categorize(spdx: string): RiskCategory {
  if (PERMISSIVE.has(spdx)) return 'Permissive';
  if (WEAK_COPYLEFT.has(spdx)) return 'Weak Copyleft';
  if (STRONG_COPYLEFT.has(spdx)) return 'Strong Copyleft';
  return 'Unknown';
}

interface DepsDevVersion {
  licenses?: string[];
}

interface DepsDevResponse {
  version?: DepsDevVersion;
}

export async function fetchLicenseFindings(
  components: SbomComponent[]
): Promise<LicenseFinding[]> {
  if (components.length === 0) return [];

  // Limit to first 50 components to stay within rate limits
  const sample = components.slice(0, 50);

  const results = await Promise.allSettled(
    sample.map(async (component): Promise<LicenseFinding | null> => {
      try {
        const encodedPurl = encodeURIComponent(component.purl);
        const url = `https://api.deps.dev/v3alpha/purl/${encodedPurl}`;

        const res = await fetch(url, {
          signal: AbortSignal.timeout(8000),
          headers: { 'Accept': 'application/json' },
        });

        if (!res.ok) return null;

        const data = await res.json() as DepsDevResponse;
        const licenses = data.version?.licenses ?? [];
        const spdx = licenses[0] ?? 'Unknown';
        const riskCategory = categorize(spdx);

        return {
          packageName: component.name,
          version: component.version,
          spdxLicense: spdx,
          riskCategory,
          requiresReview: riskCategory === 'Strong Copyleft' || riskCategory === 'Unknown',
        };
      } catch {
        return null;
      }
    })
  );

  return results
    .filter((r): r is PromiseFulfilledResult<LicenseFinding | null> => r.status === 'fulfilled')
    .map((r) => r.value)
    .filter((r): r is LicenseFinding => r !== null);
}
