// ─── EPSS scoring via FIRST API ───────────────────────────────────────────────
// https://api.first.org/data/1.0/epss
// Public API, no auth required, ~1000 requests/day

export interface EpssResult {
  cve: string;
  epss: number;        // probability 0–1
  percentile: number;  // 0–1
}

export async function fetchEpssScores(
  cveIds: string[]
): Promise<Record<string, number>> {
  if (cveIds.length === 0) return {};

  // Only CVE IDs are supported (not GHSA IDs)
  const cvesOnly = cveIds.filter((id) => id.startsWith('CVE-'));
  if (cvesOnly.length === 0) return {};

  try {
    // Batch up to 100 CVEs per request
    const batches: string[][] = [];
    for (let i = 0; i < cvesOnly.length; i += 100) {
      batches.push(cvesOnly.slice(i, i + 100));
    }

    const scores: Record<string, number> = {};

    for (const batch of batches) {
      const params = batch.map((id) => `cve=${id}`).join('&');
      const url = `https://api.first.org/data/1.0/epss?${params}`;

      const res = await fetch(url, {
        signal: AbortSignal.timeout(10000),
        headers: { 'Accept': 'application/json' },
      });

      if (!res.ok) continue;

      const data = await res.json() as { data?: EpssResult[] };
      for (const entry of data.data ?? []) {
        scores[entry.cve] = entry.epss;
      }
    }

    return scores;
  } catch {
    return {};
  }
}
