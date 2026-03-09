import { writeFileSync, readFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

// ─── Per-repo score history ────────────────────────────────────────────────────

const HISTORY_DIR = join(process.cwd(), '.certai-history');
if (!existsSync(HISTORY_DIR)) mkdirSync(HISTORY_DIR, { recursive: true });

export interface HistoryEntry {
  jobId: string;
  date: string;
  securityScore: number;
  riskCategory: string;
  threatCount: number;
  cveCount: number;
}

/** Normalize repo URL to a safe filesystem key: "owner/repo" → "owner__repo" */
export function repoKeyFromUrl(repoUrl: string): string {
  try {
    const cleaned = repoUrl.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const parts = cleaned.split('/');
    if (parts.length >= 3) {
      return `${parts[1]}__${parts[2]}`;
    }
    return cleaned.replace(/[^a-zA-Z0-9_-]/g, '_');
  } catch {
    return 'unknown';
  }
}

export function appendHistoryEntry(repoKey: string, entry: HistoryEntry): void {
  try {
    const file = join(HISTORY_DIR, `${repoKey}.json`);
    const existing: HistoryEntry[] = existsSync(file)
      ? JSON.parse(readFileSync(file, 'utf-8'))
      : [];
    existing.push(entry);
    // Keep last 50 entries
    const trimmed = existing.slice(-50);
    writeFileSync(file, JSON.stringify(trimmed, null, 2));
  } catch { /* non-fatal */ }
}

export function getHistoryForRepo(repoKey: string): HistoryEntry[] {
  try {
    // Accept both "/" and "__" separators
    const normalizedKey = repoKey.replace('/', '__');
    const file = join(HISTORY_DIR, `${normalizedKey}.json`);
    if (!existsSync(file)) return [];
    return JSON.parse(readFileSync(file, 'utf-8')) as HistoryEntry[];
  } catch {
    return [];
  }
}
