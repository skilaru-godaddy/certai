import { randomUUID } from 'crypto';
import { writeFileSync, readFileSync, mkdirSync, existsSync, readdirSync } from 'fs';
import { join } from 'path';
import { fetchRepoSnapshot, fetchSpecificFiles, fetchDependabotAlerts } from './github.js';
import { streamAnalysis, triageFiles } from './claude.js';
import { parseRepoUrl } from './github.js';
import { parseDependencies, scanWithOsv } from './osv.js';
import { scanForSecrets } from './secrets.js';
import type { RepoSnapshot, CveFinding, SecretFinding, SbomComponent } from '../types.js';

// ─── Job persistence ──────────────────────────────────────────────────────────

const JOBS_DIR = join(process.cwd(), '.certai-jobs');
if (!existsSync(JOBS_DIR)) mkdirSync(JOBS_DIR, { recursive: true });

function persistJob(job: Job): void {
  if (job.status !== JobStatus.Done) return;
  try {
    const data = {
      id: job.id,
      repoUrl: job.repoUrl,
      status: job.status,
      createdAt: job.createdAt,
      result: job.result,
    };
    writeFileSync(join(JOBS_DIR, `${job.id}.json`), JSON.stringify(data, null, 2));
  } catch { /* non-fatal */ }
}

function loadPersistedJobs(): void {
  if (!existsSync(JOBS_DIR)) return;
  try {
    const files = readdirSync(JOBS_DIR).filter((f) => f.endsWith('.json'));
    for (const file of files) {
      const data = JSON.parse(readFileSync(join(JOBS_DIR, file), 'utf-8'));
      const job: Job = {
        ...data,
        createdAt: new Date(data.createdAt),
        phases: [],
        error: null,
        subscribers: new Set(),
      };
      jobs.set(job.id, job);
    }
  } catch { /* non-fatal */ }
}

// ─── Job store ────────────────────────────────────────────────────────────────

export enum JobStatus {
  Pending = 'pending',
  Running = 'running',
  Done = 'done',
  Error = 'error',
}

export interface Job {
  id: string;
  repoUrl: string;
  status: JobStatus;
  createdAt: Date;
  phases: PhaseUpdate[];
  result: AnalysisResult | null;
  error: string | null;
  // SSE subscribers waiting for this job
  subscribers: Set<(update: PhaseUpdate) => void>;
}

export interface PhaseUpdate {
  phase: 'discovery' | 'fetching' | 'thinking' | 'generating' | 'done' | 'error';
  message: string;
  data?: unknown;
}

export interface AnalysisResult {
  riskCategory: string;
  riskReasoning: string;
  mermaidDiagram: string;
  threats: ThreatItem[];
  questionnaire: QuestionnaireItem[];
  irpDraft: string;
  snapshot: RepoSnapshot;
  thinkingText: string;
  securityScore: number;
  cveScanResults: CveFinding[];
  secretScanFindings: SecretFinding[];
  sbom: SbomComponent[];
}

export interface ThreatItem {
  component: string;
  threat: string;
  likelihood: string;
  impact: string;
  mitigation: string;
  codeEvidence: string;
  strideCategory: 'Spoofing' | 'Tampering' | 'Repudiation' | 'Information Disclosure' | 'Denial of Service' | 'Elevation of Privilege';
  dreadScore: number;
  owaspCategory: string;
}

export interface QuestionnaireItem {
  id: number;
  question: string;
  answer: string;
  evidence: string;
  confidence: 'Confirmed' | 'Inferred' | 'Needs Manual Verification';
}

// Re-export shared types for convenience
export type { CveFinding, SecretFinding, SbomComponent };

const jobs = new Map<string, Job>();
loadPersistedJobs();

export function createJob(repoUrl: string): Job {
  const job: Job = {
    id: randomUUID(),
    repoUrl,
    status: JobStatus.Pending,
    createdAt: new Date(),
    phases: [],
    result: null,
    error: null,
    subscribers: new Set(),
  };
  jobs.set(job.id, job);
  return job;
}

export function getJob(id: string): Job | undefined {
  return jobs.get(id);
}

// ─── Run analysis (non-blocking) ─────────────────────────────────────────────

function notify(job: Job, update: PhaseUpdate) {
  job.phases.push(update);
  for (const subscriber of job.subscribers) {
    subscriber(update);
  }
}

export function startAnalysis(jobId: string): void {
  // Fire and forget — do NOT await this
  runAnalysis(jobId).catch(() => {}); // errors are stored on the job
}

async function runAnalysis(jobId: string): Promise<void> {
  const job = jobs.get(jobId);
  if (!job) return;

  job.status = JobStatus.Running;

  try {
    // Phase 1: Repo discovery
    notify(job, { phase: 'discovery', message: 'Discovering repo structure...' });
    const ref = parseRepoUrl(job.repoUrl);

    // Phase 2: File fetching — two-pass triage
    notify(job, { phase: 'fetching', message: 'Fetching file tree...' });
    const snapshot = await fetchRepoSnapshot(ref);
    notify(job, {
      phase: 'fetching',
      message: `Found ${snapshot.allPaths.length} files. Running security triage...`,
    });

    const triagedPaths = await triageFiles(snapshot.allPaths, snapshot.treeText);
    if (triagedPaths.length > 0) {
      const triagedFiles = await fetchSpecificFiles(ref, triagedPaths);
      snapshot.priorityFiles = triagedFiles;
      notify(job, {
        phase: 'fetching',
        message: `Loaded ${triagedFiles.length} files selected by Claude security triage`,
      });
    } else {
      notify(job, {
        phase: 'fetching',
        message: `Loaded ${snapshot.priorityFiles.length} files (triage fallback)`,
      });
    }

    // Phase 2b: Parallel CVE + secret scans (OSV + Dependabot + secrets)
    notify(job, { phase: 'fetching', message: 'Running CVE scan and secret detection...' });
    const sbom = parseDependencies(snapshot.priorityFiles);
    const [osvResults, dependabotResults, secretScanFindings] = await Promise.all([
      scanWithOsv(sbom),
      fetchDependabotAlerts(ref),
      Promise.resolve(scanForSecrets(snapshot.priorityFiles)),
    ]);

    // Merge and deduplicate CVE findings by vulnId+package
    const seen = new Set<string>();
    const cveScanResults: CveFinding[] = [];
    for (const finding of [...osvResults, ...dependabotResults]) {
      const key = `${finding.vulnId}:${finding.packageName}`;
      if (!seen.has(key)) {
        seen.add(key);
        cveScanResults.push(finding);
      }
    }

    notify(job, {
      phase: 'fetching',
      message: `CVE scan: ${cveScanResults.length} findings | Secrets: ${secretScanFindings.length} findings`,
    });

    // Phase 3+4: Claude streaming analysis
    let rawJson = '';
    let thinkingText = '';
    for await (const chunk of streamAnalysis(snapshot, cveScanResults, secretScanFindings)) {
      if (chunk.type === 'thinking') {
        thinkingText += chunk.content;
        notify(job, { phase: 'thinking', message: chunk.content });
      } else if (chunk.type === 'text') {
        rawJson += chunk.content;
        notify(job, { phase: 'generating', message: chunk.content });
      } else if (chunk.type === 'error') {
        throw new Error(chunk.content);
      }
    }

    // Strip markdown fences if Claude wrapped the response
    const jsonText = rawJson.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();

    // Parse result
    const parsed = JSON.parse(jsonText) as AnalysisResult;
    parsed.snapshot = snapshot;
    parsed.thinkingText = thinkingText;
    parsed.cveScanResults = cveScanResults;
    parsed.secretScanFindings = secretScanFindings;
    parsed.sbom = sbom;
    job.result = parsed;
    job.status = JobStatus.Done;
    notify(job, { phase: 'done', message: 'Analysis complete', data: parsed });
    persistJob(job);
  } catch (err) {
    job.status = JobStatus.Error;
    job.error = String(err);
    notify(job, { phase: 'error', message: String(err) });
  }
}
