import { randomUUID } from 'crypto';
import { fetchRepoSnapshot, fetchSpecificFiles } from './github.js';
import { streamAnalysis, triageFiles } from './claude.js';
import { parseRepoUrl } from './github.js';
import type { RepoSnapshot, CveFinding, SecretFinding, SbomComponent } from '../types.js';

// ─── Job store (in-memory for prototype) ────────────────────────────────────

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

    // Phase 3+4: Claude streaming analysis
    let rawJson = '';
    for await (const chunk of streamAnalysis(snapshot)) {
      if (chunk.type === 'thinking') {
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
    job.result = parsed;
    job.status = JobStatus.Done;
    notify(job, { phase: 'done', message: 'Analysis complete', data: parsed });
  } catch (err) {
    job.status = JobStatus.Error;
    job.error = String(err);
    notify(job, { phase: 'error', message: String(err) });
  }
}
