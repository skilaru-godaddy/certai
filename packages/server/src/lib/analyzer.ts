import { randomUUID } from 'crypto';
import { writeFileSync, readFileSync, mkdirSync, existsSync, readdirSync } from 'fs';
import { join } from 'path';
import { fetchRepoSnapshot, fetchSpecificFiles, fetchDependabotAlerts, fetchCodeScanningAlerts } from './github.js';
import { streamAnalysis, triageFiles } from './claude.js';
import { parseRepoUrl } from './github.js';
import { parseDependencies, scanWithOsv } from './osv.js';
import { fetchEpssScores } from './epss.js';
import { fetchLicenseFindings } from './licenses.js';
import { analyzeSupplyChainRisks } from './supplychain.js';
import { scanForSecrets } from './secrets.js';
import type {
  RepoSnapshot, CveFinding, SecretFinding, SbomComponent,
  ApiEndpoint, ApiGatewayChecklist, MonitoringInfo,
  IacFinding, OwaspAsvs, ComplianceGap, PentestScope, FairRiskEstimate,
  LicenseFinding, SupplyChainRisk, SemgrepFinding,
} from '../types.js';
import { appendHistoryEntry, repoKeyFromUrl } from './history.js';

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

  // GoDaddy template fields
  inScope: string[];
  outOfScope: string[];
  architecturalAssumptions: string[];
  dataFlowDiagram: string;
  apiInventory: ApiEndpoint[];
  apiGatewayChecklist: ApiGatewayChecklist;
  secretsAndCredentials: string;
  monitoringAndLogging: MonitoringInfo;
  gitSha: string;

  // Industry-standard enrichment (from Claude)
  iacFindings: IacFinding[];
  slsaLevel: 0 | 1 | 2 | 3;
  slsaReasoning: string;
  owaspAsvs: OwaspAsvs[];
  complianceGaps: ComplianceGap[];
  pentestScope: PentestScope;
  fairRiskEstimates: FairRiskEstimate[];

  // Enriched by external APIs (not from Claude)
  epssScores: Record<string, number>;
  licenseFindings: LicenseFinding[];
  supplyChainRisks: SupplyChainRisk[];
  semgrepFindings: SemgrepFinding[];
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
  mitreAttackTactic?: string;        // e.g. "Initial Access"
  mitreAttackTechnique?: string;     // e.g. "Exploit Public-Facing Application"
  mitreAttackTechniqueId?: string;   // e.g. "T1190"
}

export interface QuestionnaireItem {
  id: number;
  question: string;
  answer: string;
  evidence: string;
  confidence: 'Confirmed' | 'Inferred' | 'Needs Manual Verification';
}

// Re-export shared types for convenience
export type {
  CveFinding, SecretFinding, SbomComponent,
  ApiEndpoint, ApiGatewayChecklist, MonitoringInfo,
  IacFinding, OwaspAsvs, ComplianceGap, PentestScope, FairRiskEstimate,
  LicenseFinding, SupplyChainRisk, SemgrepFinding,
};

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

    // Phase 2: Fetch file tree, then fan out everything in parallel
    notify(job, { phase: 'fetching', message: 'Fetching file tree...' });
    const snapshot = await fetchRepoSnapshot(ref);
    notify(job, {
      phase: 'fetching',
      message: `Found ${snapshot.allPaths.length} files. Running triage, CVE scan, and secret detection in parallel...`,
    });

    // Parse SBOM from the initial priority files so CVE scan can start immediately
    const sbomInitial = parseDependencies(snapshot.priorityFiles);

    // Fan out: triage + CVE scan + secrets + code scanning all in parallel
    const [
      triagedPaths,
      osvResults,
      dependabotResults,
      secretScanFindings,
      semgrepFindings,
    ] = await Promise.all([
      triageFiles(snapshot.allPaths, snapshot.treeText),
      scanWithOsv(sbomInitial),
      fetchDependabotAlerts(ref),
      Promise.resolve(scanForSecrets(snapshot.priorityFiles)),
      fetchCodeScanningAlerts(ref),
    ]);

    // Fetch the triaged files and update snapshot
    if (triagedPaths.length > 0) {
      const triagedFiles = await fetchSpecificFiles(ref, triagedPaths);
      snapshot.priorityFiles = triagedFiles;
    }

    // Re-parse SBOM from final file set (may include more files post-triage)
    const sbom = parseDependencies(snapshot.priorityFiles);

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
      message: `Loaded ${snapshot.priorityFiles.length} files | CVEs: ${cveScanResults.length} | Secrets: ${secretScanFindings.length} | Code scan: ${semgrepFindings.length}`,
    });

    // Phase 3+4: Start Claude AND external enrichment in parallel.
    // EPSS/licenses/supply chain only need sbom + cveIds — no need to wait for Claude.
    const cveIds = cveScanResults.map((c) => c.vulnId);
    const enrichmentPromise = Promise.all([
      fetchEpssScores(cveIds),
      fetchLicenseFindings(sbom),
      analyzeSupplyChainRisks(sbom),
    ]);

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

    // Parse result and wait for enrichment (likely already done by now)
    const [parsed, [epssScores, licenseFindings, supplyChainRisks]] = await Promise.all([
      Promise.resolve(JSON.parse(jsonText) as AnalysisResult),
      enrichmentPromise,
    ]);

    parsed.snapshot = snapshot;
    parsed.thinkingText = thinkingText;
    parsed.cveScanResults = cveScanResults;
    parsed.secretScanFindings = secretScanFindings;
    parsed.sbom = sbom;

    // Populate gitSha from snapshot ref (best effort)
    parsed.gitSha = `${snapshot.ref.owner}/${snapshot.ref.repo}@HEAD`;

    parsed.epssScores = epssScores;
    parsed.licenseFindings = licenseFindings;
    parsed.supplyChainRisks = supplyChainRisks;
    parsed.semgrepFindings = semgrepFindings;

    // Ensure new GD template fields have safe defaults if Claude omitted them
    parsed.inScope = parsed.inScope ?? [];
    parsed.outOfScope = parsed.outOfScope ?? [];
    parsed.architecturalAssumptions = parsed.architecturalAssumptions ?? [];
    parsed.dataFlowDiagram = parsed.dataFlowDiagram ?? '';
    parsed.apiInventory = parsed.apiInventory ?? [];
    parsed.apiGatewayChecklist = parsed.apiGatewayChecklist ?? {
      https: false, approvedAuth: false, rateLimiting: false, anomalyMonitoring: false, notes: '',
    };
    parsed.secretsAndCredentials = parsed.secretsAndCredentials ?? '';
    parsed.monitoringAndLogging = parsed.monitoringAndLogging ?? {
      loggingFramework: '', logDestination: '', retentionPolicy: '', alertingSetup: '',
    };
    parsed.iacFindings = parsed.iacFindings ?? [];
    parsed.slsaLevel = parsed.slsaLevel ?? 0;
    parsed.slsaReasoning = parsed.slsaReasoning ?? '';
    parsed.owaspAsvs = parsed.owaspAsvs ?? [];
    parsed.complianceGaps = parsed.complianceGaps ?? [];
    parsed.pentestScope = parsed.pentestScope ?? {
      highRiskAreas: [], attackSurface: [], testingRecommendations: [], estimatedEffort: '',
    };
    parsed.fairRiskEstimates = parsed.fairRiskEstimates ?? [];

    job.result = parsed;
    job.status = JobStatus.Done;
    notify(job, { phase: 'done', message: 'Analysis complete', data: parsed });
    persistJob(job);

    // Append to per-repo history
    const repoKey = repoKeyFromUrl(job.repoUrl);
    appendHistoryEntry(repoKey, {
      jobId: job.id,
      date: job.createdAt.toISOString(),
      securityScore: parsed.securityScore,
      riskCategory: parsed.riskCategory,
      threatCount: parsed.threats.length,
      cveCount: (parsed.cveScanResults ?? []).length,
    });
  } catch (err) {
    job.status = JobStatus.Error;
    job.error = String(err);
    notify(job, { phase: 'error', message: String(err) });
  }
}
