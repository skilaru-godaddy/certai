# CertAI v2 Improvements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade CertAI from a prototype to a production-quality security certification tool by adding real CVE data, STRIDE/DREAD/OWASP enrichment, secret scanning, SBOM generation, two-pass file selection, extended thinking persistence, and UI enhancements.

**Architecture:** All improvements are layered on top of the existing Fastify + React stack. No new paid APIs — OSV (Google) and Dependabot are free. New fields flow from `types.ts` (server) → `claude.ts` (prompt) → `analyzer.ts` (pipeline) → `types.ts` (web) → UI components. All tasks are independently testable.

**Tech Stack:** TypeScript, Fastify v5, React 19, Vite, Tailwind v4, `@anthropic-ai/sdk`, `@octokit/rest`, OSV Batch API (free), CycloneDX JSON (standard), Node.js `fs` for job persistence.

---

## Phase 1: Enrich types with STRIDE, DREAD, OWASP, Confidence

### Task 1: Update server types

**Files:**
- Modify: `packages/server/src/lib/analyzer.ts` — `ThreatItem`, `QuestionnaireItem`, `AnalysisResult`

**Step 1: Update `ThreatItem` in `analyzer.ts`**

Find the existing interface at line ~44:
```typescript
export interface ThreatItem {
  component: string;
  threat: string;
  likelihood: string;
  impact: string;
  mitigation: string;
  codeEvidence: string;
}
```
Replace with:
```typescript
export interface ThreatItem {
  component: string;
  threat: string;
  likelihood: string;
  impact: string;
  mitigation: string;
  codeEvidence: string;
  strideCategory: 'Spoofing' | 'Tampering' | 'Repudiation' | 'Information Disclosure' | 'Denial of Service' | 'Elevation of Privilege';
  dreadScore: number; // 1-10 composite (avg of D+R+E+A+D)
  owaspCategory: string; // e.g. "A01:2021 – Broken Access Control"
}
```

**Step 2: Update `QuestionnaireItem` in `analyzer.ts`**

Find the existing interface at line ~52:
```typescript
export interface QuestionnaireItem {
  id: number;
  question: string;
  answer: string;
  evidence: string;
}
```
Replace with:
```typescript
export interface QuestionnaireItem {
  id: number;
  question: string;
  answer: string;
  evidence: string;
  confidence: 'Confirmed' | 'Inferred' | 'Needs Manual Verification';
}
```

**Step 3: Update `AnalysisResult` in `analyzer.ts`**

Find the existing interface at line ~34:
```typescript
export interface AnalysisResult {
  riskCategory: string;
  riskReasoning: string;
  mermaidDiagram: string;
  threats: ThreatItem[];
  questionnaire: QuestionnaireItem[];
  irpDraft: string;
  snapshot: RepoSnapshot;
}
```
Replace with:
```typescript
export interface AnalysisResult {
  riskCategory: string;
  riskReasoning: string;
  mermaidDiagram: string;
  threats: ThreatItem[];
  questionnaire: QuestionnaireItem[];
  irpDraft: string;
  snapshot: RepoSnapshot;
  thinkingText: string;       // stored Claude extended thinking
  securityScore: number;      // 0-100 composite score
  cveScanResults: CveFinding[]; // real CVE data from OSV API
  secretScanFindings: SecretFinding[]; // regex-detected secrets
  sbom: SbomComponent[];      // CycloneDX-compatible component list
}

export interface CveFinding {
  packageName: string;
  version: string;
  ecosystem: string;
  vulnId: string;       // e.g. "GHSA-xxxx" or "CVE-2024-xxx"
  summary: string;
  severity: string;
  fixedVersion: string | null;
}

export interface SecretFinding {
  path: string;
  line: number;
  type: string;         // e.g. "AWS Access Key", "GitHub PAT"
  preview: string;      // first 20 chars redacted: "AKIA**************"
}

export interface SbomComponent {
  name: string;
  version: string;
  ecosystem: string;    // "npm", "pypi", "go", "maven"
  purl: string;         // e.g. "pkg:npm/express@4.18.0"
}
```

**Step 4: Commit**
```bash
cd /Users/skilaru/Documents/certai
git add packages/server/src/lib/analyzer.ts
git commit -m "feat: extend types — STRIDE, DREAD, OWASP, confidence, CVE, secrets, SBOM, score"
```

---

### Task 2: Mirror types in web package

**Files:**
- Modify: `packages/web/src/types.ts`

**Step 1: Replace entire file**
```typescript
export interface ThreatItem {
  component: string;
  threat: string;
  likelihood: string;
  impact: string;
  mitigation: string;
  codeEvidence: string;
  strideCategory: string;
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

export interface CveFinding {
  packageName: string;
  version: string;
  ecosystem: string;
  vulnId: string;
  summary: string;
  severity: string;
  fixedVersion: string | null;
}

export interface SecretFinding {
  path: string;
  line: number;
  type: string;
  preview: string;
}

export interface SbomComponent {
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
}

export interface AnalysisResult {
  riskCategory: string;
  riskReasoning: string;
  mermaidDiagram: string;
  threats: ThreatItem[];
  questionnaire: QuestionnaireItem[];
  irpDraft: string;
  thinkingText: string;
  securityScore: number;
  cveScanResults: CveFinding[];
  secretScanFindings: SecretFinding[];
  sbom: SbomComponent[];
}
```

**Step 2: Commit**
```bash
git add packages/web/src/types.ts
git commit -m "feat: mirror enriched types in web package"
```

---

## Phase 2: Update Claude prompt for new fields

### Task 3: Update `buildAnalysisPrompt` in `claude.ts`

**Files:**
- Modify: `packages/server/src/lib/claude.ts`

**Step 1: Find the JSON schema block in the prompt (around line 39)**

Replace the `threats` array schema in the prompt from:
```
"threats": [
  {
    "component": "string",
    "threat": "string",
    "likelihood": "Low" | "Medium" | "High",
    "impact": "Low" | "Medium" | "High" | "Critical",
    "mitigation": "string",
    "codeEvidence": "path/to/file.ts:lineHint"
  }
],
```
With:
```
"threats": [
  {
    "component": "string",
    "threat": "string",
    "likelihood": "Low" | "Medium" | "High",
    "impact": "Low" | "Medium" | "High" | "Critical",
    "mitigation": "string",
    "codeEvidence": "path/to/file.ts:lineHint",
    "strideCategory": "Spoofing" | "Tampering" | "Repudiation" | "Information Disclosure" | "Denial of Service" | "Elevation of Privilege",
    "dreadScore": <number 1-10, composite average of Damage+Reproducibility+Exploitability+AffectedUsers+Discoverability>,
    "owaspCategory": "<OWASP Top 10 2021 category, e.g. 'A01:2021 – Broken Access Control'>"
  }
],
```

**Step 2: Replace the `questionnaire` item schema from:**
```
"questionnaire": [
  {
    "id": 1,
    "question": "string",
    "answer": "string",
    "evidence": "path/to/file.ts:lineHint or N/A"
  }
],
```
With:
```
"questionnaire": [
  {
    "id": 1,
    "question": "string",
    "answer": "string",
    "evidence": "path/to/file.ts:lineHint or N/A",
    "confidence": "Confirmed" | "Inferred" | "Needs Manual Verification"
  }
],
```
Rules for `confidence`:
- `"Confirmed"`: directly visible in fetched file content
- `"Inferred"`: reasoned from indirect evidence
- `"Needs Manual Verification"`: cannot be determined from code alone

**Step 3: Add `securityScore` to the JSON schema**

Add after `irpDraft`:
```
"securityScore": <number 0-100. 100=perfect security posture. Deduct: 30 pts for CAT 0, 20 for CAT 1, 10 for CAT 2; 5 pts per Critical threat; 3 per High; 10 pts if any "Needs Manual Verification" answers for auth/secrets questions (Q10, Q14, Q15, Q16, Q20, Q21); bonus +10 if no high/critical threats>
```

**Step 4: Add scoring rules section to the prompt text** (add before "Return ONLY the JSON object"):
```
## STRIDE Categories:
Map each threat to exactly one STRIDE category based on the primary attack vector.

## DREAD Scoring (1-10 each component, return composite average rounded to 1 decimal):
- Damage: How bad would a successful attack be?
- Reproducibility: How easy to reproduce the attack?
- Exploitability: How much skill does an attacker need?
- Affected users: What percentage of users would be impacted?
- Discoverability: How easy to find the vulnerability?

## OWASP Top 10 2021 Categories:
A01:2021 – Broken Access Control
A02:2021 – Cryptographic Failures
A03:2021 – Injection
A04:2021 – Insecure Design
A05:2021 – Security Misconfiguration
A06:2021 – Vulnerable and Outdated Components
A07:2021 – Identification and Authentication Failures
A08:2021 – Software and Data Integrity Failures
A09:2021 – Security Logging and Monitoring Failures
A10:2021 – Server-Side Request Forgery (SSRF)

## Questionnaire confidence rules:
- "Confirmed": you can point to a specific line of code
- "Inferred": you're reasoning from project structure or framework choices
- "Needs Manual Verification": the code alone cannot answer this question
```

**Step 5: Commit**
```bash
git add packages/server/src/lib/claude.ts
git commit -m "feat: enrich prompt — STRIDE, DREAD, OWASP, confidence, security score"
```

---

## Phase 3: Two-pass file selection

### Task 4: Add Pass 1 (file triage) to `claude.ts`

**Files:**
- Modify: `packages/server/src/lib/claude.ts`

**Step 1: Add a new function `triageFiles` after `buildAnalysisPrompt`**

```typescript
export async function triageFiles(
  allPaths: string[],
  treeText: string
): Promise<string[]> {
  const client = createClaudeClient();

  // Cheap call: no file content, just paths. Ask Claude to select up to 30.
  const prompt = `You are a security engineer performing a security certification review.
Below is the full file tree of a repository. Select up to 30 file paths that are MOST relevant for a security review.

Prioritize in order:
1. Authentication, authorization, middleware files
2. Route handlers, API controllers, GraphQL resolvers
3. Database models, migrations, ORM schemas
4. Infrastructure: Dockerfile, docker-compose, Terraform (.tf), CDK, CloudFormation
5. Dependency manifests: package.json, requirements.txt, go.mod, pom.xml, build.gradle, Cargo.toml
6. Configuration: .env.example, nginx.conf, k8s manifests
7. CI/CD: .github/workflows, Jenkinsfile
8. README.md (always include if present)

Full file tree:
${treeText}

Return ONLY a JSON array of file paths, nothing else. Example:
["src/auth/middleware.ts", "Dockerfile", "package.json"]`;

  const message = await client.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 2000,
    messages: [{ role: 'user', content: prompt }],
  });

  const text = message.content
    .filter((b): b is Anthropic.TextBlock => b.type === 'text')
    .map((b) => b.text)
    .join('');

  try {
    const jsonText = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();
    const selected = JSON.parse(jsonText) as string[];
    // Filter to only paths that exist in allPaths
    return selected.filter((p) => allPaths.includes(p)).slice(0, 30);
  } catch {
    // Fallback to original priority-based selection if parse fails
    return [];
  }
}
```

**Step 2: Add the `Anthropic` import for type annotation** — Add `import Anthropic from '@anthropic-ai/sdk';` if not already present at the top of `claude.ts` (it already imports from `@anthropic-ai/sdk` so just add the type reference as needed).

**Step 3: Commit**
```bash
git add packages/server/src/lib/claude.ts
git commit -m "feat: add two-pass file triage — Claude selects up to 30 security-relevant files"
```

---

### Task 5: Wire two-pass into `analyzer.ts`

**Files:**
- Modify: `packages/server/src/lib/analyzer.ts`
- Modify: `packages/server/src/lib/github.ts`

**Step 1: Update `github.ts` — increase tree display from 60 to 500 paths**

Find line 110:
```typescript
const treeText = allPaths.slice(0, 60).join('\n');
```
Replace with:
```typescript
const treeText = allPaths.slice(0, 500).join('\n');
```
This gives Claude's triage pass enough paths to choose from.

**Step 2: Update `runAnalysis` in `analyzer.ts` to use two-pass**

Find the Phase 2 block (around line 107):
```typescript
notify(job, { phase: 'fetching', message: 'Fetching security-relevant files...' });
const snapshot = await fetchRepoSnapshot(ref);
notify(job, {
  phase: 'fetching',
  message: `Loaded ${snapshot.priorityFiles.length} files (${snapshot.allPaths.length} total in repo)`,
});
```

Replace with:
```typescript
notify(job, { phase: 'fetching', message: 'Fetching file tree...' });
const snapshot = await fetchRepoSnapshot(ref);
notify(job, {
  phase: 'fetching',
  message: `Found ${snapshot.allPaths.length} files. Running security triage...`,
});

// Two-pass: ask Claude which files matter most
const { triageFiles } = await import('./claude.js');
const triagedPaths = await triageFiles(snapshot.allPaths, snapshot.treeText);

if (triagedPaths.length > 0) {
  // Fetch triaged files (up to 30) — these replace the original 14
  const { fetchSpecificFiles } = await import('./github.js');
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
```

**Step 3: Add `fetchSpecificFiles` to `github.ts`**

Add after `fetchRepoSnapshot`:
```typescript
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
```

**Step 4: Commit**
```bash
git add packages/server/src/lib/analyzer.ts packages/server/src/lib/github.ts
git commit -m "feat: wire two-pass triage into analysis pipeline — up to 30 Claude-selected files"
```

---

## Phase 4: Real CVE scanning via OSV API

### Task 6: Create `packages/server/src/lib/osv.ts`

**Files:**
- Create: `packages/server/src/lib/osv.ts`

**Step 1: Create the file**
```typescript
import type { CveFinding, SbomComponent } from '../lib/analyzer.js';
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

  // OSV accepts max 1000 per batch; slice to 200 to keep request size reasonable
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
      signal: AbortSignal.timeout(15000), // 15s timeout
    });

    if (!res.ok) return [];
    const data = await res.json() as { results: Array<{ vulns?: OsvVuln[] }> };

    const findings: CveFinding[] = [];
    for (let i = 0; i < data.results.length; i++) {
      const result = data.results[i];
      const component = batch[i];
      if (!result.vulns) continue;

      for (const vuln of result.vulns) {
        // Find fixed version from ranges
        let fixedVersion: string | null = null;
        for (const affected of vuln.affected ?? []) {
          for (const range of affected.ranges ?? []) {
            const fixedEvent = range.events?.find((e) => e.fixed);
            if (fixedEvent?.fixed) { fixedVersion = fixedEvent.fixed; break; }
          }
          if (fixedVersion) break;
        }

        // Determine severity from CVSS or default
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

    // Deduplicate by vulnId+package
    const seen = new Set<string>();
    return findings.filter((f) => {
      const key = `${f.vulnId}:${f.packageName}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  } catch {
    return []; // OSV unavailable — degrade gracefully
  }
}
```

**Step 2: Commit**
```bash
git add packages/server/src/lib/osv.ts
git commit -m "feat: OSV API integration — real CVE scanning from parsed dependency files"
```

---

## Phase 5: Secret scanning (regex, no external API)

### Task 7: Create `packages/server/src/lib/secrets.ts`

**Files:**
- Create: `packages/server/src/lib/secrets.ts`

**Step 1: Create the file**
```typescript
import type { SecretFinding } from './analyzer.js';
import type { RepoFile } from '../types.js';

// Patterns ordered by specificity — more specific patterns first
const SECRET_PATTERNS: Array<{ type: string; pattern: RegExp }> = [
  { type: 'AWS Access Key', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { type: 'AWS Secret Key', pattern: /\b[Aa]ws[_\-]?[Ss]ecret[_\-]?[Kk]ey\s*[=:]\s*['"]?([A-Za-z0-9/+]{40})['"]?/ },
  { type: 'GitHub Personal Access Token', pattern: /\bghp_[A-Za-z0-9]{36}\b/ },
  { type: 'GitHub Fine-Grained PAT', pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/ },
  { type: 'Slack Bot Token', pattern: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/ },
  { type: 'Slack App Token', pattern: /\bxapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{13}-[a-f0-9]{64}\b/ },
  { type: 'Stripe Secret Key', pattern: /\bsk_live_[A-Za-z0-9]{24,}\b/ },
  { type: 'Google API Key', pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { type: 'JWT', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { type: 'Private Key (PEM)', pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { type: 'GoDaddy API Key Pattern', pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { type: 'Generic Secret Assignment', pattern: /(?:password|passwd|secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*['"][^'"]{8,}['"]/i },
];

// Skip files that are expected to contain secret-shaped strings
const SKIP_PATHS = /\.(test|spec|md|example|sample)\.|__tests__\/|\.env\.example/i;

export function scanForSecrets(files: RepoFile[]): SecretFinding[] {
  const findings: SecretFinding[] = [];

  for (const file of files) {
    if (SKIP_PATHS.test(file.path)) continue;

    const lines = file.content.split('\n');
    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];

      for (const { type, pattern } of SECRET_PATTERNS) {
        const match = line.match(pattern);
        if (match) {
          const raw = match[1] ?? match[0];
          // Redact middle: show first 4 + asterisks + last 2
          const preview = raw.length > 8
            ? raw.slice(0, 4) + '*'.repeat(Math.min(raw.length - 6, 12)) + raw.slice(-2)
            : raw.slice(0, 2) + '*'.repeat(raw.length - 2);

          findings.push({
            path: file.path,
            line: lineNum + 1,
            type,
            preview,
          });
          break; // only report first match per line
        }
      }
    }
  }

  return findings;
}
```

**Step 2: Commit**
```bash
git add packages/server/src/lib/secrets.ts
git commit -m "feat: secret scanning — 12 pattern types, no external API"
```

---

## Phase 6: Wire OSV + secrets + thinking into `analyzer.ts`

### Task 8: Update `runAnalysis` pipeline

**Files:**
- Modify: `packages/server/src/lib/analyzer.ts`

**Step 1: Add imports at top of `analyzer.ts`**
```typescript
import { parseDependencies, scanWithOsv } from './osv.js';
import { scanForSecrets } from './secrets.js';
```

**Step 2: Add a new phase notification after Phase 2 file fetching, before Claude call**

After the two-pass triage block (from Task 5), add:
```typescript
// Phase 2b: Parallel scans (CVE + secrets) — run while we prepare Claude call
notify(job, { phase: 'fetching', message: 'Running CVE scan and secret detection...' });
const [cveScanResults, secretScanFindings] = await Promise.all([
  scanWithOsv(parseDependencies(snapshot.priorityFiles)),
  Promise.resolve(scanForSecrets(snapshot.priorityFiles)),
]);

const sbom = parseDependencies(snapshot.priorityFiles);

notify(job, {
  phase: 'fetching',
  message: `CVE scan: ${cveScanResults.length} findings | Secrets: ${secretScanFindings.length} findings`,
});
```

**Step 3: Inject CVE and secret findings into Claude prompt**

In `claude.ts`, update `buildAnalysisPrompt` to accept optional scan results:

Change the signature from:
```typescript
export function buildAnalysisPrompt(snapshot: RepoSnapshot): string {
```
To:
```typescript
export function buildAnalysisPrompt(
  snapshot: RepoSnapshot,
  cveScanResults?: CveFinding[],
  secretScanFindings?: SecretFinding[]
): string {
```

Add after the `fileBlocks` construction and before the return:
```typescript
let prebuiltContext = '';

if (cveScanResults && cveScanResults.length > 0) {
  const cveLines = cveScanResults
    .slice(0, 20) // top 20 to keep prompt size reasonable
    .map((c) => `- ${c.packageName}@${c.version} → ${c.vulnId} (${c.severity}): ${c.summary}${c.fixedVersion ? ` | Fix: upgrade to ${c.fixedVersion}` : ''}`)
    .join('\n');
  prebuiltContext += `\n\n## REAL CVE DATA (from OSV API — use this for Q28 answer):\n${cveLines}`;
}

if (secretScanFindings && secretScanFindings.length > 0) {
  const secretLines = secretScanFindings
    .map((s) => `- ${s.path}:${s.line} → ${s.type} (${s.preview})`)
    .join('\n');
  prebuiltContext += `\n\n## DETECTED SECRETS IN CODE (use this for Q10 answer):\n${secretLines}`;
}
```

Insert `${prebuiltContext}` into the prompt string right after the file blocks section.

**Step 4: Update the `streamAnalysis` call in `analyzer.ts` to pass scan results**

Find:
```typescript
for await (const chunk of streamAnalysis(snapshot)) {
```

Change the `streamAnalysis` signature in `claude.ts` to accept and pass through:
```typescript
export async function* streamAnalysis(
  snapshot: RepoSnapshot,
  cveScanResults?: CveFinding[],
  secretScanFindings?: SecretFinding[]
): AsyncGenerator<AnalysisChunk> {
  const client = createClaudeClient();
  const prompt = buildAnalysisPrompt(snapshot, cveScanResults, secretScanFindings);
  // ... rest unchanged
```

And in `analyzer.ts`:
```typescript
for await (const chunk of streamAnalysis(snapshot, cveScanResults, secretScanFindings)) {
```

**Step 5: Store thinking text and attach scan results to the final result**

Find the result parsing block:
```typescript
const jsonText = rawJson.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();
const parsed = JSON.parse(jsonText) as AnalysisResult;
parsed.snapshot = snapshot;
```

Replace with:
```typescript
const jsonText = rawJson.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();
const parsed = JSON.parse(jsonText) as AnalysisResult;
parsed.snapshot = snapshot;
parsed.thinkingText = thinkingText;
parsed.cveScanResults = cveScanResults;
parsed.secretScanFindings = secretScanFindings;
parsed.sbom = sbom;
```

And accumulate thinking text — find the thinking chunk handler:
```typescript
if (chunk.type === 'thinking') {
  notify(job, { phase: 'thinking', message: chunk.content });
```
Change to:
```typescript
let thinkingText = ''; // declare before the for-await loop
// ...inside loop:
if (chunk.type === 'thinking') {
  thinkingText += chunk.content;
  notify(job, { phase: 'thinking', message: chunk.content });
```

**Step 6: Commit**
```bash
git add packages/server/src/lib/analyzer.ts packages/server/src/lib/claude.ts
git commit -m "feat: wire CVE scan, secret scan, SBOM, and thinking text into analysis result"
```

---

## Phase 7: Dependabot alerts via GitHub API

### Task 9: Add `fetchDependabotAlerts` to `github.ts`

**Files:**
- Modify: `packages/server/src/lib/github.ts`
- Modify: `packages/server/src/lib/analyzer.ts`

**Step 1: Add to `github.ts`**
```typescript
export async function fetchDependabotAlerts(ref: RepoRef): Promise<CveFinding[]> {
  const pat = process.env.GITHUB_PAT!;
  const baseUrl = process.env.GITHUB_API_URL!;
  const octokit = createGitHubClient(pat, baseUrl);

  try {
    // First check if dependabot.yml exists (proxy for Dependabot being active)
    await octokit.repos.getContent({
      owner: ref.owner,
      repo: ref.repo,
      path: '.github/dependabot.yml',
    });

    // Fetch open Dependabot alerts
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
    // Dependabot not configured or API not available — not an error
    return [];
  }
}
```

**Step 2: Merge Dependabot results with OSV results in `analyzer.ts`**

In the parallel scan block from Task 8, update to:
```typescript
const [osvResults, dependabotResults, secretScanFindings] = await Promise.all([
  scanWithOsv(parseDependencies(snapshot.priorityFiles)),
  fetchDependabotAlerts(ref),
  Promise.resolve(scanForSecrets(snapshot.priorityFiles)),
]);

// Merge and deduplicate by vulnId
const seen = new Set<string>();
const cveScanResults: CveFinding[] = [];
for (const finding of [...osvResults, ...dependabotResults]) {
  const key = `${finding.vulnId}:${finding.packageName}`;
  if (!seen.has(key)) {
    seen.add(key);
    cveScanResults.push(finding);
  }
}
```

**Step 3: Commit**
```bash
git add packages/server/src/lib/github.ts packages/server/src/lib/analyzer.ts
git commit -m "feat: merge Dependabot alerts with OSV CVE results"
```

---

## Phase 8: Persist jobs to disk

### Task 10: Add job persistence in `analyzer.ts`

**Files:**
- Modify: `packages/server/src/lib/analyzer.ts`

**Step 1: Add file persistence at the top of `analyzer.ts`**
```typescript
import { writeFileSync, readFileSync, mkdirSync, existsSync, readdirSync } from 'fs';
import { join } from 'path';

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

// Load persisted jobs on startup
loadPersistedJobs();
```

**Step 2: Call `persistJob` when job completes in `runAnalysis`**

Find:
```typescript
job.status = JobStatus.Done;
notify(job, { phase: 'done', message: 'Analysis complete', data: parsed });
```
Add after:
```typescript
persistJob(job);
```

**Step 3: Add `.certai-jobs/` to `.gitignore`**
```bash
echo '.certai-jobs/' >> /Users/skilaru/Documents/certai/.gitignore
```

**Step 4: Commit**
```bash
git add packages/server/src/lib/analyzer.ts .gitignore
git commit -m "feat: persist completed jobs to disk — survives server restarts"
```

---

## Phase 9: UI — New tabs, enriched components

### Task 11: Add Dependencies tab to `ResultView.tsx`

**Files:**
- Modify: `packages/web/src/components/ResultView.tsx`

**Step 1: Update `TABS` constant**
```typescript
const TABS = ['Overview', 'Architecture', 'Threats', 'Questionnaire', 'IRP', 'Dependencies', 'AI Reasoning'] as const;
```

**Step 2: Add CVE count stat to the stats row**

Find the stats row (3 columns). Add a 4th column. Change `grid-cols-3` to `grid-cols-4` and add:
```tsx
<div className="px-6 py-4 text-center">
  <p className={`text-2xl font-bold ${result.cveScanResults?.length > 0 ? 'text-orange-400' : 'text-green-400'}`}>
    {result.cveScanResults?.length ?? 0}
  </p>
  <p className="text-xs text-gray-500 mt-0.5">CVEs found</p>
</div>
```

**Step 3: Add "Time saved" stat below the hero banner**

After the stats row closing `</div>`, add:
```tsx
{/* Time saved banner */}
<div className="border-t border-gray-800 px-6 py-3 bg-indigo-950/20 flex items-center justify-between">
  <span className="text-xs text-indigo-400">
    ⚡ Manual security certification averages <strong>61 days</strong> at GoDaddy
  </span>
  <span className="text-xs text-indigo-300 font-semibold">
    CertAI completed this analysis in seconds
  </span>
</div>
```

**Step 4: Add security score ring to Overview tab**

In the Overview tab, before the "Risk Summary" section, add:
```tsx
{/* Security Score */}
<div className="flex items-center gap-6 bg-gray-950 rounded-xl p-5 border border-gray-800">
  <div className="relative w-20 h-20 shrink-0">
    <svg className="w-20 h-20 -rotate-90" viewBox="0 0 36 36">
      <circle cx="18" cy="18" r="15.9" fill="none" stroke="#1f2937" strokeWidth="3" />
      <circle
        cx="18" cy="18" r="15.9" fill="none"
        stroke={result.securityScore >= 70 ? '#22c55e' : result.securityScore >= 40 ? '#f59e0b' : '#ef4444'}
        strokeWidth="3"
        strokeDasharray={`${result.securityScore} 100`}
        strokeLinecap="round"
      />
    </svg>
    <span className="absolute inset-0 flex items-center justify-center text-xl font-bold text-white">
      {result.securityScore ?? 0}
    </span>
  </div>
  <div>
    <p className="text-white font-semibold">Security Score</p>
    <p className="text-gray-500 text-sm mt-0.5">
      {(result.securityScore ?? 0) >= 70 ? 'Good security posture' :
       (result.securityScore ?? 0) >= 40 ? 'Needs improvement' :
       'Critical issues require attention'}
    </p>
  </div>
</div>
```

**Step 5: Add Dependencies tab content**
```tsx
{activeTab === 'Dependencies' && (
  <div className="space-y-6">
    {/* CVE Findings */}
    <div>
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
        CVE Findings
        <span className="ml-2 normal-case font-normal text-gray-600">
          from OSV API + Dependabot
        </span>
      </h3>
      {(!result.cveScanResults || result.cveScanResults.length === 0) ? (
        <div className="text-center py-8 text-gray-600">
          <p className="text-3xl mb-2">✅</p>
          <p>No known CVEs found in parsed dependencies.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {result.cveScanResults.map((c, i) => (
            <div key={i} className="bg-gray-950 border border-gray-800 rounded-xl p-4">
              <div className="flex items-start gap-3">
                <span className={`text-xs font-bold border px-2 py-0.5 rounded-full shrink-0 mt-0.5 ${
                  c.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                  c.severity === 'High' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                  c.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                  'bg-green-500/20 text-green-400 border-green-500/30'
                }`}>{c.severity}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-baseline gap-2 flex-wrap">
                    <code className="text-white font-mono text-sm">{c.packageName}@{c.version}</code>
                    <span className="text-indigo-400 text-xs font-mono">{c.vulnId}</span>
                  </div>
                  <p className="text-gray-400 text-xs mt-1">{c.summary}</p>
                  {c.fixedVersion && (
                    <p className="text-green-400 text-xs mt-1">Fix: upgrade to {c.fixedVersion}</p>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>

    {/* Secret Findings */}
    {result.secretScanFindings && result.secretScanFindings.length > 0 && (
      <div>
        <h3 className="text-sm font-semibold text-red-400 uppercase tracking-wider mb-4">
          ⚠ Potential Secrets Detected
        </h3>
        <div className="space-y-2">
          {result.secretScanFindings.map((s, i) => (
            <div key={i} className="bg-red-950/20 border border-red-800/40 rounded-xl p-4">
              <div className="flex items-center gap-3">
                <span className="text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded-full">
                  {s.type}
                </span>
                <code className="text-red-300 font-mono text-xs">{s.path}:{s.line}</code>
                <code className="text-gray-600 font-mono text-xs ml-auto">{s.preview}</code>
              </div>
            </div>
          ))}
        </div>
      </div>
    )}

    {/* SBOM Download */}
    {result.sbom && result.sbom.length > 0 && (
      <div>
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
          SBOM — {result.sbom.length} components
        </h3>
        <button
          onClick={() => downloadSbom(result.sbom, repoUrl)}
          className="bg-gray-800 hover:bg-gray-700 border border-gray-700 text-white text-sm
                     px-4 py-2.5 rounded-xl transition-colors flex items-center gap-2"
        >
          Download CycloneDX JSON
        </button>
      </div>
    )}
  </div>
)}
```

**Step 6: Add SBOM download helper function** — add before the `ResultView` component:
```typescript
function downloadSbom(components: SbomComponent[], repoUrl: string) {
  const repoName = repoUrl.split('/').pop() ?? 'repo';
  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'GoDaddy', name: 'CertAI', version: '2.0' }],
      component: { type: 'application', name: repoName },
    },
    components: components.map((c) => ({
      type: 'library',
      name: c.name,
      version: c.version,
      purl: c.purl,
    })),
  };
  const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${repoName}-sbom.cdx.json`;
  a.click();
  URL.revokeObjectURL(url);
}
```

**Step 7: Add AI Reasoning tab content**
```tsx
{activeTab === 'AI Reasoning' && (
  <div>
    <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
      Claude's Extended Thinking
      <span className="ml-2 normal-case font-normal text-gray-600">
        {result.thinkingText ? `${(result.thinkingText.length / 1000).toFixed(1)}k chars` : 'Not available'}
      </span>
    </h3>
    {result.thinkingText ? (
      <pre className="text-xs text-gray-500 bg-gray-950 border border-gray-800 rounded-xl p-5
                      max-h-[600px] overflow-y-auto whitespace-pre-wrap leading-relaxed font-mono">
        {result.thinkingText}
      </pre>
    ) : (
      <p className="text-gray-600 text-sm">Thinking text was not captured for this analysis.</p>
    )}
  </div>
)}
```

**Step 8: Commit**
```bash
git add packages/web/src/components/ResultView.tsx
git commit -m "feat: UI — Dependencies tab, CVE list, secret findings, SBOM download, AI Reasoning tab, security score, time-saved banner"
```

---

### Task 12: Enrich `ThreatTable.tsx` with STRIDE + DREAD + OWASP

**Files:**
- Modify: `packages/web/src/components/ThreatTable.tsx`

**Step 1: Add STRIDE badge and DREAD score to each threat card**

After the `{t.likelihood} likelihood` span:
```tsx
{t.strideCategory && (
  <span className="text-xs bg-purple-500/20 text-purple-300 border border-purple-500/30 px-2 py-0.5 rounded-full">
    {t.strideCategory}
  </span>
)}
{t.dreadScore !== undefined && (
  <span className="text-xs text-gray-500">
    DREAD: <span className={t.dreadScore >= 7 ? 'text-red-400' : t.dreadScore >= 4 ? 'text-yellow-400' : 'text-green-400'}>
      {t.dreadScore}/10
    </span>
  </span>
)}
{t.owaspCategory && (
  <span className="text-xs text-blue-400 font-mono">{t.owaspCategory.split('–')[0].trim()}</span>
)}
```

**Step 2: Commit**
```bash
git add packages/web/src/components/ThreatTable.tsx
git commit -m "feat: threat table — show STRIDE category, DREAD score, OWASP category"
```

---

### Task 13: Enrich `Questionnaire.tsx` with confidence badges

**Files:**
- Modify: `packages/web/src/components/Questionnaire.tsx`

**Step 1: Add confidence badge in the accordion header**

Find the button's flex row. Add after the question text span:
```tsx
{item.confidence && (
  <span className={`text-xs px-2 py-0.5 rounded-full border shrink-0 ${
    item.confidence === 'Confirmed'
      ? 'bg-green-500/10 text-green-400 border-green-500/30'
      : item.confidence === 'Inferred'
      ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
      : 'bg-red-500/10 text-red-300 border-red-500/30'
  }`}>
    {item.confidence === 'Confirmed' ? '✓ Confirmed' :
     item.confidence === 'Inferred' ? '~ Inferred' :
     '? Verify'}
  </span>
)}
```

**Step 2: Commit**
```bash
git add packages/web/src/components/Questionnaire.tsx
git commit -m "feat: questionnaire — confidence badges (Confirmed/Inferred/Verify) per answer"
```

---

## Phase 10: OWASP Top 10 tab

### Task 14: Add OWASP summary tab to `ResultView.tsx`

**Files:**
- Modify: `packages/web/src/components/ResultView.tsx`

**Step 1: Add `OWASP` to the TABS constant** (already done in Task 11 — just add it if not there)

Actually, keep tabs lean. Add OWASP as a subsection within the Threats tab instead.

**Step 1: Add OWASP mapping view inside the Threats tab**

After the `<ThreatTable threats={result.threats} />` block, add:
```tsx
{/* OWASP Top 10 breakdown */}
{result.threats.some(t => t.owaspCategory) && (
  <div className="mt-6">
    <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">OWASP Top 10 Coverage</h4>
    <div className="space-y-1.5">
      {Object.entries(
        result.threats
          .filter(t => t.owaspCategory)
          .reduce<Record<string, number>>((acc, t) => {
            const cat = t.owaspCategory.split('–')[0].trim();
            acc[cat] = (acc[cat] ?? 0) + 1;
            return acc;
          }, {})
      ).sort(([, a], [, b]) => b - a).map(([cat, count]) => (
        <div key={cat} className="flex items-center gap-3">
          <code className="text-xs text-blue-400 font-mono w-10 shrink-0">{cat}</code>
          <div className="flex-1 bg-gray-800 rounded-full h-1.5">
            <div
              className="bg-blue-500 rounded-full h-1.5"
              style={{ width: `${Math.min(100, count * 20)}%` }}
            />
          </div>
          <span className="text-xs text-gray-600 w-4 text-right">{count}</span>
        </div>
      ))}
    </div>
  </div>
)}
```

**Step 2: Commit**
```bash
git add packages/web/src/components/ResultView.tsx
git commit -m "feat: OWASP Top 10 coverage breakdown in Threats tab"
```

---

## Phase 11: Update Confluence publish output

### Task 15: Update `atlassian.ts` to include new fields in the published page

**Files:**
- Modify: `packages/server/src/lib/atlassian.ts`

**Step 1: Update `resultToMarkdown` to include CVE findings and security score**

Add these sections to the generated markdown:

After the threat model table:
```typescript
// CVE section
let cveSection = '';
if (result.cveScanResults && result.cveScanResults.length > 0) {
  const critHighCves = result.cveScanResults.filter(c =>
    c.severity === 'Critical' || c.severity === 'High'
  );
  const cveRows = result.cveScanResults
    .slice(0, 20)
    .map(c => `| ${c.packageName}@${c.version} | ${c.vulnId} | ${c.severity} | ${c.summary.slice(0, 80)} | ${c.fixedVersion ?? 'No patch available'} |`)
    .join('\n');
  cveSection = `\n---\n\n## Dependency CVEs (${result.cveScanResults.length} total, ${critHighCves.length} critical/high)\n\n| Package | CVE ID | Severity | Summary | Fix |\n|---------|--------|----------|---------|-----|\n${cveRows}`;
}

// Secrets section
let secretSection = '';
if (result.secretScanFindings && result.secretScanFindings.length > 0) {
  secretSection = `\n---\n\n## ⚠ Potential Secrets Detected\n\n${
    result.secretScanFindings.map(s => `- **${s.type}** at \`${s.path}:${s.line}\` (${s.preview})`).join('\n')
  }`;
}
```

And append them to the return string.

**Step 2: Update the header to include security score**
```typescript
// Change:
**Risk Category:** ${result.riskCategory}
// To:
**Risk Category:** ${result.riskCategory}
**Security Score:** ${result.securityScore ?? 'N/A'}/100
```

**Step 3: Commit**
```bash
git add packages/server/src/lib/atlassian.ts
git commit -m "feat: include CVE findings, secret findings, and security score in Confluence publish"
```

---

## Phase 12: Final integration test and push

### Task 16: Verify the full pipeline runs

**Step 1: Start the dev server**
```bash
cd /Users/skilaru/Documents/certai
npm run dev
```

**Step 2: Verify TypeScript compiles without errors**
```bash
npm run build -w packages/server 2>&1 | head -30
```
Expected: no TypeScript errors.

**Step 3: Submit a real repo and verify**
- Open http://localhost:5173
- Paste a GoDaddy GitHub URL
- Verify the analysis completes
- Check: Dependencies tab shows CVE data (or "no CVEs" for clean repos)
- Check: Threats tab shows STRIDE + DREAD + OWASP
- Check: Questionnaire shows confidence badges
- Check: AI Reasoning tab shows thinking text
- Check: Security score ring shows on Overview
- Check: Time saved banner shows

**Step 4: Final commit and push to main**
```bash
git log --oneline -10
git push origin main
```

---

## Summary of changes

| Phase | Files touched | What it does |
|-------|--------------|--------------|
| 1 | `analyzer.ts` types | STRIDE, DREAD, OWASP, confidence, score, CVE, secret, SBOM types |
| 1 | `web/types.ts` | Mirror new types in frontend |
| 2 | `claude.ts` prompt | Prompt teaches Claude to produce all new fields |
| 3 | `claude.ts` + `github.ts` | Two-pass: Claude triages files, fetch up to 30 |
| 4 | `osv.ts` (new) | Parse deps + OSV batch API CVE scan |
| 5 | `secrets.ts` (new) | Regex secret detection, 12 pattern types |
| 6 | `analyzer.ts` pipeline | Wire all scans into runAnalysis, store thinking |
| 7 | `github.ts` + `analyzer.ts` | Dependabot alerts merged with OSV results |
| 8 | `analyzer.ts` | Job persistence to `.certai-jobs/` |
| 9 | `ResultView.tsx` | Dependencies tab, AI Reasoning tab, score ring, time-saved |
| 10 | `ThreatTable.tsx` | STRIDE + DREAD + OWASP per threat |
| 11 | `Questionnaire.tsx` | Confidence badges |
| 12 | `ResultView.tsx` | OWASP Top 10 breakdown chart |
| 13 | `atlassian.ts` | CVEs + secrets + score in Confluence output |

All external API calls are **free and no-auth**: OSV API (Google), Dependabot via existing GitHub PAT.
