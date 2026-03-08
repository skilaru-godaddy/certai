import Anthropic from '@anthropic-ai/sdk';
import type { RepoSnapshot, CveFinding, SecretFinding } from '../types.js';

// ─── Client (GoCode proxy drop-in) ───────────────────────────────────────────

export function createClaudeClient() {
  return new Anthropic({
    baseURL: process.env.GOCODE_BASE_URL,
    apiKey: process.env.GOCODE_API_KEY,
  });
}

// ─── Prompt builder ───────────────────────────────────────────────────────────

export function buildAnalysisPrompt(
  snapshot: RepoSnapshot,
  cveScanResults?: CveFinding[],
  secretScanFindings?: SecretFinding[]
): string {
  const fileBlocks = snapshot.priorityFiles
    .map((f) => `### ${f.path}\n\`\`\`\n${f.content}\n\`\`\``)
    .join('\n\n');

  let prebuiltContext = '';

  if (cveScanResults && cveScanResults.length > 0) {
    const cveLines = cveScanResults
      .slice(0, 20)
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

  return `You are a GoDaddy security engineer performing a security certification analysis.

## Repo: ${snapshot.ref.owner}/${snapshot.ref.repo}
Host: ${snapshot.ref.host}

## Full file tree (first 60 paths):
${snapshot.treeText}

## Security-relevant files (${snapshot.priorityFiles.length} files):
${fileBlocks}${prebuiltContext}

---

Analyze this repository thoroughly and produce a complete security certification package.

## Required Output (JSON)

Return a valid JSON object with exactly these fields:

\`\`\`json
{
  "riskCategory": "CAT 0" | "CAT 1" | "CAT 2" | "CAT 3",
  "riskReasoning": "string — 2-3 sentence explanation using evidence from the code",
  "mermaidDiagram": "string — valid Mermaid graph TD diagram showing architecture",
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
  "questionnaire": [
    {
      "id": 1,
      "question": "string",
      "answer": "string",
      "evidence": "path/to/file.ts:lineHint or N/A",
      "confidence": "Confirmed" | "Inferred" | "Needs Manual Verification"
    }
  ],
  "irpDraft": "string — markdown incident response plan draft",
  "securityScore": <number 0-100. 100=perfect security posture. Deduct: 30 pts for CAT 0, 20 for CAT 1, 10 for CAT 2; 5 pts per Critical threat; 3 per High; 10 pts if any "Needs Manual Verification" answers for auth/secrets questions (Q10, Q14, Q15, Q16, Q20, Q21); bonus +10 if no high/critical threats>
}
\`\`\`

## Risk Category Criteria (GoDaddy standard):
- CAT 0: External/public-facing, critical data (Critical/Restricted), continuous RTO, core service
- CAT 1: Highly Confidential data, internal + VPN inbound from non-GoDaddy network, 1-4h RTO
- CAT 2: Confidential data, internal-only, 4-12h RTO
- CAT 3: Public data, everything else

## Questionnaire (answer all 29):
1. Which resources will this review be primarily based on? (AWS / OnPrem / Both)
2. Which environments/accounts is this project expected to utilize?
3. Are any services within this project Service Tier 0 or 1?
4. Which regions will this project utilize?
5. Which methods are used to double/half capacity?
6. Does your application store data (database, logs, cache, etc)?
7. Does your project expose any service, UI or endpoints?
8. Are any interfaces available or reachable from the internet?
9. Which of the following are configured to protect exposed interfaces? (WAF, rate limiting, auth)
10. Is all sensitive information securely stored in a GoDaddy-approved Secrets/Certificate Manager?
11. Will application security logging be included for production services?
12. Are you using the deploy role or other privileged roles outside of automated workflows?
13. Which automated tests are required to pass within CICD pipelines prior to deployment?
14. Do you transmit data via TLS 1.2+ in or out of your account?
15. Is administrative and programmatic access to all datastores reduced to least privilege?
16. Sensitive or P*I Data must be application layer encrypted — which method?
17. Is data ever moved or accessed between Prod and Non-Prod environments?
18. For what purposes is data moved between Prod and Non-Prod?
19. Does your application store, process or transmit P*I data?
20. Do all endpoints and integrations adhere to the Authentication Pattern Standard?
21. How are all user endpoints protected?
22. Select all domains this application will run on?
23. How are all 3rd party integrations protected?
24. Will this project use machine learning before your next readiness review?
25. Does your application adhere to all Must Haves in the Must Haves Should Dos document?
26. Is everything you are using in ADOPT or MAINTAIN on TechRadar?
27. Does your application have proper error handling that does not leak sensitive information?
28. Are all dependencies up to date with no known critical/high CVEs?
29. Does the service have documented on-call runbooks and escalation paths?

For each question, provide a specific answer with code evidence (file path and line hint).
If you cannot determine from the code, state what would need to be manually verified.

## Mermaid diagram requirements:
- Use "graph TD" format
- Show all major components (services, databases, external dependencies)
- Label connections with protocols (HTTPS, OAuth2, SQL, etc.)
- Keep it to 10-15 nodes max for readability

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

Return ONLY the JSON object, no markdown fences, no explanation.`;
}

// ─── Two-pass file triage ─────────────────────────────────────────────────────

export async function triageFiles(
  allPaths: string[],
  treeText: string
): Promise<string[]> {
  const client = createClaudeClient();

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
    return selected.filter((p) => allPaths.includes(p)).slice(0, 30);
  } catch {
    return [];
  }
}

// ─── Streaming analysis ───────────────────────────────────────────────────────

export interface AnalysisChunk {
  type: 'thinking' | 'text' | 'done' | 'error';
  content: string;
}

export async function* streamAnalysis(
  snapshot: RepoSnapshot,
  cveScanResults?: CveFinding[],
  secretScanFindings?: SecretFinding[]
): AsyncGenerator<AnalysisChunk> {
  const client = createClaudeClient();
  const prompt = buildAnalysisPrompt(snapshot, cveScanResults, secretScanFindings);

  try {
    const stream = await client.messages.stream({
      model: 'claude-sonnet-4-6',
      max_tokens: 16000,
      thinking: {
        type: 'enabled',
        budget_tokens: 10000,
      },
      messages: [{ role: 'user', content: prompt }],
    });

    for await (const event of stream) {
      if (
        event.type === 'content_block_delta' &&
        event.delta.type === 'thinking_delta'
      ) {
        yield { type: 'thinking', content: event.delta.thinking };
      } else if (
        event.type === 'content_block_delta' &&
        event.delta.type === 'text_delta'
      ) {
        yield { type: 'text', content: event.delta.text };
      }
    }

    yield { type: 'done', content: '' };
  } catch (err) {
    yield { type: 'error', content: String(err) };
  }
}
