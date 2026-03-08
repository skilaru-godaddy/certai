import Anthropic from '@anthropic-ai/sdk';
import type { RepoSnapshot } from '../types.js';

// ─── Client (GoCode proxy drop-in) ───────────────────────────────────────────

export function createClaudeClient() {
  return new Anthropic({
    baseURL: process.env.GOCODE_BASE_URL,
    apiKey: process.env.GOCODE_API_KEY,
  });
}

// ─── Prompt builder ───────────────────────────────────────────────────────────

export function buildAnalysisPrompt(snapshot: RepoSnapshot): string {
  const fileBlocks = snapshot.priorityFiles
    .map((f) => `### ${f.path}\n\`\`\`\n${f.content}\n\`\`\``)
    .join('\n\n');

  return `You are a GoDaddy security engineer performing a security certification analysis.

## Repo: ${snapshot.ref.owner}/${snapshot.ref.repo}
Host: ${snapshot.ref.host}

## Full file tree (first 60 paths):
${snapshot.treeText}

## Security-relevant files (${snapshot.priorityFiles.length} files):
${fileBlocks}

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
      "codeEvidence": "path/to/file.ts:lineHint"
    }
  ],
  "questionnaire": [
    {
      "id": 1,
      "question": "string",
      "answer": "string",
      "evidence": "path/to/file.ts:lineHint or N/A"
    }
  ],
  "irpDraft": "string — markdown incident response plan draft"
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

Return ONLY the JSON object, no markdown fences, no explanation.`;
}

// ─── Streaming analysis ───────────────────────────────────────────────────────

export interface AnalysisChunk {
  type: 'thinking' | 'text' | 'done' | 'error';
  content: string;
}

export async function* streamAnalysis(
  snapshot: RepoSnapshot
): AsyncGenerator<AnalysisChunk> {
  const client = createClaudeClient();
  const prompt = buildAnalysisPrompt(snapshot);

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
