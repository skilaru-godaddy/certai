import type { SecretFinding } from '../types.js';
import type { RepoFile } from '../types.js';

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
          const preview = raw.length > 8
            ? raw.slice(0, 4) + '*'.repeat(Math.min(raw.length - 6, 12)) + raw.slice(-2)
            : raw.slice(0, 2) + '*'.repeat(raw.length - 2);

          findings.push({
            path: file.path,
            line: lineNum + 1,
            type,
            preview,
          });
          break;
        }
      }
    }
  }

  return findings;
}
