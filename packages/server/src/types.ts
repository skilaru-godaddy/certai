export interface RepoRef {
  owner: string;
  repo: string;
  host: string; // 'github.secureserver.net' or 'github.com'
}

export interface RepoFile {
  path: string;
  content: string;
  sizeBytes: number;
}

export interface RepoSnapshot {
  ref: RepoRef;
  allPaths: string[];          // full file tree
  priorityFiles: RepoFile[];   // top 14 security-relevant files
  treeText: string;            // human-readable tree for Claude
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
  preview: string;      // first 4 chars + asterisks + last 2
}

export interface SbomComponent {
  name: string;
  version: string;
  ecosystem: string;    // "npm", "pypi", "go", "maven"
  purl: string;         // e.g. "pkg:npm/express@4.18.0"
}
