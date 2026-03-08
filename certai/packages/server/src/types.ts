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
