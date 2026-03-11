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
  branch: string;
  commitSha: string;
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
  reachable?: boolean | null;  // null = unknown
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

// ─── New interfaces for Phase 1 ───────────────────────────────────────────────

export interface ApiEndpoint {
  endpoint: string;       // e.g. "POST /api/users"
  mutating: boolean;
  authn: string;          // e.g. "JWT Bearer", "None"
  authz: string;          // e.g. "RBAC", "None"
  externalFacing: boolean;
}

export interface ApiGatewayChecklist {
  https: boolean;
  approvedAuth: boolean;   // JWT or certs only
  rateLimiting: boolean;
  anomalyMonitoring: boolean;
  notes: string;
}

export interface MonitoringInfo {
  loggingFramework: string;
  logDestination: string;
  retentionPolicy: string;
  alertingSetup: string;
}

export interface IacFinding {
  resource: string;
  check: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  file: string;
  line?: number;
  framework: string;  // "Terraform" | "CloudFormation" | "Kubernetes" | "Dockerfile"
}

export interface OwaspAsvs {
  chapter: string;         // e.g. "V2 Authentication"
  requirement: string;
  level: 1 | 2 | 3;
  status: 'pass' | 'fail' | 'not-applicable';
  evidence: string;
}

export interface ComplianceGap {
  framework: string;   // "PCI DSS" | "SOC 2" | "ISO 27001" | "GoDaddy CAT"
  control: string;
  status: 'pass' | 'fail' | 'partial';
  notes: string;
}

export interface PentestScope {
  highRiskAreas: string[];
  attackSurface: string[];
  testingRecommendations: string[];
  estimatedEffort: string;
}

export interface FairRiskEstimate {
  threat: string;
  annualLossExpectancy: string;   // e.g. "$10K–$100K"
  riskBand: 'low' | 'medium' | 'high' | 'critical';
  assumptions: string;
}

export interface LicenseFinding {
  packageName: string;
  version: string;
  spdxLicense: string;
  riskCategory: 'Permissive' | 'Weak Copyleft' | 'Strong Copyleft' | 'Unknown';
  requiresReview: boolean;
}

export interface SupplyChainRisk {
  packageName: string;
  signals: string[];
  riskLevel: 'low' | 'medium' | 'high';
}

export interface Remediation {
  description: string;
  codeExample?: string;
  file?: string;
  effort: 'Low' | 'Medium' | 'High';
}

export interface SemgrepFinding {
  rule: string;
  severity: string;
  description: string;
  file: string;
  line: number;
  cweId?: string;
}
