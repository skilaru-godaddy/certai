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
