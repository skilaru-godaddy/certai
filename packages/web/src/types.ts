export interface ThreatItem {
  component: string;
  threat: string;
  likelihood: string;
  impact: string;
  mitigation: string;
  codeEvidence: string;
}

export interface QuestionnaireItem {
  id: number;
  question: string;
  answer: string;
  evidence: string;
}

export interface AnalysisResult {
  riskCategory: string;
  riskReasoning: string;
  mermaidDiagram: string;
  threats: ThreatItem[];
  questionnaire: QuestionnaireItem[];
  irpDraft: string;
}
