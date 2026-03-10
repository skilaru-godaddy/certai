import type { AnalysisResult } from '../types.js';

interface Props {
  result: AnalysisResult;
}

interface CheckItem {
  label: string;
  pass: boolean;
  critical: boolean;
}

export function MissingItemsChecklist({ result }: Props) {
  const checks: CheckItem[] = [
    {
      label: 'Architecture diagram generated',
      pass: !!result.mermaidDiagram,
      critical: false,
    },
    {
      label: 'Data flow diagram generated',
      pass: !!result.dataFlowDiagram,
      critical: false,
    },
    {
      label: 'API gateway checklist — all 4 controls passing',
      pass: !!(
        result.apiGatewayChecklist?.https &&
        result.apiGatewayChecklist?.approvedAuth &&
        result.apiGatewayChecklist?.rateLimiting &&
        result.apiGatewayChecklist?.anomalyMonitoring
      ),
      critical: true,
    },
    {
      label: 'All Critical threats have mitigations defined',
      pass: result.threats
        .filter((t) => t.impact === 'Critical')
        .every((t) => t.mitigation && t.mitigation.trim().length > 10),
      critical: true,
    },
    {
      label: 'SBOM has at least 1 component',
      pass: (result.sbom?.length ?? 0) > 0,
      critical: false,
    },
    {
      label: 'No unresolved secrets detected',
      pass: (result.secretScanFindings?.length ?? 0) === 0,
      critical: true,
    },
    {
      label: 'IRP has at least 1 contact defined',
      pass: !!(result.irpDraft?.match(/contact|escalat|on-call|pagerduty|slack/i)),
      critical: false,
    },
    {
      label: 'Semgrep / code scan available',
      pass: (result.semgrepFindings?.length ?? 0) >= 0 && result.semgrepFindings !== undefined,
      critical: false,
    },
  ];

  const failingCritical = checks.filter((c) => c.critical && !c.pass);
  const passCount = checks.filter((c) => c.pass).length;

  if (passCount === checks.length) {
    return (
      <div className="bg-green-50 border border-green-200 rounded-2xl p-4 flex items-center gap-3">
        <span className="text-green-600 text-xl">✓</span>
        <p className="text-[14px] text-green-800 font-medium">All cert readiness checks passing — ready to publish</p>
      </div>
    );
  }

  return (
    <div className="bg-white border border-[#D4DBE0] rounded-2xl overflow-hidden">
      <div className="px-5 py-3 border-b border-[#D4DBE0] bg-[#F5F7F8] flex items-center justify-between">
        <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider">Cert Readiness Checklist</h3>
        <span className="text-[12px] text-[#666]">{passCount}/{checks.length} passing</span>
      </div>
      <div className="p-4 space-y-2">
        {checks.map((check, i) => (
          <div key={i} className="flex items-center gap-3">
            <span className={check.pass ? 'text-green-600' : check.critical ? 'text-red-500' : 'text-amber-500'}>
              {check.pass ? '✓' : check.critical ? '✗' : '–'}
            </span>
            <span className={`text-[13px] ${check.pass ? 'text-[#444]' : check.critical ? 'text-red-700 font-medium' : 'text-[#666]'}`}>
              {check.label}
            </span>
            {!check.pass && check.critical && (
              <span className="text-[11px] bg-red-50 text-red-600 border border-red-200 px-1.5 py-0.5 rounded-[6px] ml-auto shrink-0">
                Required
              </span>
            )}
          </div>
        ))}
      </div>
      {failingCritical.length > 0 && (
        <div className="px-5 py-3 bg-amber-50 border-t border-amber-200">
          <p className="text-[12px] text-amber-700">
            ⚠ {failingCritical.length} critical item{failingCritical.length > 1 ? 's' : ''} incomplete — publishing is allowed but reviewer will flag these
          </p>
        </div>
      )}
    </div>
  );
}
