import type { IacFinding } from '../types.js';

interface Props {
  findings: IacFinding[];
}

const SEV_STYLES: Record<string, string> = {
  Critical: 'bg-red-50 text-red-700 border-red-200',
  High: 'bg-orange-50 text-orange-700 border-orange-200',
  Medium: 'bg-amber-50 text-amber-700 border-amber-200',
  Low: 'bg-green-50 text-green-700 border-green-200',
};

export function IacScanView({ findings }: Props) {
  if (findings.length === 0) {
    return (
      <div className="text-center py-12 bg-[#F5F7F8] rounded-2xl border border-[#D4DBE0]">
        <p className="text-3xl mb-2">✓</p>
        <p className="text-[#666] text-[14px] font-medium">No IaC misconfigurations found</p>
        <p className="text-[#999] text-[13px] mt-1">No Terraform, CloudFormation, Kubernetes, or Dockerfile issues detected</p>
      </div>
    );
  }

  const counts = {
    Critical: findings.filter((f) => f.severity === 'Critical').length,
    High: findings.filter((f) => f.severity === 'High').length,
    Medium: findings.filter((f) => f.severity === 'Medium').length,
    Low: findings.filter((f) => f.severity === 'Low').length,
  };

  const frameworkGroups = findings.reduce<Record<string, IacFinding[]>>((acc, f) => {
    acc[f.framework] = acc[f.framework] ?? [];
    acc[f.framework].push(f);
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="grid grid-cols-4 gap-3">
        {(['Critical', 'High', 'Medium', 'Low'] as const).map((sev) => (
          <div key={sev} className={`border rounded-2xl p-4 text-center ${SEV_STYLES[sev].replace('border-', 'border ').split(' ').filter(c => !c.includes('text-')).join(' ')}`}>
            <p className={`text-[22px] font-bold ${SEV_STYLES[sev].split(' ').find(c => c.startsWith('text-'))}`}>{counts[sev]}</p>
            <p className="text-[12px] text-[#666] mt-0.5">{sev}</p>
          </div>
        ))}
      </div>

      {/* Findings by framework */}
      {Object.entries(frameworkGroups).map(([framework, fwFindings]) => (
        <div key={framework}>
          <h4 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-3">{framework}</h4>
          <div className="space-y-2">
            {fwFindings.map((f, i) => (
              <div key={i} className="bg-white border border-[#D4DBE0] rounded-2xl p-4">
                <div className="flex items-start gap-3">
                  <span className={`text-[11px] font-semibold border px-2 py-0.5 rounded-[6px] shrink-0 mt-0.5 ${SEV_STYLES[f.severity]}`}>
                    {f.severity}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-[14px] text-[#111] font-medium">{f.check}</p>
                    <div className="flex items-center gap-3 mt-1 flex-wrap">
                      <code className="text-[12px] text-[#666] font-mono">{f.resource}</code>
                      <code className="text-[12px] text-[#999] font-mono">
                        {f.file}{f.line ? `:${f.line}` : ''}
                      </code>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
