import type { OwaspAsvs, ComplianceGap, FairRiskEstimate } from '../types.js';

interface Props {
  owaspAsvs: OwaspAsvs[];
  complianceGaps: ComplianceGap[];
  fairRiskEstimates: FairRiskEstimate[];
}

const STATUS_STYLES: Record<string, string> = {
  pass: 'bg-green-50 text-green-700 border-green-200',
  fail: 'bg-red-50 text-red-700 border-red-200',
  partial: 'bg-amber-50 text-amber-700 border-amber-200',
  'not-applicable': 'bg-[#F5F7F8] text-[#999] border-[#D4DBE0]',
};

const RISK_BAND_STYLES: Record<string, string> = {
  low: 'bg-green-50 text-green-700 border-green-200',
  medium: 'bg-amber-50 text-amber-700 border-amber-200',
  high: 'bg-orange-50 text-orange-700 border-orange-200',
  critical: 'bg-red-50 text-red-700 border-red-200',
};

export function ComplianceView({ owaspAsvs, complianceGaps, fairRiskEstimates }: Props) {
  // Group ASVS by chapter
  const chapterGroups = (owaspAsvs ?? []).reduce<Record<string, OwaspAsvs[]>>((acc, item) => {
    acc[item.chapter] = acc[item.chapter] ?? [];
    acc[item.chapter].push(item);
    return acc;
  }, {});

  const gapsByFramework = (complianceGaps ?? []).reduce<Record<string, ComplianceGap[]>>((acc, g) => {
    acc[g.framework] = acc[g.framework] ?? [];
    acc[g.framework].push(g);
    return acc;
  }, {});

  return (
    <div className="space-y-8">
      {/* OWASP ASVS */}
      <section>
        <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
          OWASP ASVS
          <span className="ml-2 normal-case font-normal text-[#999]">
            {(owaspAsvs ?? []).length} requirements assessed
          </span>
        </h3>

        {Object.keys(chapterGroups).length === 0 ? (
          <p className="text-[#999] text-[13px]">No ASVS requirements assessed</p>
        ) : (
          <div className="space-y-4">
            {Object.entries(chapterGroups).map(([chapter, items]) => {
              const passCount = items.filter((i) => i.status === 'pass').length;
              const failCount = items.filter((i) => i.status === 'fail').length;
              return (
                <div key={chapter} className="border border-[#D4DBE0] rounded-2xl overflow-hidden">
                  <div className="px-5 py-3 bg-[#F5F7F8] flex items-center justify-between">
                    <span className="text-[13px] font-semibold text-[#111]">{chapter}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[12px] text-green-700">{passCount} pass</span>
                      {failCount > 0 && <span className="text-[12px] text-red-700">{failCount} fail</span>}
                    </div>
                  </div>
                  <div className="divide-y divide-[#F5F7F8]">
                    {items.map((item, i) => (
                      <div key={i} className="px-5 py-3 flex items-start gap-3">
                        <span className={`text-[11px] font-semibold border px-1.5 py-0.5 rounded-[6px] shrink-0 mt-0.5 ${STATUS_STYLES[item.status]}`}>
                          {item.status === 'not-applicable' ? 'N/A' : item.status.toUpperCase()}
                        </span>
                        <span className="text-[11px] bg-[#F5F7F8] text-[#666] border border-[#D4DBE0] px-1.5 py-0.5 rounded-[6px] shrink-0 mt-0.5">L{item.level}</span>
                        <div className="flex-1 min-w-0">
                          <p className="text-[13px] text-[#444]">{item.requirement}</p>
                          {item.evidence && (
                            <p className="text-[12px] text-[#999] font-mono mt-0.5">{item.evidence}</p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Compliance Gaps */}
      <section>
        <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
          Compliance Gaps
        </h3>
        {Object.keys(gapsByFramework).length === 0 ? (
          <p className="text-[#999] text-[13px]">No compliance gaps assessed</p>
        ) : (
          <div className="space-y-4">
            {Object.entries(gapsByFramework).map(([framework, gaps]) => (
              <div key={framework}>
                <h4 className="text-[13px] font-semibold text-[#111] mb-2">{framework}</h4>
                <div className="space-y-1.5">
                  {gaps.map((gap, i) => (
                    <div key={i} className="flex items-start gap-3 bg-white border border-[#D4DBE0] rounded-2xl p-3">
                      <span className={`text-[11px] font-semibold border px-1.5 py-0.5 rounded-[6px] shrink-0 mt-0.5 ${STATUS_STYLES[gap.status]}`}>
                        {gap.status.toUpperCase()}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-[13px] font-medium text-[#111]">{gap.control}</p>
                        {gap.notes && <p className="text-[12px] text-[#666] mt-0.5">{gap.notes}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* FAIR Risk Estimates */}
      <section>
        <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
          FAIR Risk Estimates
        </h3>
        {(fairRiskEstimates ?? []).length === 0 ? (
          <p className="text-[#999] text-[13px]">No FAIR estimates available</p>
        ) : (
          <div className="space-y-3">
            {fairRiskEstimates.map((estimate, i) => (
              <div key={i} className="bg-white border border-[#D4DBE0] rounded-2xl p-5">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <p className="text-[15px] font-semibold text-[#111]">{estimate.threat}</p>
                    <p className="text-[13px] text-[#666] mt-1">{estimate.assumptions}</p>
                  </div>
                  <div className="text-right shrink-0">
                    <p className="text-[13px] font-semibold text-[#111]">{estimate.annualLossExpectancy}</p>
                    <p className="text-[11px] text-[#999] mb-1">ALE / year</p>
                    <span className={`text-[11px] font-semibold border px-2 py-0.5 rounded-[6px] ${RISK_BAND_STYLES[estimate.riskBand]}`}>
                      {estimate.riskBand.toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
