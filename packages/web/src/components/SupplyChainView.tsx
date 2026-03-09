import type { LicenseFinding, SupplyChainRisk, CveFinding } from '../types.js';

interface Props {
  licenseFindings: LicenseFinding[];
  supplyChainRisks: SupplyChainRisk[];
  cveScanResults: CveFinding[];
  epssScores: Record<string, number>;
}

const LICENSE_STYLES: Record<string, string> = {
  Permissive: 'bg-green-50 text-green-700 border-green-200',
  'Weak Copyleft': 'bg-amber-50 text-amber-700 border-amber-200',
  'Strong Copyleft': 'bg-orange-50 text-orange-700 border-orange-200',
  Unknown: 'bg-red-50 text-red-700 border-red-200',
};

const RISK_STYLES: Record<string, string> = {
  low: 'bg-green-50 text-green-700 border-green-200',
  medium: 'bg-amber-50 text-amber-700 border-amber-200',
  high: 'bg-red-50 text-red-700 border-red-200',
};

export function SupplyChainView({ licenseFindings, supplyChainRisks, cveScanResults, epssScores }: Props) {
  const cveWithEpss = (cveScanResults ?? []).filter((c) => epssScores?.[c.vulnId] !== undefined);
  const reviewRequired = (licenseFindings ?? []).filter((l) => l.requiresReview);

  return (
    <div className="space-y-8">
      {/* License Compliance */}
      <section>
        <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
          License Compliance
          {reviewRequired.length > 0 && (
            <span className="ml-2 normal-case font-normal text-orange-600">
              {reviewRequired.length} requiring review
            </span>
          )}
        </h3>

        {(licenseFindings ?? []).length === 0 ? (
          <div className="text-center py-8 bg-[#F5F7F8] rounded-2xl border border-[#D4DBE0]">
            <p className="text-[#666] text-[13px]">License data not yet loaded — re-run analysis to populate</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-[#D4DBE0]">
                  {['Package', 'Version', 'License', 'Category', 'Review'].map((h) => (
                    <th key={h} className="text-left text-[#666] font-medium py-2 pr-4 text-[11px] uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F5F7F8]">
                {licenseFindings.map((l, i) => (
                  <tr key={i} className={l.requiresReview ? 'bg-orange-50/30' : 'hover:bg-[#F5F7F8]'}>
                    <td className="py-2.5 pr-4 font-mono text-[#111] text-[12px]">{l.packageName}</td>
                    <td className="py-2.5 pr-4 font-mono text-[#666] text-[12px]">{l.version}</td>
                    <td className="py-2.5 pr-4 font-mono text-[#444] text-[12px]">{l.spdxLicense}</td>
                    <td className="py-2.5 pr-4">
                      <span className={`text-[11px] font-medium border px-1.5 py-0.5 rounded-[6px] ${LICENSE_STYLES[l.riskCategory]}`}>
                        {l.riskCategory}
                      </span>
                    </td>
                    <td className="py-2.5">
                      {l.requiresReview
                        ? <span className="text-[11px] text-orange-600 font-medium">⚠ Review needed</span>
                        : <span className="text-[11px] text-green-600">✓</span>
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Supply Chain Risks */}
      <section>
        <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
          Supply Chain Risks
          {(supplyChainRisks ?? []).length > 0 && (
            <span className="ml-2 normal-case font-normal text-[#999]">
              {supplyChainRisks.length} packages flagged
            </span>
          )}
        </h3>

        {(supplyChainRisks ?? []).length === 0 ? (
          <div className="text-center py-8 bg-[#F5F7F8] rounded-2xl border border-[#D4DBE0]">
            <p className="text-3xl mb-2">✓</p>
            <p className="text-[#666] text-[13px]">No significant supply chain risks detected</p>
          </div>
        ) : (
          <div className="space-y-3">
            {supplyChainRisks.map((risk, i) => (
              <div key={i} className="bg-white border border-[#D4DBE0] rounded-2xl p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <code className="text-[14px] font-mono font-semibold text-[#111]">{risk.packageName}</code>
                      <span className={`text-[11px] font-semibold border px-1.5 py-0.5 rounded-[6px] ${RISK_STYLES[risk.riskLevel]}`}>
                        {risk.riskLevel.toUpperCase()}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {risk.signals.map((signal, j) => (
                        <span key={j} className="text-[12px] text-[#666] bg-[#F5F7F8] border border-[#D4DBE0] px-2 py-0.5 rounded-[6px]">
                          {signal}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* EPSS Enrichment */}
      {cveWithEpss.length > 0 && (
        <section>
          <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
            EPSS Exploitation Probability
          </h3>
          <div className="space-y-2">
            {cveWithEpss
              .sort((a, b) => (epssScores[b.vulnId] ?? 0) - (epssScores[a.vulnId] ?? 0))
              .map((cve, i) => {
                const epss = epssScores[cve.vulnId] ?? 0;
                const pct = (epss * 100).toFixed(2);
                return (
                  <div key={i} className="flex items-center gap-4 bg-white border border-[#D4DBE0] rounded-2xl p-3">
                    <code className="text-[12px] font-mono text-[#444] w-36 shrink-0">{cve.vulnId}</code>
                    <code className="text-[12px] font-mono text-[#666] flex-1 min-w-0 truncate">
                      {cve.packageName}@{cve.version}
                    </code>
                    <div className="flex items-center gap-2 shrink-0">
                      <div className="w-24 bg-[#E8EDF0] rounded-full h-1.5">
                        <div
                          className={`rounded-full h-1.5 ${epss > 0.1 ? 'bg-red-500' : epss > 0.01 ? 'bg-amber-500' : 'bg-green-500'}`}
                          style={{ width: `${Math.min(100, epss * 1000)}%` }}
                        />
                      </div>
                      <span className={`text-[12px] font-semibold font-mono ${epss > 0.1 ? 'text-red-600' : epss > 0.01 ? 'text-amber-600' : 'text-green-600'}`}>
                        {pct}%
                      </span>
                    </div>
                  </div>
                );
              })}
          </div>
          <p className="text-[11px] text-[#999] mt-2">EPSS = probability of exploitation in the wild in the next 30 days (FIRST.org)</p>
        </section>
      )}
    </div>
  );
}
