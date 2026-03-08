import type { ThreatItem } from '../types.js';

const IMPACT_STYLES: Record<string, string> = {
  Critical: 'bg-red-50 text-red-700 border border-red-200',
  High:     'bg-orange-50 text-orange-700 border border-orange-200',
  Medium:   'bg-amber-50 text-amber-700 border border-amber-200',
  Low:      'bg-green-50 text-green-700 border border-green-200',
};

const LIKELIHOOD_COLOR: Record<string, string> = {
  High:   'text-red-600',
  Medium: 'text-amber-600',
  Low:    'text-green-600',
};

interface Props {
  threats: ThreatItem[];
}

export function ThreatTable({ threats }: Props) {
  if (!threats.length) {
    return (
      <div className="text-center py-12 bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl">
        <p className="text-3xl mb-2">✓</p>
        <p className="text-[#666] text-[14px]">No threats identified in the analyzed files.</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {threats.map((t, i) => (
        <div key={i} className="bg-white border border-[#D4DBE0] rounded-2xl p-4 hover:border-[#999] transition-colors">
          <div className="flex items-start gap-3">
            <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-[6px] shrink-0 mt-0.5 ${IMPACT_STYLES[t.impact] ?? IMPACT_STYLES['Low']}`}>
              {t.impact}
            </span>
            <div className="flex-1 min-w-0">
              <div className="flex items-baseline gap-2 flex-wrap">
                <span className="text-[#111] font-medium text-[14px]">{t.component}</span>
                <span className="text-[#D4DBE0] text-[12px]">·</span>
                <span className="text-[#444] text-[14px]">{t.threat}</span>
              </div>
              <p className="text-[#666] text-[13px] mt-1.5 leading-relaxed">{t.mitigation}</p>
              <div className="flex items-center gap-4 mt-2 flex-wrap">
                <span className={`text-[12px] ${LIKELIHOOD_COLOR[t.likelihood] ?? 'text-[#666]'}`}>
                  {t.likelihood} likelihood
                </span>
                {t.strideCategory && (
                  <span className="text-[11px] bg-purple-50 text-purple-700 border border-purple-200 px-2 py-0.5 rounded-[6px]">
                    {t.strideCategory}
                  </span>
                )}
                {t.dreadScore !== undefined && (
                  <span className="text-[12px] text-[#666]">
                    DREAD: <span className={t.dreadScore >= 7 ? 'text-red-600' : t.dreadScore >= 4 ? 'text-amber-600' : 'text-green-600'}>
                      {t.dreadScore}/10
                    </span>
                  </span>
                )}
                {t.owaspCategory && (
                  <span className="text-[12px] text-[#444] font-mono">{t.owaspCategory.split('–')[0].trim()}</span>
                )}
                <code className="text-[12px] text-[#444] font-mono">{t.codeEvidence}</code>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
