import type { ThreatItem } from '../types.js';

const IMPACT_STYLES: Record<string, string> = {
  Critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  High:     'bg-orange-500/20 text-orange-400 border-orange-500/30',
  Medium:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  Low:      'bg-green-500/20 text-green-400 border-green-500/30',
};

const LIKELIHOOD_COLOR: Record<string, string> = {
  High:   'text-red-400',
  Medium: 'text-yellow-400',
  Low:    'text-green-400',
};

interface Props {
  threats: ThreatItem[];
}

export function ThreatTable({ threats }: Props) {
  if (!threats.length) {
    return (
      <div className="text-center py-12 text-gray-600">
        <p className="text-4xl mb-2">✅</p>
        <p>No threats identified in the analyzed files.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {threats.map((t, i) => (
        <div key={i} className="bg-gray-950 border border-gray-800 rounded-xl p-4 hover:border-gray-700 transition-colors">
          <div className="flex items-start gap-3">
            <span className={`text-xs font-bold border px-2 py-0.5 rounded-full shrink-0 mt-0.5 ${IMPACT_STYLES[t.impact] ?? IMPACT_STYLES['Low']}`}>
              {t.impact}
            </span>
            <div className="flex-1 min-w-0">
              <div className="flex items-baseline gap-2 flex-wrap">
                <span className="text-white font-medium text-sm">{t.component}</span>
                <span className="text-gray-600 text-xs">·</span>
                <span className="text-gray-300 text-sm">{t.threat}</span>
              </div>
              <p className="text-gray-500 text-xs mt-1.5 leading-relaxed">{t.mitigation}</p>
              <div className="flex items-center gap-4 mt-2 flex-wrap">
                <span className={`text-xs ${LIKELIHOOD_COLOR[t.likelihood] ?? 'text-gray-500'}`}>
                  {t.likelihood} likelihood
                </span>
                {t.strideCategory && (
                  <span className="text-xs bg-purple-500/20 text-purple-300 border border-purple-500/30 px-2 py-0.5 rounded-full">
                    {t.strideCategory}
                  </span>
                )}
                {t.dreadScore !== undefined && (
                  <span className="text-xs text-gray-500">
                    DREAD: <span className={t.dreadScore >= 7 ? 'text-red-400' : t.dreadScore >= 4 ? 'text-yellow-400' : 'text-green-400'}>
                      {t.dreadScore}/10
                    </span>
                  </span>
                )}
                {t.owaspCategory && (
                  <span className="text-xs text-blue-400 font-mono">{t.owaspCategory.split('–')[0].trim()}</span>
                )}
                <code className="text-xs text-indigo-400 font-mono">{t.codeEvidence}</code>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
