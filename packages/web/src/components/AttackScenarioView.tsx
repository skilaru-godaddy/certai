import { useState } from 'react';
import type { AttackScenario, ThreatItem } from '../types.js';

const SEVERITY_STYLES: Record<string, { bg: string; border: string; text: string; dot: string }> = {
  Critical: { bg: 'bg-red-50', border: 'border-red-200', text: 'text-red-700', dot: 'bg-red-500' },
  High:     { bg: 'bg-orange-50', border: 'border-orange-200', text: 'text-orange-700', dot: 'bg-orange-500' },
  Medium:   { bg: 'bg-amber-50', border: 'border-amber-200', text: 'text-amber-700', dot: 'bg-amber-500' },
};

interface Props {
  scenarios: AttackScenario[];
  threats: ThreatItem[];
}

export function AttackScenarioView({ scenarios, threats }: Props) {
  const [expanded, setExpanded] = useState<number | null>(0);

  if (!scenarios.length) {
    return (
      <div className="text-center py-12 bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl">
        <p className="text-3xl mb-2">🛡</p>
        <p className="text-[#666] text-[14px]">No attack scenarios generated for this repository.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {scenarios.map((scenario, si) => {
        const sev = SEVERITY_STYLES[scenario.severity] ?? SEVERITY_STYLES['Medium'];
        const isOpen = expanded === si;

        return (
          <div key={si} className="bg-white border border-[#D4DBE0] rounded-2xl overflow-hidden hover:border-[#999] transition-colors">
            {/* Scenario header */}
            <button
              onClick={() => setExpanded(isOpen ? null : si)}
              className="w-full text-left px-5 py-4 flex items-start gap-3"
            >
              <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-[6px] border shrink-0 mt-0.5 ${sev.bg} ${sev.text} ${sev.border}`}>
                {scenario.severity}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-[15px] font-semibold text-[#111]">{scenario.name}</p>
                <p className="text-[13px] text-[#666] mt-0.5">{scenario.objective}</p>
                <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                  <span className="text-[12px] text-[#999]">
                    Entry: <span className="text-[#444] font-mono">{scenario.entryPoint}</span>
                  </span>
                  <span className="text-[12px] text-[#999]">
                    {scenario.chain.length} steps
                  </span>
                </div>
              </div>
              <span className={`text-[#999] transition-transform duration-150 shrink-0 mt-1 ${isOpen ? 'rotate-90' : ''}`}>▶</span>
            </button>

            {/* Expanded chain */}
            {isOpen && (
              <div className="border-t border-[#D4DBE0] px-5 py-4 space-y-5">
                {/* Kill chain visualization */}
                <div className="relative">
                  {scenario.chain.map((step, ci) => (
                    <div key={ci} className="flex gap-4 relative">
                      {/* Vertical connector */}
                      <div className="flex flex-col items-center shrink-0 w-8">
                        <div className={`w-7 h-7 rounded-full flex items-center justify-center text-[12px] font-bold text-white ${sev.dot} z-10`}>
                          {step.step}
                        </div>
                        {ci < scenario.chain.length - 1 && (
                          <div className="w-0.5 flex-1 bg-[#D4DBE0] min-h-[20px]" />
                        )}
                      </div>

                      {/* Step content */}
                      <div className="flex-1 pb-4 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-[13px] font-semibold text-[#111]">{step.technique}</span>
                          <span className="text-[11px] bg-blue-50 text-blue-700 border border-blue-200 px-1.5 py-0.5 rounded-[6px] font-mono">
                            {step.techniqueId}
                          </span>
                        </div>
                        <p className="text-[13px] text-[#444] mt-1 leading-relaxed">{step.action}</p>

                        <div className="flex items-start gap-4 mt-2 flex-wrap">
                          <div className="text-[12px]">
                            <span className="text-[#999]">Target:</span>{' '}
                            <code className="text-[#444] font-mono bg-[#F5F7F8] px-1.5 py-0.5 rounded">{step.targetComponent}</code>
                          </div>
                          <div className="text-[12px]">
                            <span className="text-[#999]">Impact:</span>{' '}
                            <span className="text-[#444]">{step.impact}</span>
                          </div>
                        </div>

                        {step.preconditions.length > 0 && (
                          <div className="mt-1.5 flex items-start gap-1.5 flex-wrap">
                            <span className="text-[11px] text-[#999] shrink-0 mt-0.5">Requires:</span>
                            {step.preconditions.map((p, pi) => (
                              <span key={pi} className="text-[11px] bg-[#F5F7F8] text-[#666] border border-[#D4DBE0] px-1.5 py-0.5 rounded-[6px]">
                                {p}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Blast radius */}
                <div className="bg-red-50/50 border border-red-200 rounded-xl p-4">
                  <p className="text-[11px] font-semibold text-red-600 uppercase tracking-wider mb-1">Blast Radius</p>
                  <p className="text-[13px] text-[#444] leading-relaxed">{scenario.blastRadius}</p>
                </div>

                {/* Linked threats */}
                {scenario.linkedThreatIndices.length > 0 && (
                  <div>
                    <p className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-2">Linked Threats</p>
                    <div className="space-y-1.5">
                      {scenario.linkedThreatIndices.map((idx) => {
                        const t = threats[idx];
                        if (!t) return null;
                        return (
                          <div key={idx} className="flex items-center gap-2 text-[13px]">
                            <span className={`text-[11px] font-semibold border px-1.5 py-0.5 rounded-[6px] shrink-0 ${
                              t.impact === 'Critical' ? 'bg-red-50 text-red-700 border-red-200' :
                              t.impact === 'High' ? 'bg-orange-50 text-orange-700 border-orange-200' :
                              'bg-amber-50 text-amber-700 border-amber-200'
                            }`}>{t.impact}</span>
                            <span className="text-[#111] font-medium">{t.component}</span>
                            <span className="text-[#D4DBE0]">·</span>
                            <span className="text-[#444] truncate">{t.threat}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
