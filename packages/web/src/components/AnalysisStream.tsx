import { useEffect, useState } from 'react';
import { streamJob, type PhaseUpdate } from '../lib/sse.js';
import type { AnalysisResult } from '../types.js';

interface Props {
  jobId: string;
  onResult: (result: AnalysisResult) => void;
}

const PHASES = ['discovery', 'fetching', 'thinking', 'generating', 'done'] as const;

const PHASE_META: Record<string, { label: string; desc: string }> = {
  discovery:  { label: 'Discovering repo',  desc: 'Reading file tree and structure' },
  fetching:   { label: 'Fetching files',    desc: 'Loading security-relevant files' },
  thinking:   { label: 'Claude reasoning',  desc: 'Extended thinking in progress' },
  generating: { label: 'Generating package', desc: 'Building cert package' },
  done:       { label: 'Complete',           desc: 'Analysis finished' },
};

type PhaseKey = 'discovery' | 'fetching' | 'thinking' | 'generating' | 'done';

function phaseIndex(p: string): number {
  return PHASES.indexOf(p as PhaseKey);
}

export function AnalysisStream({ jobId, onResult }: Props) {
  const [currentPhase, setCurrentPhase] = useState<string>('discovery');
  const [phaseMessages, setPhaseMessages] = useState<Partial<Record<string, string>>>({});
  const [thinkingText, setThinkingText] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const stop = streamJob(
      jobId,
      (update: PhaseUpdate) => {
        setCurrentPhase(update.phase);
        if (update.phase === 'thinking') {
          setThinkingText((t) => t + update.message);
        } else if (update.phase !== 'generating') {
          setPhaseMessages((m) => ({ ...m, [update.phase]: update.message }));
        }
      },
      (data) => {
        setCurrentPhase('done');
        onResult(data as AnalysisResult);
      },
      (msg) => setError(msg)
    );
    return stop;
  }, [jobId, onResult]);

  const currentIdx = phaseIndex(currentPhase);

  return (
    <div className="space-y-6">
      {/* Step tracker */}
      <div className="space-y-3">
        {PHASES.filter(p => p !== 'done').map((phase, idx) => {
          const meta = PHASE_META[phase];
          const isDone = idx < currentIdx;
          const isActive = phase === currentPhase;
          const isPending = idx > currentIdx;

          return (
            <div key={phase} className={`flex items-start gap-4 transition-opacity duration-300 ${isPending ? 'opacity-30' : 'opacity-100'}`}>
              {/* Step indicator */}
              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-[13px] shrink-0 mt-0.5 border
                ${isDone ? 'bg-green-50 border-green-300 text-green-600' :
                  isActive ? 'bg-[#111] border-[#111] text-white' :
                  'bg-[#F5F7F8] border-[#D4DBE0] text-[#999]'}`}>
                {isDone ? '✓' : isActive ? (
                  <span className="w-3.5 h-3.5 border-2 border-white/40 border-t-white rounded-full animate-spin block" />
                ) : <span className="text-[11px]">{idx + 1}</span>}
              </div>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`text-[14px] font-medium ${isDone ? 'text-green-600' : isActive ? 'text-[#111]' : 'text-[#666]'}`}>
                    {meta.label}
                  </span>
                  {isActive && (
                    <span className="text-[12px] text-[#666] animate-pulse">in progress...</span>
                  )}
                </div>
                {(isDone || isActive) && phaseMessages[phase] && (
                  <p className="text-[12px] text-[#999] mt-0.5 truncate">{phaseMessages[phase]}</p>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Extended thinking accordion */}
      {thinkingText && (
        <details className="group">
          <summary className="flex items-center gap-2 cursor-pointer text-[13px] text-[#666] hover:text-[#111] transition-colors list-none">
            <span className="group-open:rotate-90 transition-transform">▶</span>
            Claude's reasoning
            <span className="ml-auto text-[#999]">{(thinkingText.length / 1000).toFixed(1)}k chars</span>
          </summary>
          <pre className="mt-3 text-[12px] text-[#444] bg-[#F5F7F8] border border-[#D4DBE0] p-4 rounded-2xl
                          max-h-56 overflow-y-auto whitespace-pre-wrap leading-relaxed">
            {thinkingText}
          </pre>
        </details>
      )}

      {error && (
        <div className="flex items-start gap-3 bg-red-50 border border-red-200 p-4 rounded-2xl text-[14px] text-red-700">
          <span>⚠</span>
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}
