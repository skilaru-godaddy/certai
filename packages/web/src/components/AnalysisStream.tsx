import { useEffect, useState } from 'react';
import { streamJob, type PhaseUpdate } from '../lib/sse.js';
import type { AnalysisResult } from '../types.js';

interface Props {
  jobId: string;
  onResult: (result: AnalysisResult) => void;
}

const PHASES = ['discovery', 'fetching', 'thinking', 'generating', 'done'] as const;

const PHASE_META: Record<string, { label: string; icon: string; desc: string }> = {
  discovery:  { label: 'Discovering repo',       icon: '🔍', desc: 'Reading file tree and structure' },
  fetching:   { label: 'Fetching files',          icon: '📥', desc: 'Loading security-relevant files' },
  thinking:   { label: 'Claude reasoning',        icon: '🧠', desc: 'Extended thinking in progress' },
  generating: { label: 'Generating package',      icon: '✍️',  desc: 'Building cert package' },
  done:       { label: 'Complete',                icon: '✅', desc: 'Analysis finished' },
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
              {/* Icon */}
              <div className={`w-9 h-9 rounded-full flex items-center justify-center text-sm shrink-0 mt-0.5
                ${isDone ? 'bg-green-900/60 border border-green-700' :
                  isActive ? 'bg-indigo-900/60 border border-indigo-500' :
                  'bg-gray-800 border border-gray-700'}`}>
                {isDone ? '✓' : isActive ? (
                  <span className="w-4 h-4 border-2 border-indigo-400/40 border-t-indigo-400 rounded-full animate-spin block" />
                ) : <span className="text-xs text-gray-600">{idx + 1}</span>}
              </div>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`text-sm font-medium ${isDone ? 'text-green-400' : isActive ? 'text-white' : 'text-gray-600'}`}>
                    {meta.icon} {meta.label}
                  </span>
                  {isActive && (
                    <span className="text-xs text-indigo-400 animate-pulse">in progress...</span>
                  )}
                </div>
                {(isDone || isActive) && phaseMessages[phase] && (
                  <p className="text-xs text-gray-500 mt-0.5 truncate">{phaseMessages[phase]}</p>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Extended thinking accordion */}
      {thinkingText && (
        <details className="group">
          <summary className="flex items-center gap-2 cursor-pointer text-xs text-gray-500 hover:text-gray-300 transition-colors list-none">
            <span className="group-open:rotate-90 transition-transform">▶</span>
            Claude's reasoning
            <span className="ml-auto text-gray-700">{(thinkingText.length / 1000).toFixed(1)}k chars</span>
          </summary>
          <pre className="mt-3 text-xs text-gray-600 bg-gray-950 border border-gray-800 p-4 rounded-xl
                          max-h-56 overflow-y-auto whitespace-pre-wrap leading-relaxed">
            {thinkingText}
          </pre>
        </details>
      )}

      {error && (
        <div className="flex items-start gap-3 bg-red-950/50 border border-red-800 p-4 rounded-xl text-sm text-red-300">
          <span>⚠️</span>
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}
