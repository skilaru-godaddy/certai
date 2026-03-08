import { useEffect, useState } from 'react';
import { streamJob, type PhaseUpdate } from '../lib/sse.js';
import type { AnalysisResult } from '../types.js';

interface Props {
  jobId: string;
  onResult: (result: AnalysisResult) => void;
}

const PHASE_LABELS: Record<string, string> = {
  discovery: '🔍 Discovering repo structure',
  fetching: '📥 Fetching security-relevant files',
  thinking: '🤔 Claude reasoning',
  generating: '✍️  Generating certification package',
  done: '✅ Analysis complete',
  error: '❌ Error',
};

export function AnalysisStream({ jobId, onResult }: Props) {
  const [phases, setPhases] = useState<PhaseUpdate[]>([]);
  const [thinkingText, setThinkingText] = useState('');
  const [currentPhase, setCurrentPhase] = useState('discovery');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const stop = streamJob(
      jobId,
      (update) => {
        setCurrentPhase(update.phase);
        if (update.phase === 'thinking') {
          setThinkingText((t) => t + update.message);
        } else if (update.phase === 'generating') {
          // accumulate silently — no need to render raw JSON tokens
        } else {
          setPhases((p) => {
            // deduplicate consecutive same-phase messages into one entry
            const last = p[p.length - 1];
            if (last?.phase === update.phase && last.message === update.message) return p;
            return [...p, update];
          });
        }
      },
      (data) => onResult(data as AnalysisResult),
      (msg) => setError(msg)
    );
    return stop;
  }, [jobId, onResult]);

  return (
    <div className="space-y-4">
      {/* Phase progress */}
      {phases.map((p, i) => (
        <div key={i} className="flex items-start gap-3 text-sm">
          <span className="text-green-400 mt-0.5">✓</span>
          <div>
            <span className="text-gray-300 font-medium">
              {PHASE_LABELS[p.phase] ?? p.phase}
            </span>
            {p.message && (
              <p className="text-gray-500 text-xs mt-0.5">{p.message}</p>
            )}
          </div>
        </div>
      ))}

      {/* Current phase spinner */}
      {currentPhase !== 'done' && !error && (
        <div className="flex items-center gap-3 text-sm text-indigo-300">
          <span className="animate-pulse">●</span>
          <span>{PHASE_LABELS[currentPhase] ?? currentPhase}...</span>
        </div>
      )}

      {/* Extended thinking preview */}
      {thinkingText && (
        <details className="mt-4">
          <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-300">
            Claude's reasoning ({thinkingText.length} chars)
          </summary>
          <pre className="mt-2 text-xs text-gray-600 bg-gray-900 p-3 rounded
                          max-h-48 overflow-y-auto whitespace-pre-wrap">
            {thinkingText}
          </pre>
        </details>
      )}

      {error && (
        <div className="text-red-400 text-sm bg-red-950 border border-red-800 p-3 rounded">
          {error}
        </div>
      )}
    </div>
  );
}
