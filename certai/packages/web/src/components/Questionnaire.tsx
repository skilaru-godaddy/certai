import { useState } from 'react';
import type { QuestionnaireItem } from '../types.js';

interface Props {
  items: QuestionnaireItem[];
}

export function Questionnaire({ items }: Props) {
  const [expanded, setExpanded] = useState<number | null>(null);

  return (
    <div className="space-y-1">
      {items.map((item) => (
        <div
          key={item.id}
          className="border border-gray-800 rounded-lg overflow-hidden"
        >
          <button
            onClick={() => setExpanded(expanded === item.id ? null : item.id)}
            className="w-full text-left px-4 py-3 flex items-center gap-3
                       hover:bg-gray-900/50 transition-colors"
          >
            <span className="text-gray-600 text-xs w-6 shrink-0">{item.id}</span>
            <span className="text-gray-300 text-sm flex-1">{item.question}</span>
            <span className="text-xs shrink-0">{expanded === item.id ? '▲' : '▼'}</span>
          </button>
          {expanded === item.id && (
            <div className="px-4 pb-4 border-t border-gray-800 pt-3 space-y-2">
              <p className="text-white text-sm">{item.answer}</p>
              {item.evidence && item.evidence !== 'N/A' && (
                <p className="text-indigo-400 font-mono text-xs">{item.evidence}</p>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
