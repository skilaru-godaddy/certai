import { useState } from 'react';
import type { QuestionnaireItem } from '../types.js';

interface Props {
  items: QuestionnaireItem[];
}

export function Questionnaire({ items }: Props) {
  const [expanded, setExpanded] = useState<number | null>(null);

  return (
    <div className="space-y-1.5">
      {items.map((item) => {
        const isOpen = expanded === item.id;
        return (
          <div
            key={item.id}
            className={`border rounded-xl overflow-hidden transition-colors
              ${isOpen ? 'border-indigo-800/60 bg-indigo-950/20' : 'border-gray-800 bg-gray-950 hover:border-gray-700'}`}
          >
            <button
              onClick={() => setExpanded(isOpen ? null : item.id)}
              className="w-full text-left px-4 py-3 flex items-center gap-3"
            >
              <span className={`text-xs font-mono w-7 shrink-0 text-right
                ${isOpen ? 'text-indigo-400' : 'text-gray-600'}`}>
                {item.id.toString().padStart(2, '0')}
              </span>
              <span className={`text-sm flex-1 ${isOpen ? 'text-white' : 'text-gray-300'}`}>
                {item.question}
              </span>
              {item.confidence && (
                <span className={`text-xs px-2 py-0.5 rounded-full border shrink-0 mr-1 ${
                  item.confidence === 'Confirmed'
                    ? 'bg-green-500/10 text-green-400 border-green-500/30'
                    : item.confidence === 'Inferred'
                    ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                    : 'bg-red-500/10 text-red-300 border-red-500/30'
                }`}>
                  {item.confidence === 'Confirmed' ? '✓ Confirmed' :
                   item.confidence === 'Inferred' ? '~ Inferred' :
                   '? Verify'}
                </span>
              )}
              <span className={`text-xs transition-transform duration-150 shrink-0
                ${isOpen ? 'rotate-180 text-indigo-400' : 'text-gray-600'}`}>
                ▼
              </span>
            </button>
            {isOpen && (
              <div className="px-4 pb-4 border-t border-indigo-800/30 pt-3 space-y-2 ml-10">
                <p className="text-white text-sm leading-relaxed">{item.answer}</p>
                {item.evidence && item.evidence !== 'N/A' && (
                  <code className="block text-indigo-400 font-mono text-xs bg-indigo-950/40 px-3 py-1.5 rounded-lg">
                    {item.evidence}
                  </code>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
