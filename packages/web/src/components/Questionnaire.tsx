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
            className={`border rounded-2xl overflow-hidden transition-colors
              ${isOpen ? 'border-[#111] bg-[#F5F7F8]' : 'border-[#D4DBE0] bg-white hover:border-[#999]'}`}
          >
            <button
              onClick={() => setExpanded(isOpen ? null : item.id)}
              className="w-full text-left px-4 py-3 flex items-center gap-3"
            >
              <span className={`text-[12px] font-mono w-7 shrink-0 text-right
                ${isOpen ? 'text-[#111]' : 'text-[#999]'}`}>
                {item.id.toString().padStart(2, '0')}
              </span>
              <span className={`text-[14px] flex-1 ${isOpen ? 'text-[#111]' : 'text-[#444]'}`}>
                {item.question}
              </span>
              {item.confidence && (
                <span className={`text-[11px] px-2 py-0.5 rounded-[6px] border shrink-0 mr-1 font-medium ${
                  item.confidence === 'Confirmed'
                    ? 'bg-green-50 text-green-700 border-green-200'
                    : item.confidence === 'Inferred'
                    ? 'bg-amber-50 text-amber-700 border-amber-200'
                    : 'bg-red-50 text-red-700 border-red-200'
                }`}>
                  {item.confidence === 'Confirmed' ? '✓ Confirmed' :
                   item.confidence === 'Inferred' ? '~ Inferred' :
                   '? Verify'}
                </span>
              )}
              <span className={`text-[12px] transition-transform duration-150 shrink-0
                ${isOpen ? 'rotate-180 text-[#111]' : 'text-[#999]'}`}>
                ▼
              </span>
            </button>
            {isOpen && (
              <div className="px-4 pb-4 border-t border-[#D4DBE0] pt-3 space-y-2 ml-10">
                <p className="text-[#111] text-[14px] leading-relaxed">{item.answer}</p>
                {item.evidence && item.evidence !== 'N/A' && (
                  <code className="block text-[#444] font-mono text-[12px] bg-white border border-[#D4DBE0] px-3 py-1.5 rounded-[6px]">
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
