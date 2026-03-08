import { useState } from 'react';
import type { AnalysisResult } from '../types.js';
import { MermaidDiagram } from './MermaidDiagram.js';
import { ThreatTable } from './ThreatTable.js';
import { Questionnaire } from './Questionnaire.js';

const CAT_COLOR: Record<string, string> = {
  'CAT 0': 'bg-red-900 text-red-300 border-red-700',
  'CAT 1': 'bg-orange-900 text-orange-300 border-orange-700',
  'CAT 2': 'bg-yellow-900 text-yellow-300 border-yellow-700',
  'CAT 3': 'bg-green-900 text-green-300 border-green-700',
};

interface Props {
  result: AnalysisResult;
  repoUrl: string;
  onPublish: (space: string) => void;
  publishing: boolean;
}

export function ResultView({ result, repoUrl, onPublish, publishing }: Props) {
  const [space, setSpace] = useState('SECARCH');

  return (
    <div className="space-y-10">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">{repoUrl.split('/').pop()}</h2>
          <p className="text-gray-500 text-sm mt-1">{repoUrl}</p>
        </div>
        <span className={`border px-3 py-1 rounded-full text-sm font-bold ${CAT_COLOR[result.riskCategory] ?? 'bg-gray-800 text-gray-300 border-gray-700'}`}>
          {result.riskCategory}
        </span>
      </div>

      <p className="text-gray-400 text-sm bg-gray-900 p-4 rounded-lg border border-gray-800">
        {result.riskReasoning}
      </p>

      {/* Architecture diagram */}
      <section>
        <h3 className="text-lg font-semibold text-white mb-4">Architecture Diagram</h3>
        <MermaidDiagram chart={result.mermaidDiagram} />
      </section>

      {/* Threat model */}
      <section>
        <h3 className="text-lg font-semibold text-white mb-4">
          Threat Model
          <span className="ml-2 text-sm font-normal text-gray-500">
            ({result.threats.length} items)
          </span>
        </h3>
        <ThreatTable threats={result.threats} />
      </section>

      {/* Questionnaire */}
      <section>
        <h3 className="text-lg font-semibold text-white mb-4">
          Security Questionnaire
          <span className="ml-2 text-sm font-normal text-gray-500">
            ({result.questionnaire.length}/29 answered)
          </span>
        </h3>
        <Questionnaire items={result.questionnaire} />
      </section>

      {/* IRP */}
      <section>
        <h3 className="text-lg font-semibold text-white mb-4">Incident Response Plan (Draft)</h3>
        <pre className="bg-gray-900 p-4 rounded-lg text-sm text-gray-300
                        whitespace-pre-wrap border border-gray-800">
          {result.irpDraft}
        </pre>
      </section>

      {/* Publish panel */}
      <section className="border border-indigo-800 bg-indigo-950/30 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Publish</h3>
        <div className="flex gap-3 items-center">
          <div>
            <label className="text-xs text-gray-500 block mb-1">Confluence Space Key</label>
            <input
              type="text"
              value={space}
              onChange={(e) => setSpace(e.target.value.toUpperCase())}
              className="bg-gray-900 border border-gray-700 rounded px-3 py-2
                         text-white text-sm w-36 focus:outline-none focus:border-indigo-500"
            />
          </div>
          <button
            onClick={() => onPublish(space)}
            disabled={publishing}
            className="mt-5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50
                       text-white font-semibold px-5 py-2 rounded-lg transition-colors text-sm"
          >
            {publishing ? 'Publishing...' : '📄 Publish to Confluence + Jira'}
          </button>
        </div>
      </section>
    </div>
  );
}
