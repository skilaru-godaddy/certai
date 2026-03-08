import { useState } from 'react';
import type { AnalysisResult } from '../types.js';
import { MermaidDiagram } from './MermaidDiagram.js';
import { ThreatTable } from './ThreatTable.js';
import { Questionnaire } from './Questionnaire.js';

const CAT_STYLES: Record<string, { badge: string; bar: string; label: string }> = {
  'CAT 0': { badge: 'bg-red-500/20 text-red-300 border-red-500/40',     bar: 'bg-red-500',    label: 'Critical' },
  'CAT 1': { badge: 'bg-orange-500/20 text-orange-300 border-orange-500/40', bar: 'bg-orange-500', label: 'High' },
  'CAT 2': { badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40', bar: 'bg-yellow-500', label: 'Medium' },
  'CAT 3': { badge: 'bg-green-500/20 text-green-300 border-green-500/40',  bar: 'bg-green-500',  label: 'Low' },
};

const TABS = ['Overview', 'Architecture', 'Threats', 'Questionnaire', 'IRP'] as const;
type Tab = typeof TABS[number];

interface Props {
  result: AnalysisResult;
  repoUrl: string;
  onPublish: (space: string) => void;
  publishing: boolean;
}

export function ResultView({ result, repoUrl, onPublish, publishing }: Props) {
  const [activeTab, setActiveTab] = useState<Tab>('Overview');
  const [space, setSpace] = useState('SECARCH');

  const cat = CAT_STYLES[result.riskCategory] ?? CAT_STYLES['CAT 3'];
  const repoName = repoUrl.split('/').pop() ?? repoUrl;

  const highCount = result.threats.filter(t => t.impact === 'Critical' || t.impact === 'High').length;

  return (
    <div className="space-y-6">
      {/* Hero banner */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden">
        <div className="p-6">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-gray-500 text-xs font-mono truncate">{repoUrl}</span>
              </div>
              <h2 className="text-2xl font-bold text-white">{repoName}</h2>
              <p className="text-gray-400 text-sm mt-2 max-w-2xl leading-relaxed">{result.riskReasoning}</p>
            </div>
            <div className="shrink-0 text-right">
              <div className={`inline-flex items-center gap-2 border rounded-xl px-4 py-2 ${cat.badge}`}>
                <span className={`w-2 h-2 rounded-full ${cat.bar}`} />
                <span className="font-bold text-lg">{result.riskCategory}</span>
              </div>
              <p className="text-xs text-gray-600 mt-1">{cat.label} risk</p>
            </div>
          </div>
        </div>

        {/* Stats row */}
        <div className="border-t border-gray-800 grid grid-cols-3 divide-x divide-gray-800">
          <div className="px-6 py-4 text-center">
            <p className="text-2xl font-bold text-white">{result.threats.length}</p>
            <p className="text-xs text-gray-500 mt-0.5">threats found</p>
          </div>
          <div className="px-6 py-4 text-center">
            <p className={`text-2xl font-bold ${highCount > 0 ? 'text-red-400' : 'text-green-400'}`}>{highCount}</p>
            <p className="text-xs text-gray-500 mt-0.5">high / critical</p>
          </div>
          <div className="px-6 py-4 text-center">
            <p className="text-2xl font-bold text-white">{result.questionnaire.length}/29</p>
            <p className="text-xs text-gray-500 mt-0.5">questions answered</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-900/50 p-1 rounded-xl border border-gray-800">
        {TABS.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`flex-1 py-2 px-3 rounded-lg text-sm font-medium transition-all duration-150
              ${activeTab === tab
                ? 'bg-gray-800 text-white shadow-sm'
                : 'text-gray-500 hover:text-gray-300'
              }`}
          >
            {tab}
            {tab === 'Threats' && highCount > 0 && (
              <span className="ml-1.5 text-xs bg-red-500/20 text-red-400 rounded-full px-1.5 py-0.5">
                {highCount}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
        {activeTab === 'Overview' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Risk Summary</h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-950 rounded-xl p-4 border border-gray-800">
                  <p className="text-xs text-gray-500 mb-1">Risk Category</p>
                  <p className={`text-lg font-bold ${cat.badge.split(' ')[1]}`}>{result.riskCategory}</p>
                </div>
                <div className="bg-gray-950 rounded-xl p-4 border border-gray-800">
                  <p className="text-xs text-gray-500 mb-1">Critical / High Threats</p>
                  <p className={`text-lg font-bold ${highCount > 0 ? 'text-red-400' : 'text-green-400'}`}>
                    {highCount === 0 ? 'None' : highCount}
                  </p>
                </div>
              </div>
            </div>

            {result.threats.filter(t => t.impact === 'Critical' || t.impact === 'High').length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Top Threats</h3>
                <div className="space-y-2">
                  {result.threats
                    .filter(t => t.impact === 'Critical' || t.impact === 'High')
                    .map((t, i) => (
                      <div key={i} className="flex items-start gap-3 bg-gray-950 rounded-xl p-3 border border-gray-800">
                        <span className={`text-xs font-bold px-2 py-0.5 rounded-full mt-0.5 shrink-0
                          ${t.impact === 'Critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>
                          {t.impact}
                        </span>
                        <div className="min-w-0">
                          <p className="text-sm text-white font-medium">{t.component} — {t.threat}</p>
                          <p className="text-xs text-indigo-400 font-mono mt-0.5">{t.codeEvidence}</p>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'Architecture' && (
          <div>
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Architecture Diagram</h3>
            <MermaidDiagram chart={result.mermaidDiagram} />
          </div>
        )}

        {activeTab === 'Threats' && (
          <div>
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
              Threat Model
              <span className="ml-2 normal-case font-normal text-gray-600">
                {result.threats.length} items identified
              </span>
            </h3>
            <ThreatTable threats={result.threats} />
          </div>
        )}

        {activeTab === 'Questionnaire' && (
          <div>
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
              Security Questionnaire
              <span className="ml-2 normal-case font-normal text-gray-600">
                {result.questionnaire.length}/29 answered
              </span>
            </h3>
            <Questionnaire items={result.questionnaire} />
          </div>
        )}

        {activeTab === 'IRP' && (
          <div>
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Incident Response Plan (Draft)</h3>
            <pre className="text-sm text-gray-300 whitespace-pre-wrap leading-relaxed font-mono
                            bg-gray-950 border border-gray-800 rounded-xl p-5 max-h-[600px] overflow-y-auto">
              {result.irpDraft}
            </pre>
          </div>
        )}
      </div>

      {/* Publish panel */}
      <div className="bg-indigo-950/40 border border-indigo-800/60 rounded-2xl p-6">
        <div className="flex items-center justify-between gap-6 flex-wrap">
          <div>
            <h3 className="text-white font-semibold">Publish to Confluence + Jira</h3>
            <p className="text-gray-500 text-sm mt-0.5">Creates a Confluence page and links a Jira ticket in one click</p>
          </div>
          <div className="flex items-center gap-3">
            <div>
              <label className="text-xs text-gray-500 block mb-1">Space key</label>
              <input
                type="text"
                value={space}
                onChange={(e) => setSpace(e.target.value.toUpperCase())}
                className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2
                           text-white text-sm w-32 focus:outline-none focus:border-indigo-500
                           font-mono tracking-wider"
              />
            </div>
            <button
              onClick={() => onPublish(space)}
              disabled={publishing}
              className="mt-5 bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700
                         disabled:opacity-50 disabled:cursor-not-allowed
                         text-white font-semibold px-6 py-2.5 rounded-xl
                         transition-all duration-150 text-sm shadow-lg shadow-indigo-900/40
                         flex items-center gap-2"
            >
              {publishing ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Publishing...
                </>
              ) : (
                '📄 Publish'
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
