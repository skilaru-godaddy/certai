import { useState } from 'react';
import type { AnalysisResult, SbomComponent } from '../types.js';
import { MermaidDiagram } from './MermaidDiagram.js';
import { ThreatTable } from './ThreatTable.js';
import { Questionnaire } from './Questionnaire.js';

const CAT_STYLES: Record<string, { badge: string; bar: string; label: string }> = {
  'CAT 0': { badge: 'bg-red-500/20 text-red-300 border-red-500/40',     bar: 'bg-red-500',    label: 'Critical' },
  'CAT 1': { badge: 'bg-orange-500/20 text-orange-300 border-orange-500/40', bar: 'bg-orange-500', label: 'High' },
  'CAT 2': { badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40', bar: 'bg-yellow-500', label: 'Medium' },
  'CAT 3': { badge: 'bg-green-500/20 text-green-300 border-green-500/40',  bar: 'bg-green-500',  label: 'Low' },
};

const TABS = ['Overview', 'Architecture', 'Threats', 'Questionnaire', 'IRP', 'Dependencies', 'AI Reasoning'] as const;
type Tab = typeof TABS[number];

interface Props {
  result: AnalysisResult;
  repoUrl: string;
  onPublish: (space: string) => void;
  publishing: boolean;
}

function downloadSbom(components: SbomComponent[], repoUrl: string) {
  const repoName = repoUrl.split('/').pop() ?? 'repo';
  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'GoDaddy', name: 'CertAI', version: '2.0' }],
      component: { type: 'application', name: repoName },
    },
    components: components.map((c) => ({
      type: 'library',
      name: c.name,
      version: c.version,
      purl: c.purl,
    })),
  };
  const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${repoName}-sbom.cdx.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function ResultView({ result, repoUrl, onPublish, publishing }: Props) {
  const [activeTab, setActiveTab] = useState<Tab>('Overview');
  const [space, setSpace] = useState('SECARCH');

  const cat = CAT_STYLES[result.riskCategory] ?? CAT_STYLES['CAT 3'];
  const repoName = repoUrl.split('/').pop() ?? repoUrl;

  const highCount = result.threats.filter(t => t.impact === 'Critical' || t.impact === 'High').length;
  const cveCount = result.cveScanResults?.length ?? 0;
  const score = result.securityScore ?? 0;

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
        <div className="border-t border-gray-800 grid grid-cols-4 divide-x divide-gray-800">
          <div className="px-6 py-4 text-center">
            <p className="text-2xl font-bold text-white">{result.threats.length}</p>
            <p className="text-xs text-gray-500 mt-0.5">threats found</p>
          </div>
          <div className="px-6 py-4 text-center">
            <p className={`text-2xl font-bold ${highCount > 0 ? 'text-red-400' : 'text-green-400'}`}>{highCount}</p>
            <p className="text-xs text-gray-500 mt-0.5">high / critical</p>
          </div>
          <div className="px-6 py-4 text-center">
            <p className={`text-2xl font-bold ${cveCount > 0 ? 'text-orange-400' : 'text-green-400'}`}>{cveCount}</p>
            <p className="text-xs text-gray-500 mt-0.5">CVEs found</p>
          </div>
          <div className="px-6 py-4 text-center">
            <p className="text-2xl font-bold text-white">{result.questionnaire.length}/29</p>
            <p className="text-xs text-gray-500 mt-0.5">questions answered</p>
          </div>
        </div>

        {/* Time saved banner */}
        <div className="border-t border-gray-800 px-6 py-3 bg-indigo-950/20 flex items-center justify-between">
          <span className="text-xs text-indigo-400">
            Manual security certification averages <strong>61 days</strong> at GoDaddy
          </span>
          <span className="text-xs text-indigo-300 font-semibold">
            CertAI completed this analysis in seconds
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-900/50 p-1 rounded-xl border border-gray-800 flex-wrap">
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
            {tab === 'Dependencies' && cveCount > 0 && (
              <span className="ml-1.5 text-xs bg-orange-500/20 text-orange-400 rounded-full px-1.5 py-0.5">
                {cveCount}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
        {activeTab === 'Overview' && (
          <div className="space-y-6">
            {/* Security Score ring */}
            <div className="flex items-center gap-6 bg-gray-950 rounded-xl p-5 border border-gray-800">
              <div className="relative w-20 h-20 shrink-0">
                <svg className="w-20 h-20 -rotate-90" viewBox="0 0 36 36">
                  <circle cx="18" cy="18" r="15.9" fill="none" stroke="#1f2937" strokeWidth="3" />
                  <circle
                    cx="18" cy="18" r="15.9" fill="none"
                    stroke={score >= 70 ? '#22c55e' : score >= 40 ? '#f59e0b' : '#ef4444'}
                    strokeWidth="3"
                    strokeDasharray={`${score} 100`}
                    strokeLinecap="round"
                  />
                </svg>
                <span className="absolute inset-0 flex items-center justify-center text-xl font-bold text-white">
                  {score}
                </span>
              </div>
              <div>
                <p className="text-white font-semibold">Security Score</p>
                <p className="text-gray-500 text-sm mt-0.5">
                  {score >= 70 ? 'Good security posture' : score >= 40 ? 'Needs improvement' : 'Critical issues require attention'}
                </p>
              </div>
            </div>

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

            {/* OWASP Top 10 breakdown */}
            {result.threats.some(t => t.owaspCategory) && (
              <div className="mt-6">
                <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">OWASP Top 10 Coverage</h4>
                <div className="space-y-1.5">
                  {Object.entries(
                    result.threats
                      .filter(t => t.owaspCategory)
                      .reduce<Record<string, number>>((acc, t) => {
                        const cat = t.owaspCategory.split('–')[0].trim();
                        acc[cat] = (acc[cat] ?? 0) + 1;
                        return acc;
                      }, {})
                  ).sort(([, a], [, b]) => b - a).map(([cat, count]) => (
                    <div key={cat} className="flex items-center gap-3">
                      <code className="text-xs text-blue-400 font-mono w-10 shrink-0">{cat}</code>
                      <div className="flex-1 bg-gray-800 rounded-full h-1.5">
                        <div
                          className="bg-blue-500 rounded-full h-1.5"
                          style={{ width: `${Math.min(100, count * 20)}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-600 w-4 text-right">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
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

        {activeTab === 'Dependencies' && (
          <div className="space-y-6">
            {/* CVE Findings */}
            <div>
              <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
                CVE Findings
                <span className="ml-2 normal-case font-normal text-gray-600">from OSV API + Dependabot</span>
              </h3>
              {(!result.cveScanResults || result.cveScanResults.length === 0) ? (
                <div className="text-center py-8 text-gray-600">
                  <p className="text-3xl mb-2">✅</p>
                  <p>No known CVEs found in parsed dependencies.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {result.cveScanResults.map((c, i) => (
                    <div key={i} className="bg-gray-950 border border-gray-800 rounded-xl p-4">
                      <div className="flex items-start gap-3">
                        <span className={`text-xs font-bold border px-2 py-0.5 rounded-full shrink-0 mt-0.5 ${
                          c.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                          c.severity === 'High' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                          c.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                          'bg-green-500/20 text-green-400 border-green-500/30'
                        }`}>{c.severity}</span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-baseline gap-2 flex-wrap">
                            <code className="text-white font-mono text-sm">{c.packageName}@{c.version}</code>
                            <span className="text-indigo-400 text-xs font-mono">{c.vulnId}</span>
                          </div>
                          <p className="text-gray-400 text-xs mt-1">{c.summary}</p>
                          {c.fixedVersion && (
                            <p className="text-green-400 text-xs mt-1">Fix: upgrade to {c.fixedVersion}</p>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Secret Findings */}
            {result.secretScanFindings && result.secretScanFindings.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-red-400 uppercase tracking-wider mb-4">
                  Potential Secrets Detected
                </h3>
                <div className="space-y-2">
                  {result.secretScanFindings.map((s, i) => (
                    <div key={i} className="bg-red-950/20 border border-red-800/40 rounded-xl p-4">
                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded-full">
                          {s.type}
                        </span>
                        <code className="text-red-300 font-mono text-xs">{s.path}:{s.line}</code>
                        <code className="text-gray-600 font-mono text-xs ml-auto">{s.preview}</code>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* SBOM Download */}
            {result.sbom && result.sbom.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
                  SBOM — {result.sbom.length} components
                </h3>
                <button
                  onClick={() => downloadSbom(result.sbom, repoUrl)}
                  className="bg-gray-800 hover:bg-gray-700 border border-gray-700 text-white text-sm
                             px-4 py-2.5 rounded-xl transition-colors flex items-center gap-2"
                >
                  Download CycloneDX JSON
                </button>
              </div>
            )}
          </div>
        )}

        {activeTab === 'AI Reasoning' && (
          <div>
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
              Claude's Extended Thinking
              <span className="ml-2 normal-case font-normal text-gray-600">
                {result.thinkingText ? `${(result.thinkingText.length / 1000).toFixed(1)}k chars` : 'Not available'}
              </span>
            </h3>
            {result.thinkingText ? (
              <pre className="text-xs text-gray-500 bg-gray-950 border border-gray-800 rounded-xl p-5
                              max-h-[600px] overflow-y-auto whitespace-pre-wrap leading-relaxed font-mono">
                {result.thinkingText}
              </pre>
            ) : (
              <p className="text-gray-600 text-sm">Thinking text was not captured for this analysis.</p>
            )}
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
