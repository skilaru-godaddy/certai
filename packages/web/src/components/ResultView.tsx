import { useState } from 'react';
import type { AnalysisResult, SbomComponent } from '../types.js';
import { MermaidDiagram } from './MermaidDiagram.js';
import { ThreatTable } from './ThreatTable.js';
import { Questionnaire } from './Questionnaire.js';

const CAT_STYLES: Record<string, { badge: string; dot: string; label: string }> = {
  'CAT 0': { badge: 'bg-red-50 text-red-700 border border-red-200',     dot: 'bg-red-500',    label: 'Critical' },
  'CAT 1': { badge: 'bg-orange-50 text-orange-700 border border-orange-200', dot: 'bg-orange-500', label: 'High' },
  'CAT 2': { badge: 'bg-amber-50 text-amber-700 border border-amber-200',   dot: 'bg-amber-500',  label: 'Medium' },
  'CAT 3': { badge: 'bg-green-50 text-green-700 border border-green-200',   dot: 'bg-green-500',  label: 'Low' },
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
      {/* Hero banner — GoDaddy Antares card */}
      <div className="bg-white border border-[#D4DBE0] rounded-2xl overflow-hidden">
        <div className="p-6">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[#999] text-[13px] font-mono truncate">{repoUrl}</span>
              </div>
              <h2 className="text-[22px] font-bold text-[#111]">{repoName}</h2>
              <p className="text-[#444] text-[14px] mt-2 max-w-2xl leading-relaxed">{result.riskReasoning}</p>
            </div>
            <div className="shrink-0 text-right">
              <div className={`inline-flex items-center gap-2 rounded-[6px] px-3 py-1.5 text-[13px] font-semibold ${cat.badge}`}>
                <span className={`w-2 h-2 rounded-full ${cat.dot}`} />
                {result.riskCategory}
              </div>
              <p className="text-[13px] text-[#999] mt-1">{cat.label} risk</p>
            </div>
          </div>
        </div>

        {/* Stats row */}
        <div className="border-t border-[#D4DBE0] grid grid-cols-4 divide-x divide-[#D4DBE0]">
          <div className="px-6 py-4 text-center">
            <p className="text-[22px] font-bold text-[#111]">{result.threats.length}</p>
            <p className="text-[12px] text-[#666] mt-0.5">threats found</p>
          </div>
          <div className="px-6 py-4 text-center">
            <p className={`text-[22px] font-bold ${highCount > 0 ? 'text-red-600' : 'text-green-600'}`}>{highCount}</p>
            <p className="text-[12px] text-[#666] mt-0.5">high / critical</p>
          </div>
          <div className="px-6 py-4 text-center">
            <p className={`text-[22px] font-bold ${cveCount > 0 ? 'text-orange-600' : 'text-green-600'}`}>{cveCount}</p>
            <p className="text-[12px] text-[#666] mt-0.5">CVEs found</p>
          </div>
          <div className="px-6 py-4 text-center">
            <p className="text-[22px] font-bold text-[#111]">{result.questionnaire.length}/29</p>
            <p className="text-[12px] text-[#666] mt-0.5">questions answered</p>
          </div>
        </div>

        {/* Time saved banner */}
        <div className="border-t border-[#D4DBE0] px-6 py-3 bg-[#F5F7F8] flex items-center justify-between">
          <span className="text-[13px] text-[#444]">
            Manual security certification averages <strong>61 days</strong> at GoDaddy
          </span>
          <span className="text-[13px] text-[#111] font-semibold">
            CertAI completed this analysis in seconds
          </span>
        </div>
      </div>

      {/* Pivot tabs — GoDaddy Antares style */}
      <div className="border-b border-[#D4DBE0] flex">
        {TABS.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-3 text-[14px] font-medium transition-colors border-b-2 -mb-[2px] flex items-center gap-1.5
              ${activeTab === tab
                ? 'text-[#111] border-[#111]'
                : 'text-[#666] border-transparent hover:text-[#111] hover:border-[#D4DBE0]'
              }`}
          >
            {tab}
            {tab === 'Threats' && highCount > 0 && (
              <span className="text-[11px] bg-red-100 text-red-700 rounded-[6px] px-1.5 py-0.5 font-semibold">
                {highCount}
              </span>
            )}
            {tab === 'Dependencies' && cveCount > 0 && (
              <span className="text-[11px] bg-orange-100 text-orange-700 rounded-[6px] px-1.5 py-0.5 font-semibold">
                {cveCount}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content — GoDaddy Antares card */}
      <div className="bg-white border border-[#D4DBE0] rounded-2xl p-6">
        {activeTab === 'Overview' && (
          <div className="space-y-6">
            {/* Security Score ring */}
            <div className="flex items-center gap-6 bg-[#F5F7F8] rounded-2xl p-5 border border-[#D4DBE0]">
              <div className="relative w-20 h-20 shrink-0">
                <svg className="w-20 h-20 -rotate-90" viewBox="0 0 36 36">
                  <circle cx="18" cy="18" r="15.9" fill="none" stroke="#E8EDF0" strokeWidth="3" />
                  <circle
                    cx="18" cy="18" r="15.9" fill="none"
                    stroke={score >= 70 ? '#16a34a' : score >= 40 ? '#d97706' : '#dc2626'}
                    strokeWidth="3"
                    strokeDasharray={`${score} 100`}
                    strokeLinecap="round"
                  />
                </svg>
                <span className="absolute inset-0 flex items-center justify-center text-[18px] font-bold text-[#111]">
                  {score}
                </span>
              </div>
              <div>
                <p className="text-[#111] font-semibold text-[15px]">Security Score</p>
                <p className="text-[#666] text-[14px] mt-0.5">
                  {score >= 70 ? 'Good security posture' : score >= 40 ? 'Needs improvement' : 'Critical issues require attention'}
                </p>
              </div>
            </div>

            <div>
              <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">Risk Summary</h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[#F5F7F8] rounded-2xl p-4 border border-[#D4DBE0]">
                  <p className="text-[12px] text-[#666] mb-1">Risk Category</p>
                  <p className="text-[16px] font-bold text-[#111]">{result.riskCategory}</p>
                </div>
                <div className="bg-[#F5F7F8] rounded-2xl p-4 border border-[#D4DBE0]">
                  <p className="text-[12px] text-[#666] mb-1">Critical / High Threats</p>
                  <p className={`text-[16px] font-bold ${highCount > 0 ? 'text-red-600' : 'text-green-600'}`}>
                    {highCount === 0 ? 'None' : highCount}
                  </p>
                </div>
              </div>
            </div>

            {result.threats.filter(t => t.impact === 'Critical' || t.impact === 'High').length > 0 && (
              <div>
                <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-3">Top Threats</h3>
                <div className="space-y-2">
                  {result.threats
                    .filter(t => t.impact === 'Critical' || t.impact === 'High')
                    .map((t, i) => (
                      <div key={i} className="flex items-start gap-3 bg-[#F5F7F8] rounded-2xl p-3 border border-[#D4DBE0]">
                        <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-[6px] mt-0.5 shrink-0
                          ${t.impact === 'Critical' ? 'bg-red-50 text-red-700 border border-red-200' : 'bg-orange-50 text-orange-700 border border-orange-200'}`}>
                          {t.impact}
                        </span>
                        <div className="min-w-0">
                          <p className="text-[14px] text-[#111] font-medium">{t.component} — {t.threat}</p>
                          <p className="text-[12px] text-[#666] font-mono mt-0.5">{t.codeEvidence}</p>
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
            <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">Architecture Diagram</h3>
            <MermaidDiagram chart={result.mermaidDiagram} />
          </div>
        )}

        {activeTab === 'Threats' && (
          <div>
            <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
              Threat Model
              <span className="ml-2 normal-case font-normal text-[#999]">
                {result.threats.length} items identified
              </span>
            </h3>
            <ThreatTable threats={result.threats} />

            {/* OWASP Top 10 breakdown */}
            {result.threats.some(t => t.owaspCategory) && (
              <div className="mt-6">
                <h4 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-3">OWASP Top 10 Coverage</h4>
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
                      <code className="text-[12px] text-[#444] font-mono w-10 shrink-0">{cat}</code>
                      <div className="flex-1 bg-[#E8EDF0] rounded-full h-1.5">
                        <div
                          className="bg-[#111] rounded-full h-1.5"
                          style={{ width: `${Math.min(100, count * 20)}%` }}
                        />
                      </div>
                      <span className="text-[12px] text-[#666] w-4 text-right">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'Questionnaire' && (
          <div>
            <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
              Security Questionnaire
              <span className="ml-2 normal-case font-normal text-[#999]">
                {result.questionnaire.length}/29 answered
              </span>
            </h3>
            <Questionnaire items={result.questionnaire} />
          </div>
        )}

        {activeTab === 'IRP' && (
          <div>
            <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">Incident Response Plan (Draft)</h3>
            <pre className="text-[13px] text-[#444] whitespace-pre-wrap leading-relaxed font-mono
                            bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl p-5 max-h-[600px] overflow-y-auto">
              {result.irpDraft}
            </pre>
          </div>
        )}

        {activeTab === 'Dependencies' && (
          <div className="space-y-6">
            {/* CVE Findings */}
            <div>
              <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
                CVE Findings
                <span className="ml-2 normal-case font-normal text-[#999]">from OSV API + Dependabot</span>
              </h3>
              {(!result.cveScanResults || result.cveScanResults.length === 0) ? (
                <div className="text-center py-8 bg-[#F5F7F8] rounded-2xl border border-[#D4DBE0]">
                  <p className="text-3xl mb-2">✓</p>
                  <p className="text-[#666] text-[14px]">No known CVEs found in parsed dependencies.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {result.cveScanResults.map((c, i) => (
                    <div key={i} className="bg-white border border-[#D4DBE0] rounded-2xl p-4">
                      <div className="flex items-start gap-3">
                        <span className={`text-[11px] font-semibold border px-2 py-0.5 rounded-[6px] shrink-0 mt-0.5 ${
                          c.severity === 'Critical' ? 'bg-red-50 text-red-700 border-red-200' :
                          c.severity === 'High' ? 'bg-orange-50 text-orange-700 border-orange-200' :
                          c.severity === 'Medium' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                          'bg-green-50 text-green-700 border-green-200'
                        }`}>{c.severity}</span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-baseline gap-2 flex-wrap">
                            <code className="text-[#111] font-mono text-[14px]">{c.packageName}@{c.version}</code>
                            <span className="text-[#444] text-[12px] font-mono">{c.vulnId}</span>
                          </div>
                          <p className="text-[#666] text-[13px] mt-1">{c.summary}</p>
                          {c.fixedVersion && (
                            <p className="text-green-600 text-[13px] mt-1">Fix: upgrade to {c.fixedVersion}</p>
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
                <h3 className="text-[11px] font-semibold text-red-600 uppercase tracking-wider mb-4">
                  Potential Secrets Detected
                </h3>
                <div className="space-y-2">
                  {result.secretScanFindings.map((s, i) => (
                    <div key={i} className="bg-red-50 border border-red-200 rounded-2xl p-4">
                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="text-[11px] font-semibold bg-red-100 text-red-700 border border-red-200 px-2 py-0.5 rounded-[6px]">
                          {s.type}
                        </span>
                        <code className="text-red-700 font-mono text-[12px]">{s.path}:{s.line}</code>
                        <code className="text-[#666] font-mono text-[12px] ml-auto">{s.preview}</code>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* SBOM Download */}
            {result.sbom && result.sbom.length > 0 && (
              <div>
                <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
                  SBOM — {result.sbom.length} components
                </h3>
                <button
                  onClick={() => downloadSbom(result.sbom, repoUrl)}
                  className="bg-white hover:bg-[#F5F7F8] border border-[#D6D6D6] text-[#111] text-[14px]
                             px-4 py-2 rounded-[6px] transition-colors flex items-center gap-2"
                >
                  Download CycloneDX JSON
                </button>
              </div>
            )}
          </div>
        )}

        {activeTab === 'AI Reasoning' && (
          <div>
            <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
              Claude's Extended Thinking
              <span className="ml-2 normal-case font-normal text-[#999]">
                {result.thinkingText ? `${(result.thinkingText.length / 1000).toFixed(1)}k chars` : 'Not available'}
              </span>
            </h3>
            {result.thinkingText ? (
              <pre className="text-[12px] text-[#444] bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl p-5
                              max-h-[600px] overflow-y-auto whitespace-pre-wrap leading-relaxed font-mono">
                {result.thinkingText}
              </pre>
            ) : (
              <p className="text-[#666] text-[14px]">Thinking text was not captured for this analysis.</p>
            )}
          </div>
        )}
      </div>

      {/* Publish panel */}
      <div className="bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl p-6">
        <div className="flex items-center justify-between gap-6 flex-wrap">
          <div>
            <h3 className="text-[#111] font-semibold text-[15px]">Publish to Confluence + Jira</h3>
            <p className="text-[#666] text-[13px] mt-0.5">Creates a Confluence page and links a Jira ticket in one click</p>
          </div>
          <div className="flex items-center gap-3">
            <div>
              <label className="text-[12px] text-[#666] block mb-1">Space key</label>
              <input
                type="text"
                value={space}
                onChange={(e) => setSpace(e.target.value.toUpperCase())}
                className="bg-white border border-[#D6D6D6] rounded-[6px] px-3 py-2
                           text-[#111] text-[14px] w-32 focus:outline-none focus:border-[#111]
                           font-mono tracking-wider"
              />
            </div>
            <button
              onClick={() => onPublish(space)}
              disabled={publishing}
              className="mt-5 bg-[#111] hover:bg-[#333] active:bg-[#000]
                         disabled:opacity-40 disabled:cursor-not-allowed
                         text-white font-medium px-6 py-2.5 rounded-[6px]
                         transition-all duration-150 text-[14px]
                         flex items-center gap-2"
            >
              {publishing ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin" />
                  Publishing...
                </>
              ) : (
                'Publish'
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
