import { useState, useEffect } from 'react';
import type { AnalysisResult, SbomComponent } from '../types.js';
import { MermaidDiagram } from './MermaidDiagram.js';
import { ThreatTable } from './ThreatTable.js';
import { Questionnaire } from './Questionnaire.js';
import { GodaddyTemplateView } from './GodaddyTemplateView.js';
import { IacScanView } from './IacScanView.js';
import { ComplianceView } from './ComplianceView.js';
import { SupplyChainView } from './SupplyChainView.js';
import { MissingItemsChecklist } from './MissingItemsChecklist.js';
import { AttackScenarioView } from './AttackScenarioView.js';

const CAT_STYLES: Record<string, { badge: string; dot: string; label: string }> = {
  'CAT 0': { badge: 'bg-red-50 text-red-700 border border-red-200',     dot: 'bg-red-500',    label: 'Critical' },
  'CAT 1': { badge: 'bg-orange-50 text-orange-700 border border-orange-200', dot: 'bg-orange-500', label: 'High' },
  'CAT 2': { badge: 'bg-amber-50 text-amber-700 border border-amber-200',   dot: 'bg-amber-500',  label: 'Medium' },
  'CAT 3': { badge: 'bg-green-50 text-green-700 border border-green-200',   dot: 'bg-green-500',  label: 'Low' },
};

const SEVERITY_STYLES: Record<string, string> = {
  Critical: 'bg-red-50 text-red-700 border-red-200',
  High: 'bg-orange-50 text-orange-700 border-orange-200',
  Medium: 'bg-amber-50 text-amber-700 border-amber-200',
  Low: 'bg-green-50 text-green-700 border-green-200',
};

const ALL_TABS = ['Overview', 'GD Template', 'Architecture', 'Threats', 'Red Team', 'Questionnaire', 'IRP', 'Dependencies', 'IaC', 'Compliance', 'Supply Chain', 'AI Reasoning'] as const;
const CERTIFIER_TABS = ['Overview', 'GD Template', 'Architecture', 'Threats', 'Red Team', 'Questionnaire', 'IRP', 'Dependencies', 'IaC', 'Compliance', 'Supply Chain'] as const;
type Tab = typeof ALL_TABS[number];

interface Props {
  result: AnalysisResult;
  repoUrl: string;
  onPublish: (space: string) => void;
  publishing: boolean;
  jobId?: string;
  createdAt?: Date;
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

function downloadVex(result: AnalysisResult, repoUrl: string) {
  const repoName = repoUrl.split('/').pop() ?? 'repo';
  const purlMap = new Map((result.sbom ?? []).map((c) => [c.name, c.purl]));
  const vex = {
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'GoDaddy', name: 'CertAI' }],
    },
    vulnerabilities: (result.cveScanResults ?? []).map((finding) => {
      const purl = purlMap.get(finding.packageName) ?? `pkg:generic/${finding.packageName}@${finding.version}`;
      return {
        id: finding.vulnId,
        source: { url: `https://osv.dev/vulnerability/${finding.vulnId}` },
        affects: [{ ref: purl }],
        analysis: {
          state: finding.reachable === false ? 'not_affected' : 'exploitable',
          ...(finding.reachable === false ? { justification: 'vulnerable_code_not_in_execute_path' } : {}),
        },
      };
    }),
  };
  const blob = new Blob([JSON.stringify(vex, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${repoName}-vex.cdx.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function downloadFastTrack(jobId: string | undefined) {
  if (!jobId) return;
  try {
    const res = await fetch('/export/fasttrack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jobId }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error(body.error ?? `HTTP ${res.status}`);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `certai-fasttrack-${jobId.slice(0, 8)}.zip`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert(`Fast Track export failed: ${err}`);
  }
}

export function ResultView({ result, repoUrl, onPublish, publishing, jobId, createdAt }: Props) {
  const [activeTab, setActiveTab] = useState<Tab>('Overview');
  const [space, setSpace] = useState('SECARCH');

  // Certifier mode
  const isCertifierMode = new URLSearchParams(window.location.search).get('mode') === 'certifier';
  const TABS = isCertifierMode ? CERTIFIER_TABS : ALL_TABS;

  // Switch to first tab if current tab is hidden in certifier mode
  useEffect(() => {
    if (isCertifierMode && !CERTIFIER_TABS.includes(activeTab as typeof CERTIFIER_TABS[number])) {
      setActiveTab('Overview');
    }
  }, [isCertifierMode, activeTab]);

  const cat = CAT_STYLES[result.riskCategory] ?? CAT_STYLES['CAT 3'];
  const repoName = repoUrl.split('/').pop() ?? repoUrl;

  const highCount = result.threats.filter(t => t.impact === 'Critical' || t.impact === 'High').length;
  const cveCount = result.cveScanResults?.length ?? 0;
  const score = result.securityScore ?? 0;
  const iacCount = (result.iacFindings ?? []).length;
  const supplyChainCount = (result.supplyChainRisks ?? []).length;
  const scenarioCount = (result.attackScenarios ?? []).length;

  // Staleness check (> 90 days)
  const isStale = createdAt && (Date.now() - createdAt.getTime()) > 90 * 24 * 60 * 60 * 1000;
  const daysOld = createdAt ? Math.floor((Date.now() - createdAt.getTime()) / (24 * 60 * 60 * 1000)) : 0;

  return (
    <div className="space-y-6">
      {/* Staleness banner */}
      {isStale && (
        <div className="bg-amber-50 border border-amber-200 rounded-2xl px-5 py-3 flex items-center gap-3">
          <span className="text-amber-500 text-lg">⚠</span>
          <p className="text-[13px] text-amber-800">
            This analysis is <strong>{daysOld} days old</strong> — re-run recommended for accurate certification
          </p>
        </div>
      )}

      {/* Certifier pre-read panel */}
      {isCertifierMode && (
        <div className="bg-[#111] text-white rounded-2xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-[11px] text-white/60 uppercase tracking-wider">Certifier Pre-Read</p>
            <button
              onClick={() => setActiveTab('GD Template')}
              className="text-[13px] bg-white/10 hover:bg-white/20 px-3 py-1.5 rounded-[6px] transition-colors"
            >
              Begin Review →
            </button>
          </div>
          <div className="flex items-center gap-4 flex-wrap">
            <span className={`text-[13px] font-semibold px-2.5 py-1 rounded-[6px] ${cat.badge}`}>
              {result.riskCategory}
            </span>
            <span className="text-white/80 text-[14px]">Score: <strong className="text-white">{score}/100</strong></span>
            <span className="text-white/80 text-[14px]">{highCount} high/critical threats</span>
            <span className="text-white/80 text-[14px]">{cveCount} CVEs</span>
          </div>
          {result.threats.filter(t => t.impact === 'Critical' || t.impact === 'High').slice(0, 5).map((t, i) => (
            <div key={i} className="flex items-start gap-2 text-[13px] text-white/80">
              <span className={`shrink-0 px-1.5 py-0.5 rounded-[6px] text-[11px] font-semibold ${SEVERITY_STYLES[t.impact]}`}>{t.impact}</span>
              {t.component} — {t.threat}
            </div>
          ))}
        </div>
      )}

      {/* Hero banner */}
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

      {/* Pivot tabs */}
      <div className="border-b border-[#D4DBE0] flex flex-wrap">
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
              <span className="text-[11px] bg-red-100 text-red-700 rounded-[6px] px-1.5 py-0.5 font-semibold">{highCount}</span>
            )}
            {tab === 'Dependencies' && cveCount > 0 && (
              <span className="text-[11px] bg-orange-100 text-orange-700 rounded-[6px] px-1.5 py-0.5 font-semibold">{cveCount}</span>
            )}
            {tab === 'Red Team' && scenarioCount > 0 && (
              <span className="text-[11px] bg-rose-100 text-rose-700 rounded-[6px] px-1.5 py-0.5 font-semibold">{scenarioCount}</span>
            )}
            {tab === 'IaC' && iacCount > 0 && (
              <span className="text-[11px] bg-amber-100 text-amber-700 rounded-[6px] px-1.5 py-0.5 font-semibold">{iacCount}</span>
            )}
            {tab === 'Supply Chain' && supplyChainCount > 0 && (
              <span className="text-[11px] bg-purple-100 text-purple-700 rounded-[6px] px-1.5 py-0.5 font-semibold">{supplyChainCount}</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
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
                          <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                            <p className="text-[12px] text-[#666] font-mono">{t.codeEvidence}</p>
                            {t.mitreAttackTechniqueId && (
                              <span className="text-[11px] bg-blue-50 text-blue-700 border border-blue-200 px-1.5 py-0.5 rounded-[6px]">
                                MITRE {t.mitreAttackTechniqueId}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'GD Template' && (
          <GodaddyTemplateView result={result} repoUrl={repoUrl} />
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
                        <div className="bg-[#111] rounded-full h-1.5" style={{ width: `${Math.min(100, count * 20)}%` }} />
                      </div>
                      <span className="text-[12px] text-[#666] w-4 text-right">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'Red Team' && (
          <div>
            <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
              Red Team Attack Scenarios
              <span className="ml-2 normal-case font-normal text-[#999]">
                {scenarioCount > 0 ? `${scenarioCount} multi-step attack chains` : 'No scenarios generated'}
              </span>
            </h3>
            <p className="text-[13px] text-[#666] mb-4 leading-relaxed">
              Realistic attack chains that show how an adversary could exploit identified vulnerabilities step-by-step, mapped to MITRE ATT&CK techniques.
            </p>
            <AttackScenarioView
              scenarios={result.attackScenarios ?? []}
              threats={result.threats}
            />
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
          <div className="space-y-6">
            <div>
              <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">Incident Response Plan (Draft)</h3>
              <pre className="text-[13px] text-[#444] whitespace-pre-wrap leading-relaxed font-mono
                              bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl p-5 max-h-[500px] overflow-y-auto">
                {result.irpDraft}
              </pre>
            </div>

            {/* Pentest Scope */}
            {result.pentestScope && (
              <div className="border-t border-[#D4DBE0] pt-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider">Pentest Scope</h3>
                  <button
                    onClick={() => {
                      const md = [
                        '# Pentest Scope',
                        '',
                        '## High Risk Areas',
                        ...(result.pentestScope.highRiskAreas ?? []).map((a) => `- ${a}`),
                        '',
                        '## Attack Surface',
                        ...(result.pentestScope.attackSurface ?? []).map((a) => `- ${a}`),
                        '',
                        '## Testing Recommendations',
                        ...(result.pentestScope.testingRecommendations ?? []).map((r) => `- ${r}`),
                        '',
                        `## Estimated Effort`,
                        result.pentestScope.estimatedEffort ?? '',
                      ].join('\n');
                      navigator.clipboard.writeText(md);
                    }}
                    className="text-[12px] bg-white hover:bg-[#F5F7F8] border border-[#D6D6D6] text-[#444] px-3 py-1.5 rounded-[6px] transition-colors"
                  >
                    Copy as Markdown
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl p-4">
                    <p className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-2">High Risk Areas</p>
                    <ul className="space-y-1.5">
                      {(result.pentestScope.highRiskAreas ?? []).map((area, i) => (
                        <li key={i} className="text-[13px] text-[#444] flex items-start gap-2">
                          <span className="text-red-500 mt-0.5 shrink-0">●</span>
                          {area}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className="bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl p-4">
                    <p className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-2">Attack Surface</p>
                    <ul className="space-y-1.5">
                      {(result.pentestScope.attackSurface ?? []).map((item, i) => (
                        <li key={i} className="text-[13px] text-[#444] flex items-start gap-2">
                          <span className="text-amber-500 mt-0.5 shrink-0">→</span>
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="mt-4 bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl p-4">
                  <p className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-2">Testing Recommendations</p>
                  <ul className="space-y-1.5">
                    {(result.pentestScope.testingRecommendations ?? []).map((rec, i) => (
                      <li key={i} className="text-[13px] text-[#444] flex items-start gap-2">
                        <span className="text-[#999] mt-0.5 shrink-0">{i + 1}.</span>
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>

                {result.pentestScope.estimatedEffort && (
                  <p className="text-[13px] text-[#444] mt-3">
                    <span className="font-medium text-[#111]">Estimated Effort:</span> {result.pentestScope.estimatedEffort}
                  </p>
                )}
              </div>
            )}
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
                  {result.cveScanResults.map((c, i) => {
                    const epss = result.epssScores?.[c.vulnId];
                    return (
                      <div key={i} className="bg-white border border-[#D4DBE0] rounded-2xl p-4">
                        <div className="flex items-start gap-3">
                          <span className={`text-[11px] font-semibold border px-2 py-0.5 rounded-[6px] shrink-0 mt-0.5 ${SEVERITY_STYLES[c.severity] ?? SEVERITY_STYLES['Low']}`}>
                            {c.severity}
                          </span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-baseline gap-2 flex-wrap">
                              <code className="text-[#111] font-mono text-[14px]">{c.packageName}@{c.version}</code>
                              <span className="text-[#444] text-[12px] font-mono">{c.vulnId}</span>
                              {/* EPSS badge */}
                              {epss !== undefined && (
                                <span className={`text-[11px] font-mono font-semibold px-1.5 py-0.5 rounded-[6px] border ${
                                  epss > 0.1 ? 'bg-red-50 text-red-700 border-red-200' :
                                  epss > 0.01 ? 'bg-amber-50 text-amber-700 border-amber-200' :
                                  'bg-green-50 text-green-700 border-green-200'
                                }`} title="EPSS: probability of exploitation in next 30 days">
                                  EPSS {(epss * 100).toFixed(2)}%
                                </span>
                              )}
                              {/* Reachability badge */}
                              {c.reachable === true && (
                                <span className="text-[11px] bg-red-50 text-red-700 border border-red-200 px-1.5 py-0.5 rounded-[6px]">Reachable</span>
                              )}
                              {c.reachable === false && (
                                <span className="text-[11px] bg-[#F5F7F8] text-[#999] border border-[#D4DBE0] px-1.5 py-0.5 rounded-[6px]">Unreachable</span>
                              )}
                              {c.reachable === null || c.reachable === undefined ? (
                                <span className="text-[11px] bg-amber-50 text-amber-600 border border-amber-200 px-1.5 py-0.5 rounded-[6px]">Unknown</span>
                              ) : null}
                            </div>
                            <p className="text-[#666] text-[13px] mt-1">{c.summary}</p>
                            {c.fixedVersion && (
                              <p className="text-green-600 text-[13px] mt-1">Fix: upgrade to {c.fixedVersion}</p>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Semgrep / Code Scanning Findings */}
            {result.semgrepFindings && result.semgrepFindings.length > 0 && (
              <div>
                <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
                  Code Scanning Findings
                  <span className="ml-2 normal-case font-normal text-[#999]">from GitHub Code Scanning</span>
                </h3>
                <div className="space-y-2">
                  {result.semgrepFindings.map((f, i) => (
                    <div key={i} className="bg-white border border-[#D4DBE0] rounded-2xl p-4">
                      <div className="flex items-start gap-3">
                        <span className={`text-[11px] font-semibold border px-2 py-0.5 rounded-[6px] shrink-0 mt-0.5 ${SEVERITY_STYLES[f.severity] ?? SEVERITY_STYLES['Low']}`}>
                          {f.severity}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-baseline gap-2 flex-wrap">
                            <code className="text-[#111] font-mono text-[13px]">{f.rule}</code>
                            {f.cweId && (
                              <span className="text-[11px] bg-purple-50 text-purple-700 border border-purple-200 px-1.5 py-0.5 rounded-[6px]">{f.cweId}</span>
                            )}
                          </div>
                          <p className="text-[#666] text-[13px] mt-0.5">{f.description}</p>
                          <code className="text-[12px] text-[#999] font-mono mt-0.5 block">{f.file}:{f.line}</code>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

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
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => downloadSbom(result.sbom, repoUrl)}
                    className="bg-white hover:bg-[#F5F7F8] border border-[#D6D6D6] text-[#111] text-[14px]
                               px-4 py-2 rounded-[6px] transition-colors flex items-center gap-2"
                  >
                    Download SBOM (CycloneDX JSON)
                  </button>
                  {(result.cveScanResults ?? []).length > 0 && (
                    <button
                      onClick={() => downloadVex(result, repoUrl)}
                      className="bg-white hover:bg-[#F5F7F8] border border-[#D6D6D6] text-[#111] text-[14px]
                                 px-4 py-2 rounded-[6px] transition-colors flex items-center gap-2"
                    >
                      Download VEX Document
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'IaC' && (
          <div>
            <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider mb-4">
              IaC Security Scan
              <span className="ml-2 normal-case font-normal text-[#999]">
                {iacCount > 0 ? `${iacCount} issues found` : 'No issues found'}
              </span>
            </h3>
            <IacScanView findings={result.iacFindings ?? []} />
          </div>
        )}

        {activeTab === 'Compliance' && (
          <ComplianceView
            owaspAsvs={result.owaspAsvs ?? []}
            complianceGaps={result.complianceGaps ?? []}
            fairRiskEstimates={result.fairRiskEstimates ?? []}
          />
        )}

        {activeTab === 'Supply Chain' && (
          <SupplyChainView
            licenseFindings={result.licenseFindings ?? []}
            supplyChainRisks={result.supplyChainRisks ?? []}
            cveScanResults={result.cveScanResults ?? []}
            epssScores={result.epssScores ?? {}}
          />
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

      {/* Cert Readiness Checklist */}
      <MissingItemsChecklist result={result} />

      {/* Publish panel */}
      <div className="bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl p-6">
        <div className="flex items-center justify-between gap-6 flex-wrap">
          <div>
            {/* <h3 className="text-[#111] font-semibold text-[15px]">Publish to Confluence + Jira</h3> */}
            <h3 className="text-[#111] font-semibold text-[15px]">Publish to Confluence</h3>
            {/* <p className="text-[#666] text-[13px] mt-0.5">Creates a Confluence page and links a Jira ticket in one click</p> */}
            <p className="text-[#666] text-[13px] mt-0.5">Creates a Confluence page in one click</p>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            {/* Fast Track export */}
            <button
              onClick={() => downloadFastTrack(jobId)}
              disabled={!jobId}
              className="bg-white hover:bg-[#F5F7F8] disabled:opacity-40 border border-[#D6D6D6] text-[#111] text-[14px]
                         px-4 py-2.5 rounded-[6px] transition-colors flex items-center gap-2"
            >
              Export Fast Track Bundle
            </button>
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
