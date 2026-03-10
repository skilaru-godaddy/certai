import type { AnalysisResult } from '../types.js';
import { MermaidDiagram } from './MermaidDiagram.js';
import { ThreatTable } from './ThreatTable.js';

interface Props {
  result: AnalysisResult;
  repoUrl: string;
}

export function GodaddyTemplateView({ result, repoUrl }: Props) {
  const repoName = repoUrl.split('/').pop() ?? repoUrl;
  const cat = result.riskCategory;

  return (
    <div className="space-y-8">
      {/* Header — status banner */}
      <div className="bg-[#F5F7F8] border border-[#D4DBE0] rounded-2xl p-5">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <p className="text-[11px] text-[#666] uppercase tracking-wider mb-1">GoDaddy Security Cert — Threat Model</p>
            <h2 className="text-[20px] font-bold text-[#111]">{repoName}</h2>
            <p className="text-[13px] text-[#666] font-mono mt-1">{result.gitSha}</p>
          </div>
          <div className="flex items-center gap-3">
            <span className={`text-[13px] font-semibold px-3 py-1.5 rounded-[6px] border ${
              cat === 'CAT 0' ? 'bg-red-50 text-red-700 border-red-200' :
              cat === 'CAT 1' ? 'bg-orange-50 text-orange-700 border-orange-200' :
              cat === 'CAT 2' ? 'bg-amber-50 text-amber-700 border-amber-200' :
              'bg-green-50 text-green-700 border-green-200'
            }`}>{cat}</span>
            <span className="text-[13px] text-[#666]">Score: <strong>{result.securityScore}/100</strong></span>
          </div>
        </div>
      </div>

      {/* In Scope / Out of Scope */}
      <div className="grid grid-cols-2 gap-4">
        <Section title="In Scope">
          {(result.inScope ?? []).length === 0 ? (
            <p className="text-[#999] text-[13px]">Not specified</p>
          ) : (
            <ul className="space-y-1.5">
              {result.inScope.map((item, i) => (
                <li key={i} className="flex items-start gap-2 text-[14px] text-[#444]">
                  <span className="text-green-600 mt-0.5 shrink-0">✓</span>
                  {item}
                </li>
              ))}
            </ul>
          )}
        </Section>
        <Section title="Out of Scope">
          {(result.outOfScope ?? []).length === 0 ? (
            <p className="text-[#999] text-[13px]">Not specified</p>
          ) : (
            <ul className="space-y-1.5">
              {result.outOfScope.map((item, i) => (
                <li key={i} className="flex items-start gap-2 text-[14px] text-[#444]">
                  <span className="text-[#999] mt-0.5 shrink-0">–</span>
                  {item}
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>

      {/* Architectural Assumptions */}
      <Section title="Architectural Assumptions">
        {(result.architecturalAssumptions ?? []).length === 0 ? (
          <p className="text-[#999] text-[13px]">None specified</p>
        ) : (
          <ul className="space-y-1.5">
            {result.architecturalAssumptions.map((a, i) => (
              <li key={i} className="flex items-start gap-2 text-[14px] text-[#444]">
                <span className="text-amber-500 mt-0.5 shrink-0">⚠</span>
                {a}
              </li>
            ))}
          </ul>
        )}
      </Section>

      {/* Data Flow Diagram */}
      {result.dataFlowDiagram && (
        <Section title="Data Flow Diagram">
          <MermaidDiagram chart={result.dataFlowDiagram} />
        </Section>
      )}

      {/* API / Interfaces Inventory */}
      <Section title="APIs / Interfaces">
        {(result.apiInventory ?? []).length === 0 ? (
          <p className="text-[#999] text-[13px]">No API endpoints detected</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-[#D4DBE0]">
                  {['Endpoint', 'Mutating', 'AuthN', 'AuthZ', 'External Facing'].map((h) => (
                    <th key={h} className="text-left text-[#666] font-medium py-2 pr-4 text-[11px] uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F5F7F8]">
                {result.apiInventory.map((api, i) => (
                  <tr key={i} className="hover:bg-[#F5F7F8]">
                    <td className="py-2.5 pr-4 font-mono text-[#111]">{api.endpoint}</td>
                    <td className="py-2.5 pr-4">
                      <span className={`text-[11px] px-1.5 py-0.5 rounded-[6px] ${api.mutating ? 'bg-amber-50 text-amber-700 border border-amber-200' : 'bg-green-50 text-green-700 border border-green-200'}`}>
                        {api.mutating ? 'Write' : 'Read'}
                      </span>
                    </td>
                    <td className="py-2.5 pr-4 text-[#444]">{api.authn}</td>
                    <td className="py-2.5 pr-4 text-[#444]">{api.authz}</td>
                    <td className="py-2.5">
                      {api.externalFacing
                        ? <span className="text-[11px] bg-orange-50 text-orange-700 border border-orange-200 px-1.5 py-0.5 rounded-[6px]">External</span>
                        : <span className="text-[11px] bg-green-50 text-green-700 border border-green-200 px-1.5 py-0.5 rounded-[6px]">Internal</span>
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {/* API Gateway Checklist */}
      {result.apiGatewayChecklist && (
        <Section title="API Gateway Checklist">
          <div className="grid grid-cols-2 gap-3">
            {([
              ['HTTPS enforced', result.apiGatewayChecklist.https],
              ['Approved auth (JWT/certs)', result.apiGatewayChecklist.approvedAuth],
              ['Rate limiting configured', result.apiGatewayChecklist.rateLimiting],
              ['Anomaly monitoring active', result.apiGatewayChecklist.anomalyMonitoring],
            ] as [string, boolean][]).map(([label, value]) => (
              <div key={label} className="flex items-center gap-2">
                <span className={value ? 'text-green-600' : 'text-red-500'}>{value ? '✓' : '✗'}</span>
                <span className="text-[14px] text-[#444]">{label}</span>
              </div>
            ))}
          </div>
          {result.apiGatewayChecklist.notes && (
            <p className="text-[13px] text-[#666] mt-3 border-t border-[#D4DBE0] pt-3">{result.apiGatewayChecklist.notes}</p>
          )}
        </Section>
      )}

      {/* Secrets & Credentials */}
      <Section title="Secrets & Credentials">
        <p className="text-[14px] text-[#444] leading-relaxed">
          {result.secretsAndCredentials || 'Not assessed'}
        </p>
      </Section>

      {/* Monitoring & Logging */}
      {result.monitoringAndLogging && (
        <Section title="Monitoring & Logging">
          <div className="grid grid-cols-2 gap-4">
            {([
              ['Logging Framework', result.monitoringAndLogging.loggingFramework],
              ['Log Destination', result.monitoringAndLogging.logDestination],
              ['Retention Policy', result.monitoringAndLogging.retentionPolicy],
              ['Alerting Setup', result.monitoringAndLogging.alertingSetup],
            ] as [string, string][]).map(([label, value]) => (
              <div key={label}>
                <p className="text-[11px] text-[#999] uppercase tracking-wide mb-0.5">{label}</p>
                <p className="text-[14px] text-[#444]">{value || '—'}</p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Threats Table */}
      <Section title="Threats">
        <ThreatTable threats={result.threats} />
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white border border-[#D4DBE0] rounded-2xl overflow-hidden">
      <div className="px-5 py-3 border-b border-[#D4DBE0] bg-[#F5F7F8]">
        <h3 className="text-[11px] font-semibold text-[#666] uppercase tracking-wider">{title}</h3>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}
