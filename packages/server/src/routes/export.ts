import type { FastifyInstance } from 'fastify';
import archiver from 'archiver';
import { PassThrough } from 'stream';
import { getJob } from '../lib/analyzer.js';
import type { AnalysisResult } from '../lib/analyzer.js';

function threatModelMd(result: AnalysisResult, repoUrl: string): string {
  const repoName = repoUrl.split('/').pop() ?? repoUrl;
  const lines: string[] = [
    `# Threat Model — ${repoName}`,
    ``,
    `**Risk Category:** ${result.riskCategory}  `,
    `**Security Score:** ${result.securityScore}/100  `,
    `**Commit:** ${result.gitSha}`,
    ``,
    `## Risk Reasoning`,
    result.riskReasoning,
    ``,
    `## In Scope`,
    ...(result.inScope ?? []).map((s) => `- ${s}`),
    ``,
    `## Out of Scope`,
    ...(result.outOfScope ?? []).map((s) => `- ${s}`),
    ``,
    `## Architectural Assumptions`,
    ...(result.architecturalAssumptions ?? []).map((a) => `- ${a}`),
    ``,
    `## Secrets & Credentials`,
    result.secretsAndCredentials ?? 'Not assessed',
    ``,
    `## Monitoring & Logging`,
    result.monitoringAndLogging
      ? [
          `- **Framework:** ${result.monitoringAndLogging.loggingFramework}`,
          `- **Destination:** ${result.monitoringAndLogging.logDestination}`,
          `- **Retention:** ${result.monitoringAndLogging.retentionPolicy}`,
          `- **Alerting:** ${result.monitoringAndLogging.alertingSetup}`,
        ].join('\n')
      : 'Not assessed',
    ``,
    `## Threats`,
    ``,
    `| Impact | Component | Threat | STRIDE | DREAD | MITRE |`,
    `|--------|-----------|--------|--------|-------|-------|`,
    ...(result.threats ?? []).map((t) =>
      `| ${t.impact} | ${t.component} | ${t.threat} | ${t.strideCategory} | ${t.dreadScore} | ${t.mitreAttackTechniqueId ?? '—'} |`
    ),
  ];
  return lines.join('\n');
}

function irpMd(result: AnalysisResult): string {
  return result.irpDraft ?? '# Incident Response Plan\n\n*Not generated*';
}

function pentestScopeMd(result: AnalysisResult): string {
  const scope = result.pentestScope;
  if (!scope) return '# Pentest Scope\n\n*Not generated*';
  return [
    '# Pentest Scope',
    '',
    '## High Risk Areas',
    ...(scope.highRiskAreas ?? []).map((a) => `- ${a}`),
    '',
    '## Attack Surface',
    ...(scope.attackSurface ?? []).map((a) => `- ${a}`),
    '',
    '## Testing Recommendations',
    ...(scope.testingRecommendations ?? []).map((r) => `- ${r}`),
    '',
    `## Estimated Effort`,
    scope.estimatedEffort ?? '',
  ].join('\n');
}

function apiInventoryCsv(result: AnalysisResult): string {
  const rows = ['Endpoint,Mutating,AuthN,AuthZ,External Facing'];
  for (const api of result.apiInventory ?? []) {
    rows.push([
      api.endpoint,
      String(api.mutating),
      api.authn,
      api.authz,
      String(api.externalFacing),
    ].map((v) => `"${v.replace(/"/g, '""')}"`).join(','));
  }
  return rows.join('\n');
}

function cveFindingsCsv(result: AnalysisResult): string {
  const rows = ['Package,Version,Ecosystem,CVE/GHSA,Severity,Summary,Fixed Version'];
  for (const c of result.cveScanResults ?? []) {
    rows.push([
      c.packageName, c.version, c.ecosystem, c.vulnId,
      c.severity, c.summary, c.fixedVersion ?? '',
    ].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(','));
  }
  return rows.join('\n');
}

function summaryMd(result: AnalysisResult, repoUrl: string): string {
  const repoName = repoUrl.split('/').pop() ?? repoUrl;
  const highCount = (result.threats ?? []).filter((t) => t.impact === 'Critical' || t.impact === 'High').length;
  return [
    `# CertAI Fast Track — Executive Summary`,
    ``,
    `**Repository:** ${repoName}`,
    `**Risk Category:** ${result.riskCategory}`,
    `**Security Score:** ${result.securityScore}/100`,
    `**Commit:** ${result.gitSha}`,
    `**Date:** ${new Date().toISOString().split('T')[0]}`,
    ``,
    `## Key Findings`,
    `- ${(result.threats ?? []).length} threats identified, ${highCount} high/critical`,
    `- ${(result.cveScanResults ?? []).length} CVE findings`,
    `- ${(result.secretScanFindings ?? []).length} potential secrets detected`,
    `- ${(result.iacFindings ?? []).length} IaC misconfigurations`,
    ``,
    `## Risk Summary`,
    result.riskReasoning,
    ``,
    `## Top Threats`,
    ...(result.threats ?? [])
      .filter((t) => t.impact === 'Critical' || t.impact === 'High')
      .slice(0, 5)
      .map((t) => `- **${t.impact}** — ${t.component}: ${t.threat}`),
  ].join('\n');
}

/** Build a ZIP in memory and return the Buffer — avoids Fastify stream/async conflicts */
function buildZip(files: Array<{ name: string; content: string }>): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const pass = new PassThrough();
    pass.on('data', (chunk: Buffer) => chunks.push(chunk));
    pass.on('end', () => resolve(Buffer.concat(chunks)));
    pass.on('error', reject);

    const archive = archiver('zip', { zlib: { level: 6 } });
    archive.on('error', reject);
    archive.pipe(pass);

    for (const file of files) {
      archive.append(file.content, { name: file.name });
    }

    archive.finalize();
  });
}

export async function exportRoutes(app: FastifyInstance) {
  app.post('/export/fasttrack', async (request, reply) => {
    try {
    const { jobId } = request.body as { jobId: string };
    const job = getJob(jobId);

    if (!job?.result) {
      return reply.status(404).send({ error: 'Job not found or not complete' });
    }

    const result = job.result;
    const repoUrl = job.repoUrl;
    const repoName = repoUrl.split('/').pop() ?? 'repo';

    const files: Array<{ name: string; content: string }> = [
      { name: 'summary.md', content: summaryMd(result, repoUrl) },
      { name: 'threat-model.md', content: threatModelMd(result, repoUrl) },
      { name: 'irp.md', content: irpMd(result) },
      { name: 'pentest-scope.md', content: pentestScopeMd(result) },
      { name: 'api-inventory.csv', content: apiInventoryCsv(result) },
      { name: 'cve-findings.csv', content: cveFindingsCsv(result) },
    ];

    if ((result.sbom ?? []).length > 0) {
      files.push({
        name: 'sbom.json',
        content: JSON.stringify({
          bomFormat: 'CycloneDX',
          specVersion: '1.4',
          version: 1,
          metadata: {
            timestamp: new Date().toISOString(),
            tools: [{ vendor: 'GoDaddy', name: 'CertAI', version: '2.0' }],
            component: { type: 'application', name: repoName },
          },
          components: result.sbom.map((c) => ({
            type: 'library', name: c.name, version: c.version, purl: c.purl,
          })),
        }, null, 2),
      });
    }

    if ((result.cveScanResults ?? []).length > 0) {
      const purlMap = new Map((result.sbom ?? []).map((c) => [c.name, c.purl]));
      files.push({
        name: 'vex.json',
        content: JSON.stringify({
          bomFormat: 'CycloneDX',
          specVersion: '1.4',
          version: 1,
          metadata: { timestamp: new Date().toISOString(), tools: [{ vendor: 'GoDaddy', name: 'CertAI' }] },
          vulnerabilities: result.cveScanResults.map((finding) => {
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
        }, null, 2),
      });
    }

    const zipBuffer = await buildZip(files);

    return reply
      .header('Content-Type', 'application/zip')
      .header('Content-Disposition', `attachment; filename="${repoName}-certai-fasttrack.zip"`)
      .send(zipBuffer);
    } catch (err) {
      app.log.error(err, 'Fast Track export error');
      return reply.status(500).send({ error: String(err) });
    }
  });
}
