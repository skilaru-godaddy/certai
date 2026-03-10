import type { FastifyInstance } from 'fastify';
import { getJob } from '../lib/analyzer.js';

export async function compareRoutes(app: FastifyInstance) {
  app.get('/compare/:jobId1/:jobId2', async (request, reply) => {
    const { jobId1, jobId2 } = request.params as { jobId1: string; jobId2: string };

    const job1 = getJob(jobId1);
    const job2 = getJob(jobId2);

    if (!job1?.result || !job2?.result) {
      return reply.status(404).send({ error: 'One or both jobs not found or not complete' });
    }

    const r1 = job1.result;
    const r2 = job2.result;

    // Threat diff — key by component+threat
    const threatKey = (t: { component: string; threat: string }) => `${t.component}::${t.threat}`;
    const threats1 = new Map(r1.threats.map((t) => [threatKey(t), t]));
    const threats2 = new Map(r2.threats.map((t) => [threatKey(t), t]));

    const newThreats = r2.threats.filter((t) => !threats1.has(threatKey(t)));
    const resolvedThreats = r1.threats.filter((t) => !threats2.has(threatKey(t)));
    const unchangedThreats = r2.threats.filter((t) => threats1.has(threatKey(t)));

    // CVE diff — key by vulnId
    const cves1 = new Set(r1.cveScanResults?.map((c) => c.vulnId) ?? []);
    const cves2 = new Set(r2.cveScanResults?.map((c) => c.vulnId) ?? []);

    const newCves = (r2.cveScanResults ?? []).filter((c) => !cves1.has(c.vulnId));
    const resolvedCves = (r1.cveScanResults ?? []).filter((c) => !cves2.has(c.vulnId));

    return reply.send({
      job1: { id: jobId1, date: job1.createdAt, securityScore: r1.securityScore, riskCategory: r1.riskCategory },
      job2: { id: jobId2, date: job2.createdAt, securityScore: r2.securityScore, riskCategory: r2.riskCategory },
      scoreDelta: r2.securityScore - r1.securityScore,
      threats: { new: newThreats, resolved: resolvedThreats, unchanged: unchangedThreats },
      cves: { new: newCves, resolved: resolvedCves },
    });
  });
}
