import type { FastifyInstance } from 'fastify';
import { createJob, startAnalysis, getJob, JobStatus } from '../lib/analyzer.js';

export async function analyzeRoutes(app: FastifyInstance) {
  // POST /analyze  — creates a job and starts analysis
  app.post<{ Body: { repoUrl: string } }>('/analyze', async (req, reply) => {
    const { repoUrl } = req.body;
    if (!repoUrl?.trim()) {
      return reply.status(400).send({ error: 'repoUrl is required' });
    }
    const job = createJob(repoUrl.trim());
    startAnalysis(job.id);
    return { jobId: job.id };
  });

  // GET /stream/:jobId  — SSE stream of phase updates
  app.get<{ Params: { jobId: string } }>(
    '/stream/:jobId',
    async (req, reply) => {
      const job = getJob(req.params.jobId);
      if (!job) {
        return reply.status(404).send({ error: 'job not found' });
      }

      reply.raw.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
        'Access-Control-Allow-Origin': '*',
      });

      const send = (data: unknown) => {
        reply.raw.write(`data: ${JSON.stringify(data)}\n\n`);
      };

      // Replay already-completed phases (job may have progressed before SSE connected)
      for (const phase of job.phases) {
        send(phase);
      }

      if (job.status === JobStatus.Done || job.status === JobStatus.Error) {
        reply.raw.end();
        return;
      }

      // Subscribe to future updates
      const onUpdate = (update: unknown) => {
        send(update);
        const j = getJob(req.params.jobId)!;
        if (j.status === JobStatus.Done || j.status === JobStatus.Error) {
          reply.raw.end();
          job.subscribers.delete(onUpdate);
        }
      };
      job.subscribers.add(onUpdate);

      // Clean up on client disconnect
      req.raw.on('close', () => {
        job.subscribers.delete(onUpdate);
      });
    }
  );

  // GET /job/:jobId  — fetch final result as JSON
  app.get<{ Params: { jobId: string } }>('/job/:jobId', async (req, reply) => {
    const job = getJob(req.params.jobId);
    if (!job) return reply.status(404).send({ error: 'not found' });
    return {
      id: job.id,
      repoUrl: job.repoUrl,
      status: job.status,
      result: job.result,
      error: job.error,
    };
  });
}
