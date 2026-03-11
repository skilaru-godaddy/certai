import type { FastifyInstance } from 'fastify';
import { createJob, startAnalysis, getJob, JobStatus } from '../lib/analyzer.js';

export async function analyzeRoutes(app: FastifyInstance) {
  // POST /analyze  — creates a job and starts analysis
  app.post<{ Body: { repoUrl: string; branch?: string; userInput?: string } }>('/analyze', async (req, reply) => {
    const { repoUrl, branch, userInput } = req.body;
    if (!repoUrl?.trim()) {
      return reply.status(400).send({ error: 'repoUrl is required' });
    }
    const normalizedBranch = branch?.trim() ? branch.trim() : 'main';
    const normalizedUserInput = userInput?.trim() ? userInput.trim() : '';
    const job = createJob({
      repoUrl: repoUrl.trim(),
      branch: normalizedBranch,
      userInput: normalizedUserInput,
    });
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
      branch: job.branch,
      commitId: job.commitId,
      userInput: job.userInput,
      status: job.status,
      createdAt: job.createdAt,
      result: job.result,
      error: job.error,
    };
  });
}
