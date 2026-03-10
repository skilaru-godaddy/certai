import type { FastifyInstance } from 'fastify';
import { getJob, JobStatus } from '../lib/analyzer.js';
import { publishToConfluence, createJiraTicket } from '../lib/atlassian.js';

export async function publishRoutes(app: FastifyInstance) {
  app.post<{ Body: { jobId: string; space: string } }>(
    '/publish',
    async (req, reply) => {
      const { jobId, space } = req.body;
      const job = getJob(jobId);

      if (!job) return reply.status(404).send({ error: 'job not found' });
      if (job.status !== JobStatus.Done || !job.result) {
        return reply.status(400).send({ error: 'analysis not complete' });
      }

      try {
        const { pageUrl } = await publishToConfluence(space, job.repoUrl, job.result);

        // JIRA TICKET CREATION DISABLED
        // const { ticketKey, ticketUrl } = await createJiraTicket(
        //   job.repoUrl,
        //   job.result,
        //   pageUrl
        // );
        // return { pageUrl, ticketKey, ticketUrl };

        return { pageUrl };
      } catch (err) {
        return reply.status(500).send({ error: String(err) });
      }
    }
  );
}
