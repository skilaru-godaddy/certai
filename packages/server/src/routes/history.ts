import type { FastifyInstance } from 'fastify';
import { getHistoryForRepo } from '../lib/history.js';

export async function historyRoutes(app: FastifyInstance) {
  app.get('/history/*', async (request, reply) => {
    const repoKey = (request.params as { '*': string })['*'];
    const history = getHistoryForRepo(repoKey);
    return reply.send(history);
  });
}
