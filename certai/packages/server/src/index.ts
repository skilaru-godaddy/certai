import Fastify from 'fastify';
import cors from '@fastify/cors';
import { analyzeRoutes } from './routes/analyze.js';
import { publishRoutes } from './routes/publish.js';
import { registerSlack } from './routes/slack.js';

const app = Fastify({ logger: true });
await app.register(cors, { origin: '*' });
await app.register(analyzeRoutes);
await app.register(publishRoutes);

app.get('/health', async () => ({ status: 'ok' }));

const port = Number(process.env.PORT ?? 3001);
await app.listen({ port, host: '0.0.0.0' });
console.log(`CertAI server running on http://localhost:${port}`);

// Slack runs on its own port (3002) — only starts when token is configured
if (process.env.SLACK_BOT_TOKEN) {
  await registerSlack(app);
  console.log('Slack slash command registered. Run: ngrok http 3002');
}
