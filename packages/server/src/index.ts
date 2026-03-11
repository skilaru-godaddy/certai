import Fastify from 'fastify';
import cors from '@fastify/cors';
import { analyzeRoutes } from './routes/analyze.js';
import { publishRoutes } from './routes/publish.js';
import { historyRoutes } from './routes/history.js';
import { compareRoutes } from './routes/compare.js';
import { exportRoutes } from './routes/export.js';
import { registerSlack } from './routes/slack.js';

import { config as loadEnv } from 'dotenv';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const app = Fastify({ logger: true });
await app.register(cors, { origin: '*' });
await app.register(analyzeRoutes);
await app.register(publishRoutes);
await app.register(historyRoutes);
await app.register(compareRoutes);
await app.register(exportRoutes);

const __dirname = fileURLToPath(new URL('.', import.meta.url));
loadEnv({ path: resolve(__dirname, '../../../.env') });

app.get('/health', async () => ({ status: 'ok' }));

const port = Number(process.env.PORT ?? 3001);
await app.listen({ port, host: '0.0.0.0' });
console.log(`CertAI server running on http://localhost:${port}`);

// Slack runs on its own port (3002) — only starts when token is configured
if (process.env.SLACK_BOT_TOKEN) {
  await registerSlack(app);
  console.log('Slack slash command registered. Run: ngrok http 3002');
}
