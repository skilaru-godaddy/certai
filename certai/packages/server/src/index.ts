import Fastify from 'fastify';
import cors from '@fastify/cors';
import { analyzeRoutes } from './routes/analyze.js';
import { publishRoutes } from './routes/publish.js';

const app = Fastify({ logger: true });
await app.register(cors, { origin: '*' });
await app.register(analyzeRoutes);
await app.register(publishRoutes);

app.get('/health', async () => ({ status: 'ok' }));

const port = Number(process.env.PORT ?? 3001);
await app.listen({ port, host: '0.0.0.0' });
console.log(`CertAI server running on http://localhost:${port}`);
