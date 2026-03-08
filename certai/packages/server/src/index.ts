import Fastify from 'fastify';
import cors from '@fastify/cors';

const app = Fastify({ logger: true });
await app.register(cors, { origin: 'http://localhost:5173' });

app.get('/health', async () => ({ status: 'ok' }));

const port = Number(process.env.PORT ?? 3001);
await app.listen({ port, host: '0.0.0.0' });
console.log(`CertAI server running on http://localhost:${port}`);
