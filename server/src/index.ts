import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import Fastify from 'fastify';
import websocket from '@fastify/websocket';
import fastifyStatic from '@fastify/static';
import { ed25519 } from '@noble/curves/ed25519';
import { generateEd25519, bytesToB64, b64ToBytes } from '@deaddrop/shared';
import { loadConfig } from './config.js';
import { Store } from './store.js';
import { buildApi } from './api.js';
import { registerWs } from './ws.js';
import { startDropScheduler } from './drops.js';

const SCHEDULER_MS = 10_000;

async function main(): Promise<void> {
  const cfg = loadConfig();
  const tls = cfg.tlsCert && cfg.tlsKey
    ? { cert: readFileSync(cfg.tlsCert), key: readFileSync(cfg.tlsKey) }
    : undefined;
  const store = new Store(cfg.dbPath);

  // --- server signing key (deletion receipts) — persisted to a file ---
  const keyFile = path.join(cfg.dataDir, 'server_signing_key.json');
  let serverSigningPriv: Uint8Array;
  if (existsSync(keyFile)) {
    const saved = JSON.parse(readFileSync(keyFile, 'utf8')) as { priv: string };
    serverSigningPriv = b64ToBytes(saved.priv);
  } else {
    const kp = generateEd25519();
    serverSigningPriv = kp.privateKey;
    writeFileSync(keyFile, JSON.stringify({ priv: bytesToB64(kp.privateKey) }), { mode: 0o600 });
  }
  const pubB64 = bytesToB64(ed25519.getPublicKey(serverSigningPriv));
  const active = store.getActiveServerKey();
  if (!active || active.public_key !== pubB64) {
    store.createServerKey(Math.floor(Date.now() / 1000), pubB64, Date.now());
  }

  const app = Fastify({
    logger: { level: process.env.DEADDROP_LOG_LEVEL ?? 'info' },
    ...(tls ? { https: tls } : {}),
  });
  await app.register(websocket);

  const { notify } = registerWs(app, store);
  buildApi(app, store, serverSigningPriv, notify);
  const scheduler = startDropScheduler(store, serverSigningPriv, notify, SCHEDULER_MS);

  // serves client/dist (SPA) on the same origin — no CORS, same origin
  await app.register(fastifyStatic, {
    root: cfg.clientDist,
    prefix: '/',
    wildcard: false,
  });
  app.setNotFoundHandler((req, reply) => {
    if (req.url.startsWith('/api/')) {
      return reply.code(404).send({ error: 'not found' });
    }
    const idx = path.join(cfg.clientDist, 'index.html');
    if (existsSync(idx)) {
      reply.type('text/html').send(readFileSync(idx));
    } else {
      reply.code(404).send('client not built — run: npm run build -w client');
    }
  });

  await app.listen({ port: cfg.port, host: cfg.host });
  app.log.info(`DeadDrop server at ${tls ? 'https' : 'http'}://${cfg.host}:${cfg.port} (db: ${cfg.dbPath})`);

  const shutdown = async (sig: string): Promise<void> => {
    app.log.info(`received ${sig}, shutting down...`);
    scheduler.stop();
    await app.close();
    store.close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

void main().catch((err) => {
  console.error('failed to start server:', err);
  process.exit(1);
});
