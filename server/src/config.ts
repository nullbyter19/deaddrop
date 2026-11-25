import { mkdirSync } from 'node:fs';
import path from 'node:path';

export interface Config {
  port: number;
  host: string;
  dbPath: string;
  dataDir: string;
  clientDist: string;
  wsPingIntervalMs: number;
  tlsCert?: string;
  tlsKey?: string;
}

function envInt(name: string, def: number): number {
  const v = process.env[name];
  if (!v) return def;
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : def;
}

export function loadConfig(): Config {
  const dataDir = process.env.DEADDROP_DATA_DIR ?? path.resolve(process.cwd(), 'data');
  mkdirSync(dataDir, { recursive: true });
  const cfg: Config = {
    port: envInt('DEADDROP_PORT', 8080),
    host: process.env.DEADDROP_HOST ?? '127.0.0.1',
    dbPath: process.env.DEADDROP_DB_PATH ?? path.join(dataDir, 'deaddrop.db'),
    dataDir,
    clientDist: path.resolve(process.cwd(), '../client/dist'),
    wsPingIntervalMs: envInt('DEADDROP_WS_PING_MS', 30_000),
    tlsCert: process.env.DEADDROP_TLS_CERT || undefined,
    tlsKey: process.env.DEADDROP_TLS_KEY || undefined,
  };
  return cfg;
}
