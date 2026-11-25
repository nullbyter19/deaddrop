#!/usr/bin/env node
/**
 * DeadDrop server launcher.
 * Applies --experimental-sqlite only when Node requires it:
 *   - Node 22.5-23.3  -> required flag (node:sqlite experimental)
 *   - Node >= 23.4    -> flag removido; node:sqlite carrega sem flag
 *   - Node < 22.5     -> node:sqlite does not exist (clear error)
 * Uso: node run.mjs [--npx] <script> [args...]
 */
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const [major, minor] = process.versions.node.split('.').map(Number);
const needFlag = (major === 22 && minor >= 5) || (major === 23 && minor < 4);
const supported = major > 22 || (major === 22 && minor >= 5);

if (!supported) {
  console.error(`[DeadDrop] node:sqlite exige Node >= 22.5 - versao atual: ${process.version}`);
  console.error('[DeadDrop] instale o Node 22 LTS ou 24: https://nodejs.org (Linux: NodeSource)');
  process.exit(1);
}

const useNpx = process.argv[2] === '--npx';
const scriptArgs = process.argv.slice(useNpx ? 3 : 2);
if (scriptArgs.length === 0) {
  console.error('[DeadDrop] uso: node run.mjs [--npx] <script> [args...]');
  process.exit(1);
}

const flags = needFlag ? ['--experimental-sqlite'] : [];
const cmd = useNpx ? 'npx' : process.execPath;
const args = useNpx ? ['tsx', ...flags, ...scriptArgs] : [...flags, ...scriptArgs];
const r = spawnSync(cmd, args, { stdio: 'inherit', cwd: import.meta.dirname });
process.exit(r.status ?? 1);
