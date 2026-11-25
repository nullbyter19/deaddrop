import { sha256Bytes, INFO_SAFETY } from './hkdf.js';
import { concatBytes, utf8Encode } from './util.js';

/**
 * Safety number estilo Signal: 12 grupos de 5 digitos (60 digitos).
 * Fingerprint = SHA256("DeadDrop-SafetyNumber-v1" || ikA || ikB) com ikA <= ikB
 * (byte-wise order, so both sides compute the same value).
 * 240 bits → big-endian BigInt → 12 rodadas de mod 100000.
 */
export function safetyNumber(ikA: string, ikB: string): { digits: string; groups: string[] } {
  const a = b64ToBytes(ikA);
  const b = b64ToBytes(ikB);
  const [first, second] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
  const fp = sha256Bytes(concatBytes(INFO_SAFETY, first, second)).slice(0, 30);
  let n = 0n;
  for (const byte of fp) n = (n << 8n) | BigInt(byte);
  const groups: string[] = [];
  for (let i = 0; i < 12; i++) {
    const g = Number(n % 100000n);
    n /= 100000n;
    groups.push(String(g).padStart(5, '0'));
  }
  return { digits: groups.join(''), groups };
}
export function formatSafetyNumber(groups: string[]): string {
  return groups.join(' ');
}
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  return a.length - b.length;
}
function b64ToBytes(b64: string): Uint8Array {
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
export const SAFETY_GROUP_COUNT = 12;
