import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_LEN = 64;
const TOKEN_TTL_MS = 30 * 86_400_000; // 30 dias

export function hashPassword(password: string, saltHex?: string): { salt: string; hash: string } {
  const salt = saltHex ?? randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, SCRYPT_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  return { salt, hash: hash.toString('hex') };
}

export function verifyPassword(password: string, saltHex: string, expectedHashHex: string): boolean {
  const { hash } = hashPassword(password, saltHex);
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(expectedHashHex, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

export function newToken(): string {
  return randomBytes(32).toString('hex');
}

export function tokenExpiry(): number {
  return Date.now() + TOKEN_TTL_MS;
}
