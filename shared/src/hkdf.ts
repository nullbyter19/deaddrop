import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { utf8Encode } from './util.js';

/** HKDF-SHA256. ikm, salt, info: bytes. length: output size. */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length);
}

/** HMAC-SHA256(key, data). */
export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data);
}

export const ZERO_SALT = new Uint8Array(32);
export const INFO_RK = utf8Encode('DeadDrop-RK-v1');
export const INFO_X3DH = utf8Encode('DeadDrop-X3DH-v1');
export const INFO_MK = utf8Encode('DeadDrop-MessageKey-v1');
export const INFO_SAFETY = utf8Encode('DeadDrop-SafetyNumber-v1');
export const INFO_VAULT = utf8Encode('DeadDrop-Vault-v1');
