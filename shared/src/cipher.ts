import { gcm } from '@noble/ciphers/aes';
import { concatBytes } from './util.js';
import { hkdfSha256, ZERO_SALT, INFO_MK } from './hkdf.js';

export const MK_OUTPUT_LEN = 44; // 32 key + 12 nonce
export const NONCE_LEN = 12;

/**
 * Deterministic AEAD per message key (Double Ratchet).
 * Derives the AES-256 key + 12B nonce from the message key via HKDF-SHA256.
 * AD = CONCAT(AD_base, header-binary) — binds identities + header.
 */
export function deriveAeadMaterial(mk: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const out = hkdfSha256(mk, ZERO_SALT, INFO_MK, MK_OUTPUT_LEN);
  return { key: out.slice(0, 32), nonce: out.slice(32, 44) };
}

export function aeadEncrypt(mk: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Uint8Array {
  const { key, nonce } = deriveAeadMaterial(mk);
  return gcm(key, nonce, ad).encrypt(plaintext);
}

export function aeadDecrypt(mk: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array): Uint8Array {
  const { key, nonce } = deriveAeadMaterial(mk);
  return gcm(key, nonce, ad).decrypt(ciphertext);
}

/** AD_base: identidade de quem envia || identidade de quem recebe. */
export function buildAdBase(senderIdentityPub: Uint8Array, recipientIdentityPub: Uint8Array): Uint8Array {
  return concatBytes(senderIdentityPub, recipientIdentityPub);
}
