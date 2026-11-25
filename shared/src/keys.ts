import { x25519, ed25519 } from '@noble/curves/ed25519';
import { concatBytes, bytesToB64, b64ToBytes, utf8Encode } from './util.js';
import { sha256Bytes } from './hkdf.js';

/** X25519 key pair. */
export interface X25519KeyPair {
  privateKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array;  // 32 bytes
}
/** Ed25519 key pair (signing). */
export interface Ed25519KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}
/** Full identity of a user: X25519 (E2EE) + Ed25519 (prekey signing). */
export interface Identity {
  ik: X25519KeyPair;
  signing: Ed25519KeyPair;
}
export interface SignedPreKey {
  keyId: number;
  keyPair: X25519KeyPair;
  signature: Uint8Array; // ed25519 signature over (keyId || publicKey)
}
export interface OneTimePreKey {
  keyId: number;
  keyPair: X25519KeyPair;
}

export function generateX25519(): X25519KeyPair {
  const kp = x25519.keygen();
  return { privateKey: kp.secretKey, publicKey: kp.publicKey };
}
export function generateEd25519(): Ed25519KeyPair {
  const priv = ed25519.utils.randomSecretKey();
  return { privateKey: priv, publicKey: ed25519.getPublicKey(priv) };
}
export function generateIdentity(): Identity {
  return { ik: generateX25519(), signing: generateEd25519() };
}
export function x25519PublicFromPrivate(priv: Uint8Array): Uint8Array {
  return x25519.getPublicKey(priv);
}

/** Ed25519 signature over the binary blob. */
export function signBytes(priv: Uint8Array, data: Uint8Array): Uint8Array {
  return ed25519.sign(data, priv);
}
export function verifyBytes(pub: Uint8Array, sig: Uint8Array, data: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, data, pub);
  } catch {
    return false;
  }
}

/** Canonical signed blob for a prekey: SHA256(keyId||pub) — signs the hash (avoids encoding ambiguity). */
export function preKeySigningBlob(keyId: number, publicKey: Uint8Array): Uint8Array {
  const id = new Uint8Array(4);
  new DataView(id.buffer).setUint32(0, keyId >>> 0, false);
  return sha256Bytes(concatBytes(id, publicKey));
}

export function createSignedPreKey(signingPriv: Uint8Array, keyId: number): SignedPreKey {
  const keyPair = generateX25519();
  const sig = signBytes(signingPriv, preKeySigningBlob(keyId, keyPair.publicKey));
  return { keyId, keyPair, signature: sig };
}
export function createOneTimePreKey(keyId: number): OneTimePreKey {
  return { keyId, keyPair: generateX25519() };
}

export function verifySignedPreKey(signingPub: Uint8Array, keyId: number, publicKey: Uint8Array, signature: Uint8Array): boolean {
  return verifyBytes(signingPub, signature, preKeySigningBlob(keyId, publicKey));
}

export function pubToB64(pub: Uint8Array): string { return bytesToB64(pub); }
export function b64ToPub(b64: string): Uint8Array { return b64ToBytes(b64); }
export const PK_B64 = utf8Encode('b64');
