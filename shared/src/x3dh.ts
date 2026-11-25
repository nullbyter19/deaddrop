import { x25519 } from '@noble/curves/ed25519';
import { concatBytes } from './util.js';
import { hkdfSha256, ZERO_SALT, INFO_X3DH } from './hkdf.js';
import { generateX25519, type X25519KeyPair } from './keys.js';

/**
 * X3DH (Signal) — derives a shared SK between Alice (initiator) and Bob (responder).
 * DH1 = DH(IKA, SPKB), DH2 = DH(EKA, IKB), DH3 = DH(EKA, SPKB), DH4 = DH(EKA, OPKB)
 * SK = HKDF(0xFF*32 || DH1 || DH2 || DH3 || [DH4], salt=zeros, info="DeadDrop-X3DH-v1")
 */

export interface X3DHResult {
  sharedKey: Uint8Array; // 32 bytes
  ephemeralKey: X25519KeyPair; // EKA (Alice) — vai no header.dh da 1a msg
}

/** Alice side: needs her identity and Bob's bundle (IKB, SPKB, optional OPKB). */
export function x3dhInitiator(
  aliceIk: X25519KeyPair,
  bobIdentityPub: Uint8Array,
  bobSignedPreKeyPub: Uint8Array,
  bobOneTimePreKeyPub: Uint8Array | null,
): X3DHResult {
  const eka = generateX25519();
  const dh1 = x25519.getSharedSecret(aliceIk.privateKey, bobSignedPreKeyPub);
  const dh2 = x25519.getSharedSecret(eka.privateKey, bobIdentityPub);
  const dh3 = x25519.getSharedSecret(eka.privateKey, bobSignedPreKeyPub);
  const dh4 = bobOneTimePreKeyPub
    ? x25519.getSharedSecret(eka.privateKey, bobOneTimePreKeyPub)
    : null;

  const f = new Uint8Array(32).fill(0xff);
  const ikm = dh4 ? concatBytes(f, dh1, dh2, dh3, dh4) : concatBytes(f, dh1, dh2, dh3);
  const sk = hkdfSha256(ikm, ZERO_SALT, INFO_X3DH, 32);
  return { sharedKey: sk, ephemeralKey: eka };
}

/** Bob side (responder): rebuilds the SK from the material received in the first msg. */
export function x3dhResponder(
  bobIkPriv: Uint8Array,
  bobSignedPreKeyPriv: Uint8Array,
  bobOneTimePreKeyPriv: Uint8Array | null,
  aliceIdentityPub: Uint8Array,
  aliceEphemeralPub: Uint8Array,
): Uint8Array {
  const dh1 = x25519.getSharedSecret(bobSignedPreKeyPriv, aliceIdentityPub);
  const dh2 = x25519.getSharedSecret(bobIkPriv, aliceEphemeralPub);
  const dh3 = x25519.getSharedSecret(bobSignedPreKeyPriv, aliceEphemeralPub);
  const dh4 = bobOneTimePreKeyPriv
    ? x25519.getSharedSecret(bobOneTimePreKeyPriv, aliceEphemeralPub)
    : null;

  const f = new Uint8Array(32).fill(0xff);
  const ikm = dh4 ? concatBytes(f, dh1, dh2, dh3, dh4) : concatBytes(f, dh1, dh2, dh3);
  return hkdfSha256(ikm, ZERO_SALT, INFO_X3DH, 32);
}
