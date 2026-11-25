import { describe, it, expect } from 'vitest';
import { x3dhInitiator, x3dhResponder } from './x3dh.js';
import { generateIdentity, createSignedPreKey, createOneTimePreKey, verifySignedPreKey } from './keys.js';
import { aeadEncrypt, aeadDecrypt, buildAdBase } from './cipher.js';
import { safetyNumber } from './safety.js';
import { signReceipt, verifyReceipt } from './receipts.js';
import { utf8Encode, b64ToBytes } from './util.js';
import type { DeletionReceipt } from './types.js';

describe('X3DH', () => {
  it('identical SK on both sides, with and without OPK', () => {
    for (const withOpk of [true, false]) {
      const alice = generateIdentity();
      const bob = generateIdentity();
      const spk = createSignedPreKey(bob.signing.privateKey, 1);
      const opk = withOpk ? createOneTimePreKey(2) : null;
      const x = x3dhInitiator(alice.ik, bob.ik.publicKey, spk.keyPair.publicKey, opk?.keyPair.publicKey ?? null);
      const skB = x3dhResponder(
        bob.ik.privateKey,
        spk.keyPair.privateKey,
        opk?.keyPair.privateKey ?? null,
        alice.ik.publicKey,
        x.ephemeralKey.publicKey,
      );
      expect(Buffer.from(x.sharedKey).equals(Buffer.from(skB))).toBe(true);
      expect(x.sharedKey.length).toBe(32);
    }
  });

  it('SK diferente com prekeys diferentes', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const spk1 = createSignedPreKey(bob.signing.privateKey, 1);
    const spk2 = createSignedPreKey(bob.signing.privateKey, 2);
    const x1 = x3dhInitiator(alice.ik, bob.ik.publicKey, spk1.keyPair.publicKey, null);
    const x2 = x3dhInitiator(alice.ik, bob.ik.publicKey, spk2.keyPair.publicKey, null);
    expect(Buffer.from(x1.sharedKey).equals(Buffer.from(x2.sharedKey))).toBe(false);
  });
});

describe('prekeys', () => {
  it('verifies the signed prekey signature and rejects tampering', () => {
    const id = generateIdentity();
    const s = createSignedPreKey(id.signing.privateKey, 11);
    expect(verifySignedPreKey(id.signing.publicKey, s.keyId, s.keyPair.publicKey, s.signature)).toBe(true);
    const bad = s.keyPair.publicKey.slice();
    bad[0]! ^= 1;
    expect(verifySignedPreKey(id.signing.publicKey, s.keyId, bad, s.signature)).toBe(false);
    expect(verifySignedPreKey(id.signing.publicKey, s.keyId + 1, s.keyPair.publicKey, s.signature)).toBe(false);
  });
});

describe('AEAD', () => {
  it('roundtrip with AD and failure with the wrong AD', () => {
    const ikA = new Uint8Array(32).fill(1);
    const ikB = new Uint8Array(32).fill(2);
    const mk = new Uint8Array(32).fill(7);
    const ad = buildAdBase(ikA, ikB);
    const ct = aeadEncrypt(mk, utf8Encode('segredo'), ad);
    expect(new TextDecoder().decode(aeadDecrypt(mk, ct, ad))).toBe('segredo');
    const adBad = buildAdBase(ikB, ikA);
    expect(() => aeadDecrypt(mk, ct, adBad)).toThrow();
  });
});

describe('safety number', () => {
  it('same value on both sides, 12 groups of 5 digits', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const aPub = Buffer.from(alice.ik.publicKey).toString('base64');
    const bPub = Buffer.from(bob.ik.publicKey).toString('base64');
    const s1 = safetyNumber(aPub, bPub);
    const s2 = safetyNumber(bPub, aPub);
    expect(s1.digits).toBe(s2.digits);
    expect(s1.groups.length).toBe(12);
    for (const g of s1.groups) expect(/^\d{5}$/.test(g)).toBe(true);
    // identidade trocada → fingerprint diferente
    const other = generateIdentity();
    const s3 = safetyNumber(aPub, Buffer.from(other.ik.publicKey).toString('base64'));
    expect(s3.digits).not.toBe(s1.digits);
  });
});

describe('deletion receipts', () => {
  it('server signature verifies and rejects tampering', () => {
    const server = generateIdentity();
    const r: Omit<DeletionReceipt, 'id' | 'sig'> = {
      messageId: 'msg-123',
      recipient: 'bob',
      deletedAt: 1730000000000,
      reason: 'burn',
    };
    const sig = signReceipt(server.signing.privateKey, r);
    const receipt: DeletionReceipt = { ...r, id: 'r1', sig: Buffer.from(sig).toString('base64') };
    expect(verifyReceipt(server.signing.publicKey, receipt)).toBe(true);
    const forged: DeletionReceipt = { ...receipt, deletedAt: receipt.deletedAt + 1 };
    expect(verifyReceipt(server.ik.publicKey, forged)).toBe(false);
    const wrongKey = generateIdentity();
    expect(verifyReceipt(wrongKey.signing.publicKey, receipt)).toBe(false);
  });
});
