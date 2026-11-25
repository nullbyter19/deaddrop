import { describe, it, expect } from 'vitest';
import { DoubleRatchet, encodeHeader, decodeHeader } from './ratchet.js';
import { x3dhInitiator, x3dhResponder } from './x3dh.js';
import { generateIdentity, createSignedPreKey, createOneTimePreKey, verifySignedPreKey, b64ToBytes } from './keys.js';
import { utf8Decode, utf8Encode, randomUuid } from './util.js';

function setupSessions() {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const spk = createSignedPreKey(bob.signing.privateKey, 7);
  const opk = createOneTimePreKey(42);
  // Alice verifies Bob's bundle
  expect(verifySignedPreKey(bob.signing.publicKey, spk.keyId, spk.keyPair.publicKey, spk.signature)).toBe(true);
  // X3DH
  const x = x3dhInitiator(alice.ik, bob.ik.publicKey, spk.keyPair.publicKey, opk.keyPair.publicKey);
  const skBob = x3dhResponder(bob.ik.privateKey, spk.keyPair.privateKey, opk.keyPair.privateKey, alice.ik.publicKey, x.ephemeralKey.publicKey);
  expect(Buffer.from(x.sharedKey).equals(Buffer.from(skBob))).toBe(true);
  const sid = randomUuid();
  const a = DoubleRatchet.initAlice(x.sharedKey, x.ephemeralKey, spk.keyPair.publicKey, sid, alice.ik.publicKey, bob.ik.publicKey);
  const b = DoubleRatchet.initBob(skBob, spk.keyPair, sid, bob.ik.publicKey, alice.ik.publicKey);
  return { a, b, alice, bob, spk, opk };
}

describe('Double Ratchet + X3DH', () => {
  it('troca bidirecional completa e ordenada', () => {
    const { a, b } = setupSessions();
    for (let i = 0; i < 5; i++) {
      const enc = a.encrypt(utf8Encode(`alice->bob ${i}`), 0);
      expect(utf8Decode(b.decrypt(enc.header, enc.ct))).toBe(`alice->bob ${i}`);
    }
    for (let i = 0; i < 3; i++) {
      const enc = b.encrypt(utf8Encode(`bob->alice ${i}`), 0);
      expect(utf8Decode(a.decrypt(enc.header, enc.ct))).toBe(`bob->alice ${i}`);
    }
  });

  it('ratchet advances DH on every reply (alternation)', () => {
    const { a, b } = setupSessions();
    const e1 = a.encrypt(utf8Encode('m1'), 0);
    b.decrypt(e1.header, e1.ct);
    const e2 = b.encrypt(utf8Encode('r1'), 0);
    a.decrypt(e2.header, e2.ct);
    const e3 = a.encrypt(utf8Encode('m2'), 0);
    b.decrypt(e3.header, e3.ct);
    const e4 = b.encrypt(utf8Encode('r2'), 0);
    a.decrypt(e4.header, e4.ct);
    expect(e1.header.dh).not.toBe(e3.header.dh);
    expect(e2.header.dh).not.toBe(e4.header.dh);
  });

  it('out-of-order delivery uses skipped message keys', () => {
    const { a, b } = setupSessions();
    const msgs = [a.encrypt(utf8Encode('m0'), 0), a.encrypt(utf8Encode('m1'), 0), a.encrypt(utf8Encode('m2'), 0)];
    expect(utf8Decode(b.decrypt(msgs[2]!.header, msgs[2]!.ct))).toBe('m2');
    expect(utf8Decode(b.decrypt(msgs[0]!.header, msgs[0]!.ct))).toBe('m0');
    expect(utf8Decode(b.decrypt(msgs[1]!.header, msgs[1]!.ct))).toBe('m1');
  });

  it('corrupted message fails with an error (authentication)', () => {
    const { a, b } = setupSessions();
    const enc = a.encrypt(utf8Encode('integro'), 0);
    const tampered = enc.ct.slice();
    tampered[5]! ^= 0xff;
    expect(() => b.decrypt(enc.header, tampered)).toThrow();
  });

  it('header codec roundtrip', () => {
    const { a, b } = setupSessions();
    const enc = a.encrypt(utf8Encode('codec'), 0);
    const bytes = encodeHeader(enc.header);
    expect(bytes.length).toBe(46);
    expect(decodeHeader(bytes)).toEqual(enc.header);
  });

  it('estado serializavel sobrevive a import/export', () => {
    const { a, b } = setupSessions();
    const e1 = a.encrypt(utf8Encode('persist'), 0);
    const b2 = DoubleRatchet.importState(b.exportState());
    expect(utf8Decode(b2.decrypt(e1.header, e1.ct))).toBe('persist');
    const a2 = DoubleRatchet.importState(a.exportState());
    const e2 = b2.encrypt(utf8Encode('volta'), 0);
    expect(utf8Decode(a2.decrypt(e2.header, e2.ct))).toBe('volta');
  });

  it('drop messages use mtype=1 in the header', () => {
    const { a, b } = setupSessions();
    const enc = a.encrypt(utf8Encode('drop-content'), 1);
    expect(enc.header.mtype).toBe(1);
    expect(utf8Decode(b.decrypt(enc.header, enc.ct))).toBe('drop-content');
  });
});
