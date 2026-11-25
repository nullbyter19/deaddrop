import { x25519 } from '@noble/curves/ed25519';
import { concatBytes } from './util.js';
import { hkdfSha256, hmacSha256, ZERO_SALT, INFO_RK } from './hkdf.js';
import { aeadDecrypt, aeadEncrypt, buildAdBase } from './cipher.js';
import { generateX25519, type X25519KeyPair } from './keys.js';
import { MAX_SKIP, type WireHeader } from './types.js';

/**
 * Double Ratchet (Signal) — faithful to the official pseudocode.
 * KDF_RK(rk, dh_out) = HKDF-SHA256(ikm=dh_out, salt=rk, info="DeadDrop-RK-v1", len=32)
 * KDF_CK(ck): mk = HMAC(ck, 0x01); ck' = HMAC(ck, 0x02)
 * AD = CONCAT(AD_base, header-binary)
 */

interface ChainState {
  ck: Uint8Array;
  n: number;
}
export interface RatchetState {
  rk: Uint8Array;
  cks: ChainState | null; // sending chain
  ckr: ChainState | null; // receiving chain
  dhs: X25519KeyPair;     // nossa DH ratchet atual
  dhr: Uint8Array | null; // DH ratchet do peer
  pn: number;
  mkskipped: Map<string, Uint8Array>; // key: `${dhB64}:${n}`
  sessionId: string;
  lastRemoteRatchetPub: Uint8Array | null;
}

export class DoubleRatchet {
  private st: RatchetState;
  private ownIk: Uint8Array;   // identity public nossa
  private peerIk: Uint8Array;  // identity public do peer

  private constructor(st: RatchetState, ownIk: Uint8Array, peerIk: Uint8Array) {
    this.st = st;
    this.ownIk = ownIk;
    this.peerIk = peerIk;
  }

  /** Alice: starts with the X3DH SK. The ephemeral key EKA becomes the first dhs (it appears in header.dh of the first message, letting Bob rebuild the SK via x3dhResponder). */
  static initAlice(sk: Uint8Array, ephemeral: X25519KeyPair, bobDhPublic: Uint8Array, sessionId: string, ownIk: Uint8Array, peerIk: Uint8Array): DoubleRatchet {
    const dhs = ephemeral;
    const rk = kdfRk(sk, x25519.getSharedSecret(dhs.privateKey, bobDhPublic));
    return new DoubleRatchet(
      {
        rk,
        cks: { ck: rk, n: 0 },
        ckr: null,
        dhs,
        dhr: bobDhPublic,
        pn: 0,
        mkskipped: new Map(),
        sessionId,
        lastRemoteRatchetPub: null,
      },
      ownIk,
      peerIk,
    );
  }

  /** Bob (responder): DHs = signed prekey; RK = SK do X3DH. */
  static initBob(sk: Uint8Array, bobSignedPreKey: X25519KeyPair, sessionId: string, ownIk: Uint8Array, peerIk: Uint8Array): DoubleRatchet {
    return new DoubleRatchet(
      {
        rk: sk,
        cks: null,
        ckr: null,
        dhs: bobSignedPreKey,
        dhr: null,
        pn: 0,
        mkskipped: new Map(),
        sessionId,
        lastRemoteRatchetPub: null,
      },
      ownIk,
      peerIk,
    );
  }

  get stateForDebug(): Readonly<RatchetState> { return this.st; }

  encrypt(plaintext: Uint8Array, mtype: number): { header: WireHeader; ct: Uint8Array } {
    if (!this.st.cks) throw new Error('no sending chain');
    const { mk, ck } = kdfCk(this.st.cks.ck);
    this.st.cks = { ck, n: this.st.cks.n };
    const header: WireHeader = {
      dh: b64(this.st.dhs.publicKey),
      pn: this.st.pn,
      ns: this.st.cks.n,
      n: this.st.cks.n,
      mtype,
    };
    this.st.cks.n += 1;
    const ad = buildAd(this.ownIk, this.peerIk, header);
    const ct = aeadEncrypt(mk, plaintext, ad);
    return { header, ct };
  }

  decrypt(header: WireHeader, ciphertext: Uint8Array): Uint8Array {
    const dhBytes = unB64(header.dh);

    // 1. Tenta message keys puladas
    const skipped = this.trySkipped(header, ciphertext);
    if (skipped !== null) return skipped;

    // 2. Se DH do header != DHr → DHRatchet
    if (!this.st.dhr || !bytesEq(dhBytes, this.st.dhr)) {
      this.skipMessageKeys(header.pn);
      this.dhRatchet(header);
    }
    this.skipMessageKeys(header.n);

    // 3. Advance the receiving chain
    if (!this.st.ckr) throw new Error('no receiving chain');
    const { mk, ck } = kdfCk(this.st.ckr.ck);
    this.st.ckr = { ck, n: this.st.ckr.n };
    this.st.ckr.n += 1;
    const ad = buildAd(this.peerIk, this.ownIk, header);
    return aeadDecrypt(mk, ciphertext, ad);
  }

  private dhRatchet(header: WireHeader): void {
    const dhBytes = unB64(header.dh);
    this.st.pn = this.st.cks ? this.st.cks.n : 0;
    this.st.cks = null;
    this.st.ckr = null;
    this.st.dhr = dhBytes;
    this.st.lastRemoteRatchetPub = dhBytes;
    this.st.rk = kdfRk(this.st.rk, x25519.getSharedSecret(this.st.dhs.privateKey, dhBytes));
    this.st.ckr = { ck: this.st.rk, n: 0 };
    this.st.dhs = generateX25519();
    this.st.rk = kdfRk(this.st.rk, x25519.getSharedSecret(this.st.dhs.privateKey, dhBytes));
    this.st.cks = { ck: this.st.rk, n: 0 };
  }

  private skipMessageKeys(until: number): void {
    if (!this.st.ckr) return;
    if (this.st.ckr.n + MAX_SKIP < until) throw new Error('too many skipped keys');
    while (this.st.ckr.n < until) {
      const { mk, ck } = kdfCk(this.st.ckr.ck);
      this.st.mkskipped.set(`${b64(this.st.dhr!)}:${this.st.ckr.n}`, mk);
      this.st.ckr = { ck, n: this.st.ckr.n + 1 };
    }
  }

  private trySkipped(header: WireHeader, ciphertext: Uint8Array): Uint8Array | null {
    const key = `${header.dh}:${header.n}`;
    const mk = this.st.mkskipped.get(key);
    if (!mk) return null;
    this.st.mkskipped.delete(key);
    const ad = buildAd(this.peerIk, this.ownIk, header);
    return aeadDecrypt(mk, ciphertext, ad);
  }

  /** Compacta estado para persistencia (serializavel JSON). */
  exportState(): Record<string, unknown> {
    return {
      sessionId: this.st.sessionId,
      rk: b64(this.st.rk),
      dhsPriv: b64(this.st.dhs.privateKey),
      dhsPub: b64(this.st.dhs.publicKey),
      dhr: this.st.dhr ? b64(this.st.dhr) : null,
      pn: this.st.pn,
      cks: this.st.cks ? { ck: b64(this.st.cks.ck), n: this.st.cks.n } : null,
      ckr: this.st.ckr ? { ck: b64(this.st.ckr.ck), n: this.st.ckr.n } : null,
      skipped: Array.from(this.st.mkskipped.entries()),
      lastRemoteRatchetPub: this.st.lastRemoteRatchetPub ? b64(this.st.lastRemoteRatchetPub) : null,
      ownIk: b64(this.ownIk),
      peerIk: b64(this.peerIk),
    };
  }

  static importState(raw: Record<string, unknown>): DoubleRatchet {
    const st: RatchetState = {
      sessionId: raw.sessionId as string,
      rk: unB64(raw.rk as string),
      dhs: { privateKey: unB64(raw.dhsPriv as string), publicKey: unB64(raw.dhsPub as string) },
      dhr: raw.dhr ? unB64(raw.dhr as string) : null,
      pn: raw.pn as number,
      cks: raw.cks ? { ck: unB64((raw.cks as { ck: string }).ck), n: (raw.cks as { n: number }).n } : null,
      ckr: raw.ckr ? { ck: unB64((raw.ckr as { ck: string }).ck), n: (raw.ckr as { n: number }).n } : null,
      mkskipped: new Map((raw.skipped as [string, string][]).map(([k, v]) => [k, unB64(v)])),
      lastRemoteRatchetPub: raw.lastRemoteRatchetPub ? unB64(raw.lastRemoteRatchetPub as string) : null,
    };
    return new DoubleRatchet(st, unB64(raw.ownIk as string), unB64(raw.peerIk as string));
  }
}

// ---- primitivas ----

function kdfRk(rk: Uint8Array, dhOut: Uint8Array): Uint8Array {
  return hkdfSha256(dhOut, rk, INFO_RK, 32);
}
function kdfCk(ck: Uint8Array): { mk: Uint8Array; ck: Uint8Array } {
  const mk = hmacSha256(ck, new Uint8Array([0x01]));
  const next = hmacSha256(ck, new Uint8Array([0x02]));
  return { mk, ck: next };
}
function buildAd(senderIk: Uint8Array, recipientIk: Uint8Array, header: WireHeader): Uint8Array {
  return concatBytes(senderIk, recipientIk, encodeHeader(header));
}
/** Canonical binary header: v(1) mtype(1) dh(32) pn(4) ns(4) n(4) = 46 bytes. */
export function encodeHeader(h: WireHeader): Uint8Array {
  const out = new Uint8Array(46);
  out[0] = 1;
  out[1] = h.mtype & 0xff;
  out.set(unB64(h.dh), 2);
  const dv = new DataView(out.buffer);
  dv.setUint32(34, h.pn >>> 0, false);
  dv.setUint32(38, h.ns >>> 0, false);
  dv.setUint32(42, h.n >>> 0, false);
  return out;
}
export function decodeHeader(b: Uint8Array): WireHeader {
  if (b.length !== 46 || b[0] !== 1) throw new Error('invalid header');
  const dv = new DataView(b.buffer, b.byteOffset, 46);
  return {
    dh: b64(b.slice(2, 34)),
    pn: dv.getUint32(34, false),
    ns: dv.getUint32(38, false),
    n: dv.getUint32(42, false),
    mtype: b[1]!,
  };
}
function b64(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!);
  return btoa(s);
}
function unB64(s: string): Uint8Array {
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
