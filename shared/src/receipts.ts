import { verifyBytes, signBytes } from './keys.js';
import { sha256Bytes } from './hkdf.js';
import { concatBytes, utf8Encode, bytesToB64, b64ToBytes } from './util.js';
import type { DeletionReceipt } from './types.js';

const RECEIPT_INFO = utf8Encode('DeadDrop-DeletionReceipt-v1');

/** Server-signed blob: canonical hash of (messageId, recipient, deletedAt, reason). */
export function receiptSigningBlob(r: Omit<DeletionReceipt, 'id' | 'sig'>): Uint8Array {
  const mid = utf8Encode(r.messageId);
  const rec = utf8Encode(r.recipient);
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(Math.trunc(r.deletedAt)), false);
  const reason = utf8Encode(r.reason);
  return sha256Bytes(concatBytes(RECEIPT_INFO, mid, rec, ts, reason));
}

export function signReceipt(serverSigningPriv: Uint8Array, r: Omit<DeletionReceipt, 'id' | 'sig'>): Uint8Array {
  return signBytes(serverSigningPriv, receiptSigningBlob(r));
}

/** Verifies the server's Ed25519 signature over the receipt. */
export function verifyReceipt(serverPub: Uint8Array, receipt: DeletionReceipt): boolean {
  const { sig, id, ...rest } = receipt;
  return verifyBytes(serverPub, b64ToBytes(sig), receiptSigningBlob(rest));
}
