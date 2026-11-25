import {
  DoubleRatchet, PROTOCOL_VERSION, b64ToBytes, bytesToB64, createOneTimePreKey,
  randomUuid, utf8Decode, utf8Encode, verifySignedPreKey, x3dhInitiator, x3dhResponder,
  type DropMeta, type WireMessage,
} from '@deaddrop/shared';
import { api } from './api';
import { vault, type LocalMessage } from './vault';

/**
 * Orchestrates X3DH + Double Ratchet against the real API.
 *  - first msg to a peer: fetch the bundle, verify the SignedPreKey signature,
 *    x3dhInitiator + initAlice (EKA vira header.dh da 1a msg).
 *  - msgs seguintes: importState/encrypt/exportState (persistido no vault).
 *  - first msg received from an unknown peer: x3dhResponder + initBob,
 *    consumindo a OPK local correspondente (keyId da msg).
 */

/** Sessao de ratchet existente? */
export async function hasSession(peer: string): Promise<boolean> {
  return (await vault.getSession(peer)) !== null;
}

/** Verifies the bundle SPK signature (MITM defense over prekeys). */
export function verifyBundle(bundle: Awaited<ReturnType<typeof api.bundle>>): void {
  const ok = verifySignedPreKey(
    b64ToBytes(bundle.signingKey),
    bundle.signedPreKey.keyId,
    b64ToBytes(bundle.signedPreKey.publicKey),
    b64ToBytes(bundle.signedPreKey.signature),
  );
  if (!ok) throw new Error('Invalid SignedPreKey signature — tampered bundle (possible MITM)');
}

/** Reloads local OPKs (<=2 left) through the new server endpoint. */
export async function maybeRefillOpks(token: string): Promise<void> {
  const id = await vault.getIdentity();
  if (!id) return;
  if (id.opks.length > 2) return;
  const fresh = Array.from({ length: 10 }, (_, i) => createOneTimePreKey(id.opkCounter + i));
  await api.refillOneTimeKeys(
    fresh.map((k) => ({ keyId: k.keyId, publicKey: bytesToB64(k.keyPair.publicKey) })),
    token,
  );
  id.opks.push(...fresh.map((k) => ({
    keyId: k.keyId,
    priv: bytesToB64(k.keyPair.privateKey),
    pub: bytesToB64(k.keyPair.publicKey),
  })));
  id.opkCounter += 10;
  await vault.setIdentity(id);
}

export interface SendResult {
  message: LocalMessage;
  wire: WireMessage;
}

/** Sends text (normal or drop) to a peer, creating/advancing the session. */
export async function sendMessage(
  peer: string,
  text: string,
  drop: DropMeta | null,
  username: string,
  token: string,
): Promise<SendResult> {
  const id = await vault.getIdentity();
  if (!id) throw new Error('Identity not loaded');
  const kind = drop ? 'drop' : 'normal';

  let session = await vault.getSession(peer);
  let spkId: number | null = null;
  let opkId: number | null = null;

  let ratchet: DoubleRatchet;
  if (session) {
    ratchet = DoubleRatchet.importState(session.state);
  } else {
    const bundle = await api.bundle(peer, token);
    verifyBundle(bundle);
    const x = x3dhInitiator(
      { privateKey: b64ToBytes(id.ikPriv), publicKey: b64ToBytes(id.ikPub) },
      b64ToBytes(bundle.identityKey),
      b64ToBytes(bundle.signedPreKey.publicKey),
      bundle.oneTimePreKey ? b64ToBytes(bundle.oneTimePreKey.publicKey) : null,
    );
    ratchet = DoubleRatchet.initAlice(
      x.sharedKey,
      x.ephemeralKey,
      b64ToBytes(bundle.signedPreKey.publicKey),
      randomUuid(),
      b64ToBytes(id.ikPub),
      b64ToBytes(bundle.identityKey),
    );
    spkId = bundle.signedPreKey.keyId;
    opkId = bundle.oneTimePreKey?.keyId ?? null;
  }

  const { header, ct } = ratchet.encrypt(utf8Encode(text), kind === 'drop' ? 1 : 0);
  const uuid = randomUuid();
  const wm: WireMessage = {
    v: PROTOCOL_VERSION,
    id: uuid,
    from: username,
    to: peer,
    sik: id.ikPub,
    spkId,
    opkId,
    header,
    ct: bytesToB64(ct),
    drop,
    sentAt: Date.now(),
  };

  const res = await api.postMessage(wm, token);
  await vault.putSession(peer, {
    state: ratchet.exportState(),
    peerIk: session?.peerIk ?? (await vault.getContact(peer))?.identityKey ?? '',
    updatedAt: Date.now(),
  });

  const message: LocalMessage = {
    uuid,
    peer,
    direction: 'out',
    kind,
    text,
    sentAt: wm.sentAt,
    dropMeta: drop,
    status: res.state === 'queued' ? 'queued' : 'released',
    releasedAt: res.state === 'queued' ? null : wm.sentAt,
  };
  await vault.putMessage(message);
  return { message, wire: wm };
}

/** Decrypts a received message (creates a session via x3dhResponder if needed). */
export async function decryptIncoming(wm: WireMessage): Promise<LocalMessage> {
  const id = await vault.getIdentity();
  if (!id) throw new Error('Identity not loaded');

  let ratchet: DoubleRatchet;
  const session = await vault.getSession(wm.from);
  if (session) {
    ratchet = DoubleRatchet.importState(session.state);
  } else {
    // first message: rebuilds the SK via the X3DH responder. Consumes the local OPK if used.
    let opkPriv: Uint8Array | null = null;
    if (wm.opkId !== null) {
      const idx = id.opks.findIndex((k) => k.keyId === wm.opkId);
      if (idx >= 0) {
        opkPriv = b64ToBytes(id.opks[idx]!.priv);
        id.opks.splice(idx, 1);
        await vault.setIdentity(id);
      }
    }
    const sk = x3dhResponder(
      b64ToBytes(id.ikPriv),
      b64ToBytes(id.spk.priv),
      opkPriv,
      b64ToBytes(wm.sik),
      b64ToBytes(wm.header.dh),
    );
    ratchet = DoubleRatchet.initBob(
      sk,
      { privateKey: b64ToBytes(id.spk.priv), publicKey: b64ToBytes(id.spk.pub) },
      randomUuid(),
      b64ToBytes(id.ikPub),
      b64ToBytes(wm.sik),
    );
  }

  let plain: string;
  try {
    plain = utf8Decode(ratchet.decrypt(wm.header, b64ToBytes(wm.ct)));
  } catch (e) {
    throw new Error(`Failed to decrypt: ${(e as Error).message}`);
  }

  await vault.putSession(wm.from, {
    state: ratchet.exportState(),
    peerIk: wm.sik,
    updatedAt: Date.now(),
  });

  const message: LocalMessage = {
    uuid: wm.id,
    peer: wm.from,
    direction: 'in',
    kind: wm.drop ? 'drop' : 'normal',
    text: plain,
    sentAt: wm.sentAt,
    dropMeta: wm.drop,
    status: 'released',
  };
  await vault.putMessage(message);
  return message;
}
