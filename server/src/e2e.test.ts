/**
 * E2E: real Fastify server (Store on temp SQLite) + shared crypto.
 * Cobre: registro, bundle/SPK, X3DH + Double Ratchet bidirecional,
 * heartbeat, DELETE with a signed receipt, burn drop with the scheduler,
 * and notifications over WebSocket (message + receipt).
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import Fastify from 'fastify';
import websocket from '@fastify/websocket';
import WebSocket from 'ws';
import { ed25519 } from '@noble/curves/ed25519';
import {
  generateEd25519, generateIdentity, createSignedPreKey, createOneTimePreKey,
  bytesToB64, b64ToBytes, utf8Encode, utf8Decode, randomUuid,
  x3dhInitiator, x3dhResponder, DoubleRatchet, verifySignedPreKey, verifyReceipt,
  type DeletionReceipt, type WireMessage,
} from '@deaddrop/shared';
import { Store } from './store.js';
import { buildApi } from './api.js';
import { registerWs } from './ws.js';
import { startDropScheduler } from './drops.js';

const MSG = 'hi bob, this is secret 🔒';
const REPLY = 'received! also secret';
const DROP_MSG = 'ephemeral message';

let app: ReturnType<typeof Fastify>;
let store: Store;
let baseUrl = '';
let scheduler: { stop: () => void };
let tmpDir = '';

// ---- helpers -----------------------------------------------------------

async function j<T = unknown>(method: string, p: string, body?: unknown, token?: string): Promise<T> {
  const res = await fetch(baseUrl + p, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: 'Bearer ' + token } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = (await res.json()) as T & { error?: string };
  if (!res.ok) throw new Error(`${method} ${p} -> ${res.status}: ${JSON.stringify(data)}`);
  return data;
}

interface Actor {
  username: string;
  token: string;
  serverKeyPub: string;
  ik: { publicKey: Uint8Array; privateKey: Uint8Array };
  spk: { keyId: number; keyPair: { publicKey: Uint8Array; privateKey: Uint8Array } };
  opks: { keyId: number; keyPair: { publicKey: Uint8Array; privateKey: Uint8Array } }[];
}

async function register(name: string): Promise<Actor> {
  const id = generateIdentity();
  const spk = createSignedPreKey(id.signing.privateKey, Math.floor(Math.random() * 100000));
  const opks = Array.from({ length: 10 }, (_, i) => createOneTimePreKey(1000 + i));
  const res = await j<{ token: string; serverKey: { publicKey: string } }>('POST', '/api/v1/register', {
    username: name,
    password: 'strong-password-123',
    identityKey: bytesToB64(id.ik.publicKey),
    signingKey: bytesToB64(id.signing.publicKey),
    signedPreKey: {
      keyId: spk.keyId,
      publicKey: bytesToB64(spk.keyPair.publicKey),
      signature: bytesToB64(spk.signature),
    },
    oneTimePreKeys: opks.map((k) => ({ keyId: k.keyId, publicKey: bytesToB64(k.keyPair.publicKey) })),
  });
  return {
    username: name,
    token: res.token,
    serverKeyPub: res.serverKey.publicKey,
    ik: id.ik,
    spk,
    opks,
  };
}

interface InboxResp { messages: WireMessage[]; lastId: number }
interface ReceiptsResp { receipts: DeletionReceipt[]; lastId: number }

function wsConnect(token: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${baseUrl.replace('http', 'ws')}/ws?token=${token}`);
    ws.once('open', () => {
      // resolves as soon as 'hello' arrives, so later events are not lost
      ws.once('message', (raw: Buffer) => {
        const ev = JSON.parse(raw.toString());
        if (ev.type === 'hello') resolve(ws);
        else reject(new Error(`esperava hello, recebi ${JSON.stringify(ev)}`));
      });
    });
    ws.once('error', reject);
  });
}

function waitForEvent(ws: WebSocket, type: string, timeoutMs = 3000): Promise<any> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      ws.off('message', onMsg);
      reject(new Error(`timeout aguardando evento '${type}'`));
    }, timeoutMs);
    const onMsg = (raw: Buffer) => {
      const ev = JSON.parse(raw.toString());
      if (ev.type === type) {
        clearTimeout(timer);
        resolve(ev);
      }
    };
    ws.on('message', onMsg);
  });
}

// ---- setup -------------------------------------------------------------

beforeAll(async () => {
  tmpDir = mkdtempSync(path.join(tmpdir(), 'deaddrop-e2e-'));
  store = new Store(path.join(tmpDir, 'test.db'));

  const kp = generateEd25519();
  store.createServerKey(Math.floor(Date.now() / 1000), bytesToB64(ed25519.getPublicKey(kp.privateKey)), Date.now());

  app = Fastify({ logger: false });
  await app.register(websocket);
  const { notify } = registerWs(app, store);
  buildApi(app, store, kp.privateKey, notify);
  scheduler = startDropScheduler(store, kp.privateKey, notify, 250);

  await app.listen({ port: 0, host: '127.0.0.1' });
  const addr = app.server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  scheduler.stop();
  await app.close();
  store.close();
  rmSync(tmpDir, { recursive: true, force: true });
});

// ---- tests ------------------------------------------------------------

describe('E2E Alice-Bob (REST)', () => {
  it('registro -> bundle -> X3DH/ratchet bidirecional -> heartbeat -> DELETE receipt -> drop burn', async () => {
    const alice = await register('alice');
    const bob = await register('bob');
    expect(alice.token).toHaveLength(64);
    expect(bob.token).toHaveLength(64);

    // bob's bundle (the GET consumes an OPK)
    const bundle = await j<{
      identityKey: string; signingKey: string;
      signedPreKey: { keyId: number; publicKey: string; signature: string };
      oneTimePreKey: { keyId: number; publicKey: string } | null;
    }>('GET', '/api/v1/users/bob/bundle', null, alice.token);
    expect(bundle.oneTimePreKey).not.toBeNull();
    expect(
      verifySignedPreKey(
        b64ToBytes(bundle.signingKey),
        bundle.signedPreKey.keyId,
        b64ToBytes(bundle.signedPreKey.publicKey),
        b64ToBytes(bundle.signedPreKey.signature),
      ),
    ).toBe(true);

    // --- alice -> bob (first msg, new X3DH session) ---
    const x = x3dhInitiator(
      alice.ik,
      b64ToBytes(bundle.identityKey),
      b64ToBytes(bundle.signedPreKey.publicKey),
      bundle.oneTimePreKey ? b64ToBytes(bundle.oneTimePreKey.publicKey) : null,
    );
    const aSess = DoubleRatchet.initAlice(
      x.sharedKey, x.ephemeralKey,
      b64ToBytes(bundle.signedPreKey.publicKey),
      randomUuid(), alice.ik.publicKey, b64ToBytes(bundle.identityKey),
    );
    const { header: h1, ct: c1 } = aSess.encrypt(utf8Encode(MSG), 0);
    const mid1 = randomUuid();
    await j('POST', '/api/v1/messages', {
      v: 1, id: mid1, from: 'alice', to: 'bob',
      sik: bytesToB64(alice.ik.publicKey),
      spkId: bundle.signedPreKey.keyId,
      opkId: bundle.oneTimePreKey ? bundle.oneTimePreKey.keyId : null,
      header: h1, ct: bytesToB64(c1), drop: null, sentAt: Date.now(),
    }, alice.token);

    // bob decifra
    const inbox1 = await j<InboxResp>('GET', '/api/v1/messages', null, bob.token);
    const m1 = inbox1.messages.find((m) => m.id === mid1);
    expect(m1).toBeDefined();
    const bobOpk = bob.opks.find((k) => k.keyId === m1!.opkId);
    const skBob = x3dhResponder(
      bob.ik.privateKey, bob.spk.keyPair.privateKey,
      bobOpk ? bobOpk.keyPair.privateKey : null,
      b64ToBytes(m1!.sik), b64ToBytes(m1!.header.dh),
    );
    const bSess = DoubleRatchet.initBob(skBob, bob.spk.keyPair, randomUuid(), bob.ik.publicKey, b64ToBytes(m1!.sik));
    expect(utf8Decode(bSess.decrypt(m1!.header, b64ToBytes(m1!.ct)))).toBe(MSG);

    // --- bob -> alice (ratchet advances) ---
    const { header: h2, ct: c2 } = bSess.encrypt(utf8Encode(REPLY), 0);
    const mid2 = randomUuid();
    await j('POST', '/api/v1/messages', {
      v: 1, id: mid2, from: 'bob', to: 'alice',
      sik: bytesToB64(bob.ik.publicKey), spkId: null, opkId: null,
      header: h2, ct: bytesToB64(c2), drop: null, sentAt: Date.now(),
    }, bob.token);
    const inboxA = await j<InboxResp>('GET', '/api/v1/messages', null, alice.token);
    const m2 = inboxA.messages.find((m) => m.id === mid2);
    expect(m2).toBeDefined();
    expect(utf8Decode(aSess.decrypt(m2!.header, b64ToBytes(m2!.ct)))).toBe(REPLY);

    // heartbeat + DELETE com receipt assinado (alice apaga msg do bob)
    await j('POST', '/api/v1/heartbeat', {}, bob.token);
    await j('DELETE', `/api/v1/messages/${mid2}`, null, alice.token);
    const receipts = await j<ReceiptsResp>('GET', '/api/v1/receipts', null, bob.token);
    expect(receipts.receipts).toHaveLength(1);
    expect(receipts.receipts[0]!.reason).toBe('explicit');
    expect(receipts.receipts[0]!.messageId).toBe(mid2);
    expect(verifyReceipt(b64ToBytes(alice.serverKeyPub), receipts.receipts[0]!)).toBe(true);

    // --- burn drop: NEW X3DH session without OPK, mtype=1, queued -> scheduler releases ---
    const x2 = x3dhInitiator(
      alice.ik, b64ToBytes(bundle.identityKey), b64ToBytes(bundle.signedPreKey.publicKey), null,
    );
    const aS2 = DoubleRatchet.initAlice(
      x2.sharedKey, x2.ephemeralKey, b64ToBytes(bundle.signedPreKey.publicKey),
      randomUuid(), alice.ik.publicKey, b64ToBytes(bundle.identityKey),
    );
    const { header: h3, ct: c3 } = aS2.encrypt(utf8Encode(DROP_MSG), 1);
    const mid3 = randomUuid();
    await j('POST', '/api/v1/messages', {
      v: 1, id: mid3, from: 'alice', to: 'bob',
      sik: bytesToB64(alice.ik.publicKey),
      spkId: bundle.signedPreKey.keyId, opkId: null,
      header: h3, ct: bytesToB64(c3), sentAt: Date.now(),
      drop: { releaseAt: null, timeoutDays: null, dms: false, burn: true, ttlDays: null },
    }, alice.token);

    // still queued -> does NOT appear in the inbox
    const inboxQ = await j<InboxResp>('GET', '/api/v1/messages', null, bob.token);
    expect(inboxQ.messages.find((m) => m.id === mid3)).toBeUndefined();

    // scheduler (250ms) releases -> bob derives a new session from the message material
    let m3: WireMessage | undefined;
    await vi.waitFor(async () => {
      const inb = await j<InboxResp>('GET', '/api/v1/messages', null, bob.token);
      m3 = inb.messages.find((m) => m.id === mid3);
      expect(m3).toBeDefined();
    }, { timeout: 3000, interval: 100 });

    const sk3 = x3dhResponder(
      bob.ik.privateKey, bob.spk.keyPair.privateKey, null,
      b64ToBytes(m3!.sik), b64ToBytes(m3!.header.dh),
    );
    const bS3 = DoubleRatchet.initBob(sk3, bob.spk.keyPair, randomUuid(), bob.ik.publicKey, b64ToBytes(m3!.sik));
    expect(utf8Decode(bS3.decrypt(m3!.header, b64ToBytes(m3!.ct)))).toBe(DROP_MSG);

    // burn: ler apaga e gera receipt 'burn' para o remetente
    await j('POST', `/api/v1/messages/${mid3}/read`, null, bob.token);
    const receipts2 = await j<ReceiptsResp>('GET', '/api/v1/receipts', null, alice.token);
    const burnRec = receipts2.receipts.at(-1);
    expect(burnRec?.reason).toBe('burn');
    expect(burnRec?.messageId).toBe(mid3);
    expect(verifyReceipt(b64ToBytes(alice.serverKeyPub), burnRec!)).toBe(true);
    // message disappeared from bob's inbox after the burn
    const inboxF = await j<InboxResp>('GET', '/api/v1/messages', null, bob.token);
    expect(inboxF.messages.find((m) => m.id === mid3)).toBeUndefined();
  });
});

describe('E2E WebSocket (notifications)', () => {
  it('hello, message event on delivery and receipt event on delete', async () => {
    const wsalice = await register('wsalice');
    const wsbob = await register('wsbob');

    const wsA = await wsConnect(wsalice.token); // resolve no 'hello'
    const wsB = await wsConnect(wsbob.token);

    // wsbob inicia sessao com wsalice
    const bundleA = await j<{
      identityKey: string;
      signedPreKey: { keyId: number; publicKey: string };
      oneTimePreKey: { keyId: number; publicKey: string } | null;
    }>('GET', '/api/v1/users/wsalice/bundle', null, wsbob.token);
    const y = x3dhInitiator(
      wsbob.ik, b64ToBytes(bundleA.identityKey), b64ToBytes(bundleA.signedPreKey.publicKey),
      bundleA.oneTimePreKey ? b64ToBytes(bundleA.oneTimePreKey.publicKey) : null,
    );
    const bSess = DoubleRatchet.initAlice(
      y.sharedKey, y.ephemeralKey, b64ToBytes(bundleA.signedPreKey.publicKey),
      randomUuid(), wsbob.ik.publicKey, b64ToBytes(bundleA.identityKey),
    );
    const { header, ct } = bSess.encrypt(utf8Encode('via websocket 👋'), 0);
    const mid = randomUuid();

    // alice aguarda a notificacao
    const evMsgP = waitForEvent(wsA, 'message');
    await j('POST', '/api/v1/messages', {
      v: 1, id: mid, from: 'wsbob', to: 'wsalice',
      sik: bytesToB64(wsbob.ik.publicKey),
      spkId: bundleA.signedPreKey.keyId,
      opkId: bundleA.oneTimePreKey ? bundleA.oneTimePreKey.keyId : null,
      header, ct: bytesToB64(ct), drop: null, sentAt: Date.now(),
    }, wsbob.token);

    const evMsg = await evMsgP;
    expect(evMsg.data.uuid).toBe(mid);

    // wsalice busca, decifra e apaga -> wsbob recebe receipt
    const inboxA = await j<InboxResp>('GET', '/api/v1/messages', null, wsalice.token);
    const m = inboxA.messages.find((x) => x.id === mid);
    expect(m).toBeDefined();
    const opkA = wsalice.opks.find((k) => k.keyId === m!.opkId);
    const skA = x3dhResponder(
      wsalice.ik.privateKey, wsalice.spk.keyPair.privateKey,
      opkA ? opkA.keyPair.privateKey : null,
      b64ToBytes(m!.sik), b64ToBytes(m!.header.dh),
    );
    const aSess = DoubleRatchet.initBob(skA, wsalice.spk.keyPair, randomUuid(), wsalice.ik.publicKey, b64ToBytes(m!.sik));
    expect(utf8Decode(aSess.decrypt(m!.header, b64ToBytes(m!.ct)))).toBe('via websocket 👋');

    const evRecP = waitForEvent(wsB, 'receipt');
    await j('DELETE', `/api/v1/messages/${mid}`, null, wsalice.token);
    const evRec = await evRecP;
    expect(evRec.data.messageId).toBe(mid);
    expect(evRec.data.reason).toBe('explicit');
    expect(verifyReceipt(b64ToBytes(wsbob.serverKeyPub), evRec.data as DeletionReceipt)).toBe(true);

    wsA.close();
    wsB.close();
  });
});
