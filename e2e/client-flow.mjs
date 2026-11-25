// E2E that mirrors exactly the logic of client/src/sessions.ts + api.ts
// against the real server: bundle, verify SPK, X3DH, ratchet, OPK refill,
// burn drop, receipts with signature verification.
import {
  b64ToBytes, bytesToB64, createOneTimePreKey, createSignedPreKey, DoubleRatchet,
  generateIdentity, randomUuid, utf8Decode, utf8Encode, verifyReceipt,
  verifySignedPreKey, x3dhInitiator, x3dhResponder, PROTOCOL_VERSION,
} from '../shared/dist/index.js';

const BASE = 'http://127.0.0.1:8080/api/v1';
async function j(method, path, body, token) {
  const res = await fetch(BASE + path, {
    method,
    headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: 'Bearer ' + token } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${JSON.stringify(data)}`);
  return data;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let passed = 0;
function ok(cond, label) { if (!cond) throw new Error('FAIL: ' + label); passed++; console.log('  ✓', label); }

async function register(name) {
  const id = generateIdentity();
  const spk = createSignedPreKey(id.signing.privateKey, Math.floor(Math.random() * 1e6) + 1);
  const opkBase = Math.floor(Math.random() * 1e6) + 2e6;
  const opks = Array.from({ length: 10 }, (_, i) => createOneTimePreKey(opkBase + i));
  const res = await j('POST', '/register', {
    username: name, password: 'strong-password-123',
    identityKey: bytesToB64(id.ik.publicKey),
    signingKey: bytesToB64(id.signing.publicKey),
    signedPreKey: { keyId: spk.keyId, publicKey: bytesToB64(spk.keyPair.publicKey), signature: bytesToB64(spk.signature) },
    oneTimePreKeys: opks.map((k) => ({ keyId: k.keyId, publicKey: bytesToB64(k.keyPair.publicKey) })),
  });
  return { ...id, spk, opks, opkCounter: opkBase + 10, username: name, token: res.token, serverKey: res.serverKey };
}

const suf = String(Date.now()).slice(-6);
const alice = await register('alice' + suf);
const bob = await register('bob' + suf);
console.log('registered:', alice.username, '&', bob.username);

// --- client-side OPK refill path (sessions.maybeRefillOpks) ---
const fresh = Array.from({ length: 10 }, (_, i) => createOneTimePreKey(alice.opkCounter + i));
const refill = await j('POST', '/keys/one-time', {
  oneTimePreKeys: fresh.map((k) => ({ keyId: k.keyId, publicKey: bytesToB64(k.keyPair.publicKey) })),
}, alice.token);
ok(refill.ok === true && refill.count >= 10, 'refill OPK accepted, count=' + refill.count);
let bad = await fetch(BASE + '/keys/one-time', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + alice.token }, body: JSON.stringify({ oneTimePreKeys: [{ keyId: 1, publicKey: 'not-base64!!' }] }) });
ok(bad.status === 400, 'refill rejects an invalid key (400)');

// --- first message flow (client sessions.sendMessage) ---
const bundle = await j('GET', '/users/' + bob.username + '/bundle', null, alice.token);
ok(bundle.oneTimePreKey !== null, 'bundle includes an OPK');
const spkOk = verifySignedPreKey(b64ToBytes(bundle.signingKey), bundle.signedPreKey.keyId,
  b64ToBytes(bundle.signedPreKey.publicKey), b64ToBytes(bundle.signedPreKey.signature));
ok(spkOk, 'SPK signature verified');
const x = x3dhInitiator(alice.ik, b64ToBytes(bundle.identityKey),
  b64ToBytes(bundle.signedPreKey.publicKey),
  bundle.oneTimePreKey ? b64ToBytes(bundle.oneTimePreKey.publicKey) : null);
const aSess = DoubleRatchet.initAlice(x.sharedKey, x.ephemeralKey, b64ToBytes(bundle.signedPreKey.publicKey),
  randomUuid(), alice.ik.publicKey, b64ToBytes(bundle.identityKey));
const { header, ct } = aSess.encrypt(utf8Encode('first message from the client flow'), 0);
const mid = randomUuid();
await j('POST', '/messages', {
  v: PROTOCOL_VERSION, id: mid, from: alice.username, to: bob.username,
  sik: bytesToB64(alice.ik.publicKey), spkId: bundle.signedPreKey.keyId,
  opkId: bundle.oneTimePreKey.keyId, header, ct: bytesToB64(ct), drop: null, sentAt: Date.now(),
}, alice.token);
ok(true, 'msg posted');

// --- bob polls the inbox and decrypts (client decryptIncoming: no session) ---
const inbox1 = await j('GET', '/messages?since=0', null, bob.token);
const wm = inbox1.messages.find((m) => m.id === mid);
ok(!!wm, 'bob received the msg on poll');
const bobOpk = bob.opks.find((k) => k.keyId === wm.opkId);
ok(!!bobOpk, 'bob has the consumed local OPK');
bob.opks.splice(bob.opks.indexOf(bobOpk), 1); // local consumption
const sk = x3dhResponder(bob.ik.privateKey, bob.spk.keyPair.privateKey,
  bobOpk.keyPair.privateKey, b64ToBytes(wm.sik), b64ToBytes(wm.header.dh));
const bSess = DoubleRatchet.initBob(sk, bob.spk.keyPair, randomUuid(), bob.ik.publicKey, b64ToBytes(wm.sik));
const text1 = utf8Decode(bSess.decrypt(wm.header, b64ToBytes(wm.ct)));
ok(text1 === 'first message from the client flow', 'bob decrypted the first msg');

// --- bob replies using the SAME session (client sendMessage with an existing session) ---
const { header: h2, ct: c2 } = bSess.encrypt(utf8Encode('reply with a persisted session'), 0);
const mid2 = randomUuid();
await j('POST', '/messages', {
  v: PROTOCOL_VERSION, id: mid2, from: bob.username, to: alice.username,
  sik: bytesToB64(bob.ik.publicKey), spkId: null, opkId: null,
  header: h2, ct: bytesToB64(c2), drop: null, sentAt: Date.now(),
}, bob.token);
const inbox2 = await j('GET', '/messages?since=0', null, alice.token);
const wm2 = inbox2.messages.find((m) => m.id === mid2);
ok(!!wm2, 'alice received the reply');
const text2 = utf8Decode(aSess.decrypt(wm2.header, b64ToBytes(wm2.ct)));
ok(text2 === 'reply with a persisted session', 'alice decrypted with the existing session');

// --- outbox reflects states ---
let outbox = await j('GET', '/outbox?since=0', null, alice.token);
const myRow = outbox.messages.find((r) => r.payload.id === mid);
ok(myRow && myRow.state === 'released', 'alice outbox shows the released msg');
ok(myRow.deletedAt === null, 'normal outbox has no deletedAt');

// --- immediate burn drop + verified receipt ---
const x3 = x3dhInitiator(alice.ik, b64ToBytes(bundle.identityKey),
  b64ToBytes(bundle.signedPreKey.publicKey), null);
const aS3 = DoubleRatchet.initAlice(x3.sharedKey, x3.ephemeralKey, b64ToBytes(bundle.signedPreKey.publicKey),
  randomUuid(), alice.ik.publicKey, b64ToBytes(bundle.identityKey));
const { header: h3, ct: c3 } = aS3.encrypt(utf8Encode('ephemeral drop 🔥'), 1);
const mid3 = randomUuid();
await j('POST', '/messages', {
  v: PROTOCOL_VERSION, id: mid3, from: alice.username, to: bob.username,
  sik: bytesToB64(alice.ik.publicKey), spkId: bundle.signedPreKey.keyId, opkId: null,
  header: h3, ct: bytesToB64(c3), drop: { releaseAt: null, timeoutDays: null, dms: false, burn: true, ttlDays: null },
  sentAt: Date.now(),
}, alice.token);
await sleep(11000); // scheduler (10s)
const inbox3 = await j('GET', '/messages?since=0', null, bob.token);
const wm3 = inbox3.messages.find((m) => m.id === mid3);
ok(!!wm3, 'burn drop released by the scheduler');
const ob3 = (await j('GET', '/outbox?since=0', null, alice.token)).messages.find((r) => r.payload.id === mid3);
ok(ob3 && ob3.state === 'released' && ob3.releasedAt !== null, 'burn drop outbox shows releasedAt');
const sk3 = x3dhResponder(bob.ik.privateKey, bob.spk.keyPair.privateKey, null,
  b64ToBytes(wm3.sik), b64ToBytes(wm3.header.dh));
const bS3 = DoubleRatchet.initBob(sk3, bob.spk.keyPair, randomUuid(), bob.ik.publicKey, b64ToBytes(wm3.sik));
ok(utf8Decode(bS3.decrypt(wm3.header, b64ToBytes(wm3.ct))) === 'ephemeral drop 🔥', 'bob decrypted the drop');
await j('POST', `/messages/${mid3}/read`, null, bob.token); // client markRead -> burn
await sleep(1500);
const rc = await j('GET', '/receipts?since=0', null, alice.token);
const burnRc = rc.receipts.find((r) => r.messageId === mid3);
ok(!!burnRc && burnRc.reason === 'burn', 'burn receipt generated for alice');
ok(verifyReceipt(b64ToBytes(alice.serverKey.publicKey), burnRc), 'receipt signature verifies (verifyReceipt)');

// --- explicit deletion by the recipient + receipt for the sender ---
await j('DELETE', `/messages/${mid2}`, null, alice.token); // alice (recipient) deletes
const rc2 = await j('GET', '/receipts?since=0', null, bob.token);
const delRc = rc2.receipts.find((r) => r.messageId === mid2);
ok(!!delRc && delRc.reason === 'explicit', 'explicit deletion receipt for the sender (bob)');
ok(verifyReceipt(b64ToBytes(bob.serverKey.publicKey), delRc), 'deletion receipt signature verifies');

// --- heartbeat (DMS) ---
await j('POST', '/heartbeat', {}, bob.token);
ok(true, 'heartbeat ok');

console.log(`\nCLIENT-FLOW E2E PASSED ✅ (${passed} checks)`);
