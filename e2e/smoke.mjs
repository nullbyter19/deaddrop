import {
  generateIdentity, createSignedPreKey, createOneTimePreKey, bytesToB64, utf8Encode, utf8Decode,
  x3dhInitiator, x3dhResponder, DoubleRatchet, verifySignedPreKey, b64ToBytes, randomUuid,
} from '../shared/dist/index.js';

const BASE = 'http://127.0.0.1:8080/api/v1';
async function j(method, path, body, token) {
  const res = await fetch(BASE + path, {
    method, headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: 'Bearer ' + token } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${JSON.stringify(data)}`);
  return data;
}

// ---- register alice and bob ----
async function register(name) {
  const id = generateIdentity();
  const spk = createSignedPreKey(id.signing.privateKey, Math.floor(Math.random() * 100000));
  const opks = Array.from({ length: 10 }, (_, i) => createOneTimePreKey(1000 + i));
  const res = await j('POST', '/register', {
    username: name, password: 'strong-password-123',
    identityKey: bytesToB64(id.ik.publicKey),
    signingKey: bytesToB64(id.signing.publicKey),
    signedPreKey: { keyId: spk.keyId, publicKey: bytesToB64(spk.keyPair.publicKey), signature: bytesToB64(spk.signature) },
    oneTimePreKeys: opks.map((k) => ({ keyId: k.keyId, publicKey: bytesToB64(k.keyPair.publicKey) })),
  });
  console.log(`registered ${name}: token len ${res.token.length}, serverKey ${res.serverKey.publicKey.slice(0,12)}...`);
  return { ...id, spk, opks, username: name, token: res.token, serverKey: res.serverKey };
}

const suf = String(Date.now()).slice(-6); const alice = await register('alice' + suf);
const bob = await register('bob' + suf);

// ---- alice fetches bob's bundle and verifies the SPK ----
const bundle = await j('GET', '/users/' + bob.username + '/bundle', null, alice.token);
console.log('bundle: spk id', bundle.signedPreKey.keyId, 'opk?', !!bundle.oneTimePreKey);
if (!verifySignedPreKey(b64ToBytes(bundle.signingKey), bundle.signedPreKey.keyId, b64ToBytes(bundle.signedPreKey.publicKey), b64ToBytes(bundle.signedPreKey.signature))) {
  throw new Error('SPK signature invalid!');
}
console.log('SPK signature verified OK');

// ---- X3DH + ratchet: alice -> bob ----
const x = x3dhInitiator(alice.ik, b64ToBytes(bundle.identityKey), b64ToBytes(bundle.signedPreKey.publicKey),
  bundle.oneTimePreKey ? b64ToBytes(bundle.oneTimePreKey.publicKey) : null);
const aSession = DoubleRatchet.initAlice(x.sharedKey, x.ephemeralKey, b64ToBytes(bundle.signedPreKey.publicKey), randomUuid(), alice.ik.publicKey, b64ToBytes(bundle.identityKey));
const { header, ct } = aSession.encrypt(utf8Encode('hi bob, this is secret 🔒'), 0);
const mid = randomUuid();
await j('POST', '/messages', {
  v: 1, id: mid, from: alice.username, to: bob.username,
  sik: bytesToB64(alice.ik.publicKey),
  spkId: bundle.signedPreKey.keyId,
  opkId: bundle.oneTimePreKey ? bundle.oneTimePreKey.keyId : null,
  header, ct: bytesToB64(ct), drop: null, sentAt: Date.now(),
}, alice.token);
console.log('message posted, id', mid);

// ---- bob retrieves and decrypts ----
const inbox = await j('GET', '/messages', null, bob.token);
console.log('bob inbox count:', inbox.messages.length);
const m = inbox.messages.find((x) => x.id === mid);
if (!m) throw new Error('message not delivered!');
// bob reconstructs: looks up the local OPK (we kept it) and replies with X3DH
const bobOpk = bob.opks.find((k) => k.keyId === m.opkId);
const skBob = x3dhResponder(bob.ik.privateKey, bob.spk.keyPair.privateKey, bobOpk?.keyPair.privateKey ?? null,
  b64ToBytes(m.sik), b64ToBytes(m.header.dh));
const bSession = DoubleRatchet.initBob(skBob, bob.spk.keyPair, randomUuid(), bob.ik.publicKey, b64ToBytes(m.sik));
const plain = utf8Decode(bSession.decrypt(m.header, b64ToBytes(m.ct)));
console.log('bob decrypted:', plain);
if (plain !== 'hi bob, this is secret 🔒') throw new Error('decrypt mismatch!');

// ---- bob replies (2nd ratchet round) ----
const { header: h2, ct: c2 } = bSession.encrypt(utf8Encode('received! also secret'), 0);
const mid2 = randomUuid();
await j('POST', '/messages', {
  v: 1, id: mid2, from: bob.username, to: alice.username,
  sik: bytesToB64(bob.ik.publicKey), spkId: null, opkId: null,
  header: h2, ct: bytesToB64(c2), drop: null, sentAt: Date.now(),
}, bob.token);
const inboxA = await j('GET', '/messages', null, alice.token);
const m2 = inboxA.messages.find((x) => x.id === mid2);
const plain2 = utf8Decode(aSession.decrypt(m2.header, b64ToBytes(m2.ct)));
console.log('alice decrypted:', plain2);

// ---- heartbeat + delete + receipt ----
await j('POST', '/heartbeat', {}, bob.token);
await j('DELETE', `/messages/${mid2}`, null, alice.token);
const receipts = await j('GET', '/receipts', null, bob.token);
console.log('bob receipts:', receipts.receipts.length);

// ---- immediate drop with burn ----
const x2 = x3dhInitiator(alice.ik, b64ToBytes(bundle.identityKey), b64ToBytes(bundle.signedPreKey.publicKey), null);
const aS2 = DoubleRatchet.initAlice(x2.sharedKey, x2.ephemeralKey, b64ToBytes(bundle.signedPreKey.publicKey), randomUuid(), alice.ik.publicKey, b64ToBytes(bundle.identityKey));
const { header: h3, ct: c3 } = aS2.encrypt(utf8Encode('ephemeral message'), 1);
const mid3 = randomUuid();
await j('POST', '/messages', {
  v: 1, id: mid3, from: alice.username, to: bob.username,
  sik: bytesToB64(alice.ik.publicKey), spkId: bundle.signedPreKey.keyId, opkId: null,
  header: h3, ct: bytesToB64(c3), sentAt: Date.now(),
  drop: { releaseAt: null, timeoutDays: null, dms: false, burn: true, ttlDays: null },
}, alice.token);
console.log('drop posted, state queued ->', 'waiting for the scheduler (10s)');
await new Promise((r) => setTimeout(r, 11000));
const inbox2 = await j('GET', '/messages', null, bob.token);
const m3 = inbox2.messages.find((x) => x.id === mid3);
if (!m3) throw new Error('drop not released!');
// drop came from a NEW X3DH session of Alice -> Bob derives a new session from the message material
const sk3 = x3dhResponder(bob.ik.privateKey, bob.spk.keyPair.privateKey, null, b64ToBytes(m3.sik), b64ToBytes(m3.header.dh));
const bS3 = DoubleRatchet.initBob(sk3, bob.spk.keyPair, randomUuid(), bob.ik.publicKey, b64ToBytes(m3.sik));
console.log('drop released, decrypt:', utf8Decode(bS3.decrypt(m3.header, b64ToBytes(m3.ct))));
// burn: mark as read
await j('POST', `/messages/${mid3}/read`, null, bob.token);
await new Promise((r) => setTimeout(r, 1500));
const receipts2 = await j('GET', '/receipts', null, alice.token);
console.log('alice receipts after burn:', receipts2.receipts.length, 'reason:', receipts2.receipts.at(-1)?.reason);

console.log('\nE2E SMOKE TEST PASSED ✅');
