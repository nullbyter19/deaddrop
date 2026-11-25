import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  PROTOCOL_VERSION, validateDropMeta, verifySignedPreKey, b64ToBytes,
  type AuthResponse, type PreKeyBundle, type RegisterPayload, type ServerKeyInfo,
  type WireMessage, type UserStats, type DeletionReceipt,
} from '@deaddrop/shared';
import type { Store } from './store.js';
import { hashPassword, verifyPassword, newToken, tokenExpiry } from './auth.js';
import { deleteWithReceipt, type NotifyFn } from './drops.js';

declare module 'fastify' {
  interface FastifyRequest {
    userId?: number;
  }
}

function bearer(req: FastifyRequest): string | null {
  const h = req.headers.authorization;
  if (!h) return null;
  const m = /^Bearer\s+([a-f0-9]{64})$/i.exec(h);
  return m ? (m[1] ?? null) : null;
}

const PROTECTED_PREFIXES = ['/api/v1/messages', '/api/v1/outbox', '/api/v1/receipts', '/api/v1/heartbeat', '/api/v1/users', '/api/v1/keys'];

export function buildApi(
  app: FastifyInstance,
  store: Store,
  serverSigningPriv: Uint8Array,
  notify: NotifyFn,
): void {
  // autenticacao: bearer token para rotas protegidas
  app.addHook('preHandler', async (req, reply) => {
    if (!PROTECTED_PREFIXES.some((p) => req.url.startsWith(p))) return;
    const token = bearer(req);
    const user = token ? store.getUserByToken(token) : undefined;
    if (!user) {
      return reply.code(401).send({ error: 'unauthorized' });
    }
    req.userId = user.id;
  });

  app.get('/api/v1/health', async () => ({ ok: true, time: Date.now() }));

  app.get('/api/v1/server-key', async (): Promise<ServerKeyInfo> => {
    const k = store.getActiveServerKey();
    if (!k) throw new Error('server key not found');
    return { keyId: k.key_id, publicKey: k.public_key, issuedAt: k.issued_at };
  });

  app.post<{ Body: RegisterPayload }>('/api/v1/register', async (req, reply) => {
    const { username, password, identityKey, signingKey, signedPreKey, oneTimePreKeys } = req.body ?? {};
    const name = String(username ?? '').trim().toLowerCase();
    if (!/^[a-z0-9_]{3,32}$/.test(name)) {
      return reply.code(400).send({ error: 'username must be 3-32 chars [a-z0-9_]' });
    }
    if (typeof password !== 'string' || password.length < 8) {
      return reply.code(400).send({ error: 'password must be at least 8 chars' });
    }
    if (store.getUserByUsername(name)) return reply.code(409).send({ error: 'username taken' });
    if (!signedPreKey || typeof signedPreKey.publicKey !== 'string' || typeof signedPreKey.signature !== 'string') {
      return reply.code(400).send({ error: 'invalid signed prekey' });
    }
    const okSig = verifySignedPreKey(
      b64ToBytes(signingKey),
      signedPreKey.keyId,
      b64ToBytes(signedPreKey.publicKey),
      b64ToBytes(signedPreKey.signature),
    );
    if (!okSig) return reply.code(400).send({ error: 'invalid signed prekey signature' });
    if (!Array.isArray(oneTimePreKeys) || oneTimePreKeys.length === 0 || oneTimePreKeys.length > 100) {
      return reply.code(400).send({ error: 'oneTimePreKeys must be 1-100' });
    }

    const { salt, hash } = hashPassword(password);
    const userId = store.createUser(name, hash, salt, identityKey, signingKey);
    store.addSignedPreKey(userId, signedPreKey.keyId, signedPreKey.publicKey, signedPreKey.signature);
    store.addOneTimePreKeys(userId, oneTimePreKeys);

    const token = newToken();
    store.createToken(token, userId, tokenExpiry());
    const key = store.getActiveServerKey();
    if (!key) return reply.code(500).send({ error: 'server key not initialized' });
    const res: AuthResponse = {
      token,
      username: name,
      serverKey: { keyId: key.key_id, publicKey: key.public_key, issuedAt: key.issued_at },
    };
    return res;
  });

  app.post<{ Body: { username: string; password: string } }>('/api/v1/auth/login', async (req, reply) => {
    const { username, password } = req.body ?? {};
    const user = store.getUserByUsername(String(username ?? '').trim().toLowerCase());
    if (!user || !verifyPassword(String(password ?? ''), user.salt, user.password_hash)) {
      return reply.code(401).send({ error: 'invalid credentials' });
    }
    const token = newToken();
    store.createToken(token, user.id, tokenExpiry());
    const key = store.getActiveServerKey();
    if (!key) return reply.code(500).send({ error: 'server key not initialized' });
    return {
      token,
      username: user.username,
      serverKey: { keyId: key.key_id, publicKey: key.public_key, issuedAt: key.issued_at },
    } satisfies AuthResponse;
  });

  app.post('/api/v1/auth/logout', async (req, reply) => {
    const token = bearer(req);
    if (token) store.deleteToken(token);
    return { ok: true };
  });

  app.get<{ Querystring: { q?: string } }>('/api/v1/users/search', async (req) => {
    const token = bearer(req);
    const me = token ? store.getUserByToken(token) : undefined;
    const q = String(req.query.q ?? '').trim().toLowerCase();
    if (q.length < 2) return { users: [] };
    return { users: store.searchUsers(q, me?.id ?? -1) };
  });

  app.get<{ Params: { username: string } }>('/api/v1/users/:username/bundle', async (req, reply) => {
    const user = store.getUserByUsername(req.params.username.toLowerCase());
    if (!user) return reply.code(404).send({ error: 'user not found' });
    const spk = store.getLatestSignedPreKey(user.id);
    if (!spk) return reply.code(404).send({ error: 'no signed prekey' });
    const opk = store.claimOneTimePreKey(user.id, req.userId ?? 0);
    const bundle: PreKeyBundle = {
      identityKey: user.identity_key,
      signingKey: user.signing_key,
      signedPreKey: { keyId: spk.key_id, publicKey: spk.public_key, signature: spk.signature },
      oneTimePreKey: opk ? { keyId: opk.key_id, publicKey: opk.public_key } : null,
    };
    return bundle;
  });

  app.post<{ Body: WireMessage }>('/api/v1/messages', async (req, reply) => {
    const wm = req.body;
    if (!wm || wm.v !== PROTOCOL_VERSION || typeof wm.id !== 'string' || !wm.from || !wm.to) {
      return reply.code(400).send({ error: 'invalid message envelope' });
    }
    const sender = store.getUserByUsername(wm.from.toLowerCase());
    const recipient = store.getUserByUsername(wm.to.toLowerCase());
    if (!sender || !recipient) return reply.code(404).send({ error: 'recipient not found' });
    if (store.getMessageByUuid(wm.id)) return reply.code(409).send({ error: 'duplicate message id' });

    let kind = 'normal';
    let state = 'released';
    let dropMeta: WireMessage['drop'] = null;
    if (wm.drop) {
      kind = 'drop';
      try {
        validateDropMeta(wm.drop);
      } catch (e) {
        return reply.code(400).send({ error: (e as Error).message });
      }
      dropMeta = wm.drop;
      state = 'queued';
    }
    const id = store.insertMessage(wm, sender.id, recipient.id, kind, state, dropMeta, wm.sentAt ?? Date.now());
    if (state === 'released') {
      notify(recipient.id, { type: 'message', data: { uuid: wm.id } });
    }
    return { id, state };
  });

  app.get<{ Querystring: { since?: string } }>('/api/v1/messages', async (req) => {
    const since = Number(req.query.since ?? 0) || 0;
    const rows = store.listIncomingReleased(req.userId!, since);
    return {
      messages: rows.map((r) => JSON.parse(r.payload) as WireMessage),
      lastId: rows.length ? rows[rows.length - 1]!.id : since,
    };
  });

  app.get<{ Querystring: { since?: string } }>('/api/v1/outbox', async (req) => {
    const since = Number(req.query.since ?? 0) || 0;
    const rows = store.listOutgoing(req.userId!, since);
    return {
      messages: rows.map((r) => ({
        payload: JSON.parse(r.payload) as WireMessage,
        serverId: r.id,
        state: r.state,
        releasedAt: r.released_at,
        readAt: r.read_at,
        deletedAt: r.deleted_at,
      })),
      lastId: rows.length ? rows[rows.length - 1]!.id : since,
    };
  });

  app.post<{ Params: { uuid: string } }>('/api/v1/messages/:uuid/read', async (req, reply) => {
    const owners = store.getMessageOwners(req.params.uuid);
    if (!owners) return reply.code(404).send({ error: 'message not found' });
    if (owners.recipient_id !== req.userId) return reply.code(403).send({ error: 'not your message' });
    store.setRead(req.params.uuid, Date.now());
    const meta = store.getDropMeta(req.params.uuid);
    if (meta?.burn) {
      deleteWithReceipt(store, serverSigningPriv, req.params.uuid, 'burn', notify);
    }
    return { ok: true };
  });

  app.delete<{ Params: { uuid: string } }>('/api/v1/messages/:uuid', async (req, reply) => {
    const owners = store.getMessageOwners(req.params.uuid);
    if (!owners) return reply.code(404).send({ error: 'message not found' });
    if (owners.sender_id !== req.userId && owners.recipient_id !== req.userId) {
      return reply.code(403).send({ error: 'not your message' });
    }
    if (owners.sender_id === req.userId && owners.state !== 'released') {
      store.deleteRow(req.params.uuid);
      return { ok: true, receipt: null };
    }
    const receipt = deleteWithReceipt(store, serverSigningPriv, req.params.uuid, 'explicit', notify);
    return { ok: true, receipt };
  });

  app.get<{ Querystring: { since?: string } }>('/api/v1/receipts', async (req) => {
    const since = Number(req.query.since ?? 0) || 0;
    const rows = store.listReceiptsForSender(req.userId!, since);
    const receipts: DeletionReceipt[] = rows.map((r) => {
      const recipient = store.getUserById(r.recipient_id);
      return {
        id: r.receipt_id,
        messageId: r.message_uuid,
        recipient: recipient?.username ?? String(r.recipient_id),
        deletedAt: r.deleted_at,
        reason: r.reason as DeletionReceipt['reason'],
        sig: r.sig,
      };
    });
    return { receipts, lastId: rows.length ? rows[rows.length - 1]!.id : since };
  });

  app.post('/api/v1/heartbeat', async (req) => {
    store.updateLastSeen(req.userId!, Date.now());
    return { ok: true };
  });


  /** One-time prekey refill (the client refills when it has <=2 left). */
  app.post<{ Body: { oneTimePreKeys: { keyId: number; publicKey: string }[] } }>('/api/v1/keys/one-time', async (req, reply) => {
    const keys = req.body?.oneTimePreKeys;
    if (!Array.isArray(keys) || keys.length === 0 || keys.length > 100) {
      return reply.code(400).send({ error: 'oneTimePreKeys must be 1-100' });
    }
    for (const k of keys) {
      if (!k || typeof k.keyId !== 'number' || !Number.isInteger(k.keyId) ||
          typeof k.publicKey !== 'string' || !/^[A-Za-z0-9+/]{42,44}={0,2}$/.test(k.publicKey)) {
        return reply.code(400).send({ error: 'invalid one-time prekey entry' });
      }
    }
    store.addOneTimePreKeys(req.userId!, keys);
    return { ok: true, count: store.countOneTimePreKeys(req.userId!) };
  });

  app.get('/api/v1/stats', async (): Promise<UserStats> => store.stats());
}
