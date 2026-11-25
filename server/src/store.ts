import type { DatabaseSync } from 'node:sqlite';
import type { DeletionReceipt, DropMeta, WireMessage, UserStats } from '@deaddrop/shared';
import {
  openDb, rowToStoredMessage,
  type UserRow, type SignedPreKeyRow, type OneTimePreKeyRow,
  type MessageRow, type ReceiptRow, type ServerKeyRow, type TokenRow,
} from './db.js';

export class Store {
  private db: DatabaseSync;
  constructor(path: string) {
    this.db = openDb(path);
  }
  close(): void {
    try { this.db.close(); } catch { /* noop */ }
  }

  // ---- users ----
  createUser(username: string, hash: string, salt: string, ik: string, sk: string): number {
    const now = Date.now();
    const r = this.db.prepare(
      'INSERT INTO users (username, password_hash, salt, identity_key, signing_key, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    ).run(username, hash, salt, ik, sk, now, now);
    return Number(r.lastInsertRowid);
  }
  getUserByUsername(username: string): UserRow | undefined {
    return this.db.prepare('SELECT * FROM users WHERE username = ?').get(username) as UserRow | undefined;
  }
  getUserById(id: number): UserRow | undefined {
    return this.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
  }
  updateLastSeen(userId: number, ts: number): void {
    this.db.prepare('UPDATE users SET last_seen_at = ? WHERE id = ?').run(ts, userId);
  }
  getLastSeen(userId: number): number {
    const row = this.db.prepare('SELECT last_seen_at FROM users WHERE id = ?').get(userId) as { last_seen_at: number } | undefined;
    return row?.last_seen_at ?? 0;
  }
  searchUsers(prefix: string, excludeId: number, limit = 20): { username: string; identityKey: string }[] {
    const rows = this.db.prepare(
      "SELECT username, identity_key FROM users WHERE username LIKE ? AND id != ? ORDER BY username LIMIT ?",
    ).all(`${prefix}%`, excludeId, limit) as { username: string; identity_key: string }[];
    return rows.map((r) => ({ username: r.username, identityKey: r.identity_key }));
  }

  // ---- prekeys ----
  addSignedPreKey(userId: number, keyId: number, pub: string, sig: string): void {
    this.db.prepare(
      'INSERT INTO signed_prekeys (user_id, key_id, public_key, signature, created_at) VALUES (?, ?, ?, ?, ?)',
    ).run(userId, keyId, pub, sig, Date.now());
  }
  getLatestSignedPreKey(userId: number): SignedPreKeyRow | undefined {
    return this.db.prepare(
      'SELECT * FROM signed_prekeys WHERE user_id = ? ORDER BY id DESC LIMIT 1',
    ).get(userId) as SignedPreKeyRow | undefined;
  }
  addOneTimePreKeys(userId: number, keys: { keyId: number; publicKey: string }[]): void {
    const stmt = this.db.prepare(
      'INSERT OR IGNORE INTO one_time_prekeys (user_id, key_id, public_key, created_at) VALUES (?, ?, ?, ?)',
    );
    const now = Date.now();
    for (const k of keys) stmt.run(userId, k.keyId, k.publicKey, now);
  }
  countOneTimePreKeys(userId: number): number {
    const row = this.db.prepare('SELECT COUNT(*) AS c FROM one_time_prekeys WHERE user_id = ?').get(userId) as { c: number };
    return Number(row.c);
  }
  /** Claim-on-fetch: removes the OPK from the server (one-time) and returns the public key. */
  claimOneTimePreKey(userId: number, claimerId: number): OneTimePreKeyRow | undefined {
    const row = this.db.prepare(
      'SELECT * FROM one_time_prekeys WHERE user_id = ? AND claimed_by IS NULL ORDER BY id ASC LIMIT 1',
    ).get(userId) as OneTimePreKeyRow | undefined;
    if (!row) return undefined;
    this.db.prepare('UPDATE one_time_prekeys SET claimed_by = ?, claimed_at = ? WHERE id = ?').run(claimerId, Date.now(), row.id);
    this.db.prepare('DELETE FROM one_time_prekeys WHERE id = ?').run(row.id);
    return row;
  }

  // ---- tokens ----
  createToken(token: string, userId: number, expiresAt: number): void {
    this.db.prepare('INSERT INTO tokens (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)').run(token, userId, Date.now(), expiresAt);
  }
  getUserByToken(token: string): UserRow | undefined {
    const row = this.db.prepare('SELECT * FROM tokens WHERE token = ?').get(token) as TokenRow | undefined;
    if (!row) return undefined;
    if (row.expires_at <= Date.now()) {
      this.db.prepare('DELETE FROM tokens WHERE token = ?').run(token);
      return undefined;
    }
    return this.getUserById(row.user_id);
  }
  deleteToken(token: string): void {
    this.db.prepare('DELETE FROM tokens WHERE token = ?').run(token);
  }

  // ---- messages ----
  insertMessage(wm: WireMessage, senderId: number, recipientId: number, kind: string, state: string, dropMeta: DropMeta | null, sentAt: number): number {
    const r = this.db.prepare(
      `INSERT INTO messages (msg_uuid, sender_id, recipient_id, payload, kind, state, drop_meta, sent_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(wm.id, senderId, recipientId, JSON.stringify(wm), kind, state, dropMeta ? JSON.stringify(dropMeta) : null, sentAt);
    return Number(r.lastInsertRowid);
  }
  getMessageByUuid(uuid: string): MessageRow | undefined {
    return this.db.prepare('SELECT * FROM messages WHERE msg_uuid = ?').get(uuid) as MessageRow | undefined;
  }
  getMessageOwners(uuid: string): { sender_id: number; recipient_id: number; state: string; kind: string } | undefined {
    return this.db.prepare('SELECT sender_id, recipient_id, state, kind FROM messages WHERE msg_uuid = ?').get(uuid) as
      | { sender_id: number; recipient_id: number; state: string; kind: string } | undefined;
  }
  listIncomingReleased(userId: number, sinceId: number, limit = 200): MessageRow[] {
    return this.db.prepare(
      `SELECT * FROM messages WHERE recipient_id = ? AND state = 'released' AND deleted_at IS NULL AND id > ? ORDER BY id ASC LIMIT ?`,
    ).all(userId, sinceId, limit) as unknown as MessageRow[];
  }
  listOutgoing(userId: number, sinceId: number, limit = 200): MessageRow[] {
    return this.db.prepare(
      'SELECT * FROM messages WHERE sender_id = ? AND id > ? ORDER BY id ASC LIMIT ?',
    ).all(userId, sinceId, limit) as unknown as MessageRow[];
  }
  setReleased(uuid: string, ts: number, ttlDeadline: number | null): void {
    this.db.prepare("UPDATE messages SET state = 'released', released_at = ?, ttl_deadline = ? WHERE msg_uuid = ?").run(ts, ttlDeadline, uuid);
  }
  setRead(uuid: string, ts: number): void {
    this.db.prepare("UPDATE messages SET state = 'read', read_at = ? WHERE msg_uuid = ?").run(ts, uuid);
  }
  setDeleted(uuid: string, ts: number): void {
    this.db.prepare('UPDATE messages SET deleted_at = ? WHERE msg_uuid = ?').run(ts, uuid);
  }
  deleteRow(uuid: string): void {
    this.db.prepare('DELETE FROM messages WHERE msg_uuid = ?').run(uuid);
  }
  /** Pending drops (not released) + sender last_seen, for the scheduler. */
  listPendingDrops(): { msg_uuid: string; sender_id: number; drop_meta: string }[] {
    return this.db.prepare(
      "SELECT msg_uuid, sender_id, drop_meta FROM messages WHERE kind = 'drop' AND state = 'queued'",
    ).all() as { msg_uuid: string; sender_id: number; drop_meta: string }[];
  }
  listReleasedDueTtl(now: number): MessageRow[] {
    return this.db.prepare(
      "SELECT * FROM messages WHERE state = 'released' AND ttl_deadline IS NOT NULL AND ttl_deadline <= ?",
    ).all(now) as unknown as MessageRow[];
  }
  getDropMeta(uuid: string): DropMeta | null {
    const row = this.db.prepare('SELECT drop_meta FROM messages WHERE msg_uuid = ?').get(uuid) as { drop_meta: string | null } | undefined;
    if (!row?.drop_meta) return null;
    return JSON.parse(row.drop_meta) as DropMeta;
  }

  // ---- receipts ----
  insertReceipt(r: DeletionReceipt, senderId: number, recipientId: number): void {
    this.db.prepare(
      `INSERT INTO receipts (receipt_id, message_uuid, sender_id, recipient_id, deleted_at, reason, sig, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(r.id, r.messageId, senderId, recipientId, r.deletedAt, r.reason, r.sig, Date.now());
  }
  listReceiptsForSender(senderId: number, sinceId: number, limit = 200): ReceiptRow[] {
    return this.db.prepare(
      'SELECT * FROM receipts WHERE sender_id = ? AND id > ? ORDER BY id ASC LIMIT ?',
    ).all(senderId, sinceId, limit) as unknown as ReceiptRow[];
  }
  receiptExists(receiptId: string): boolean {
    const row = this.db.prepare('SELECT 1 AS x FROM receipts WHERE receipt_id = ?').get(receiptId) as { x: number } | undefined;
    return row !== undefined;
  }

  // ---- server keys ----
  getActiveServerKey(): ServerKeyRow | undefined {
    return this.db.prepare("SELECT * FROM server_keys WHERE active = 1 ORDER BY id DESC LIMIT 1").get() as ServerKeyRow | undefined;
  }
  createServerKey(keyId: number, pub: string, issuedAt: number): void {
    this.db.prepare('UPDATE server_keys SET active = 0 WHERE active = 1').run();
    this.db.prepare('INSERT INTO server_keys (key_id, public_key, issued_at, active) VALUES (?, ?, ?, 1)').run(keyId, pub, issuedAt);
  }

  // ---- stats ----
  stats(): UserStats {
    const users = this.db.prepare('SELECT COUNT(*) AS c FROM users').get() as { c: number };
    const messages = this.db.prepare('SELECT COUNT(*) AS c FROM messages').get() as { c: number };
    const drops = this.db.prepare("SELECT COUNT(*) AS c FROM messages WHERE kind = 'drop'").get() as { c: number };
    const pending = this.db.prepare("SELECT COUNT(*) AS c FROM messages WHERE kind = 'drop' AND state = 'queued'").get() as { c: number };
    const released = this.db.prepare("SELECT COUNT(*) AS c FROM messages WHERE kind = 'drop' AND state = 'released'").get() as { c: number };
    const receipts = this.db.prepare('SELECT COUNT(*) AS c FROM receipts').get() as { c: number };
    return {
      users: Number(users.c),
      messages: Number(messages.c),
      drops: Number(drops.c),
      pendingDrops: Number(pending.c),
      releasedDrops: Number(released.c),
      receipts: Number(receipts.c),
    };
  }
}
