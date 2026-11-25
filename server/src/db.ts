import { DatabaseSync } from 'node:sqlite';
import type { DropMeta, WireMessage, StoredMessage } from '@deaddrop/shared';

export interface UserRow {
  id: number;
  username: string;
  password_hash: string;
  salt: string;
  identity_key: string;
  signing_key: string;
  created_at: number;
  last_seen_at: number;
}
export interface SignedPreKeyRow {
  id: number;
  user_id: number;
  key_id: number;
  public_key: string;
  signature: string;
  created_at: number;
}
export interface OneTimePreKeyRow {
  id: number;
  user_id: number;
  key_id: number;
  public_key: string;
  claimed_by: number | null;
  claimed_at: number | null;
  created_at: number;
}
export interface MessageRow {
  id: number;
  msg_uuid: string;
  sender_id: number;
  recipient_id: number;
  payload: string;
  kind: string;
  state: string;
  drop_meta: string | null;
  sent_at: number;
  released_at: number | null;
  read_at: number | null;
  deleted_at: number | null;
  ttl_deadline: number | null;
}
export interface ReceiptRow {
  id: number;
  receipt_id: string;
  message_uuid: string;
  sender_id: number;
  recipient_id: number;
  deleted_at: number;
  reason: string;
  sig: string;
  created_at: number;
}
export interface ServerKeyRow {
  id: number;
  key_id: number;
  public_key: string;
  issued_at: number;
  active: number;
}
export interface TokenRow {
  token: string;
  user_id: number;
  created_at: number;
  expires_at: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  identity_key TEXT NOT NULL,
  signing_key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS signed_prekeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL,
  public_key TEXT NOT NULL,
  signature TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, key_id)
);
CREATE TABLE IF NOT EXISTS one_time_prekeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL,
  public_key TEXT NOT NULL,
  claimed_by INTEGER REFERENCES users(id),
  claimed_at INTEGER,
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, key_id)
);
CREATE TABLE IF NOT EXISTS tokens (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  msg_uuid TEXT UNIQUE NOT NULL,
  sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  payload TEXT NOT NULL,
  kind TEXT NOT NULL,
  state TEXT NOT NULL,
  drop_meta TEXT,
  sent_at INTEGER NOT NULL,
  released_at INTEGER,
  read_at INTEGER,
  deleted_at INTEGER,
  ttl_deadline INTEGER
);
CREATE INDEX IF NOT EXISTS idx_messages_recipient_state ON messages(recipient_id, state);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_state ON messages(state);
CREATE TABLE IF NOT EXISTS receipts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  receipt_id TEXT UNIQUE NOT NULL,
  message_uuid TEXT NOT NULL,
  sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  deleted_at INTEGER NOT NULL,
  reason TEXT NOT NULL,
  sig TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_receipts_sender ON receipts(sender_id, id);
CREATE TABLE IF NOT EXISTS server_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id INTEGER NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
`;

export function openDb(path: string): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec(SCHEMA);
  return db;
}

export function rowToStoredMessage(r: MessageRow): StoredMessage {
  const payload = JSON.parse(r.payload) as WireMessage;
  return {
    ...payload,
    serverId: r.id,
    state: r.state as StoredMessage['state'],
    deliveredAt: r.released_at,
    deletedAt: r.deleted_at,
  };
}
