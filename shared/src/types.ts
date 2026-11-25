/** Types shared between client and server (wire protocol + crypto). */

export const PROTOCOL_VERSION = 1;
export const IDENTITY_KEY_BYTES = 32;
export const MAX_SKIP = 1000;

export const enum MessageType {
  Normal = 0,
  Drop = 1,
}

export interface WireHeader {
  dh: string;      // base64 X25519 public
  pn: number;      // previous chain length
  ns: number;      // sending chain length
  n: number;       // message number
  mtype: number;   // MessageType
}

export interface DropMeta {
  releaseAt: number | null; // epoch ms (absolute) — libera nesta data
  timeoutDays: number | null; // used with dms
  dms: boolean;              // dead man's switch: releases if the sender stops the heartbeat
  burn: boolean;             // apaga apos leitura
  ttlDays: number | null;    // apaga automaticamente apos release
}

export interface WireMessage {
  v: number;
  id: string;
  from: string;
  to: string;
  sik: string;          // identity key public (b64) do remetente
  spkId: number | null; // recipient signed prekey id used in X3DH
  opkId: number | null; // consumed one-time prekey id (first msg)
  header: WireHeader;
  ct: string;           // ciphertext b64
  drop: DropMeta | null;
  sentAt: number;
}

export interface StoredMessage extends WireMessage {
  serverId: number;
  state: 'queued' | 'released' | 'read';
  deliveredAt: number | null;
  deletedAt: number | null;
}

export interface DeletionReceipt {
  id: string;
  messageId: string;    // message id (from the sender)
  recipient: string;
  deletedAt: number;    // epoch ms
  reason: 'burn' | 'ttl' | 'explicit' | 'dms-ttl';
  sig: string;          // server Ed25519 signature
}

export interface PreKeyBundle {
  identityKey: string;
  signingKey: string; // ed25519 pub — verifies the signed prekey signature
  signedPreKey: { keyId: number; publicKey: string; signature: string };
  oneTimePreKey: { keyId: number; publicKey: string } | null;
}

export interface ServerKeyInfo {
  keyId: number;
  publicKey: string; // Ed25519 b64
  issuedAt: number;
}

export interface HeartbeatInfo {
  lastSeenAt: number;
}

export interface RegisterPayload {
  username: string;
  password: string;
  identityKey: string;       // x25519 pub b64
  signingKey: string;        // ed25519 pub b64
  signedPreKey: { keyId: number; publicKey: string; signature: string };
  oneTimePreKeys: { keyId: number; publicKey: string }[];
}

export interface AuthResponse {
  token: string;
  username: string;
  serverKey: ServerKeyInfo;
}

export interface UserStats {
  users: number;
  messages: number;
  drops: number;
  pendingDrops: number;
  releasedDrops: number;
  receipts: number;
}
