import { b64ToBytes, bytesToB64, type DeletionReceipt, type DropMeta } from '@deaddrop/shared';

/**
 * Vault local cifrado (IndexedDB `deaddrop-vault`, schema v1).
 *
 * Key model:
 *  - KEK: PBKDF2-SHA256(password, salt) with 600,000 iterations — never persisted.
 *  - VaultKey: 32 random bytes, AES-GCM, non-extractable, generated when the vault is created.
 *    The password only "re-wraps" the VaultKey (envelope {salt, iv, ct} in the vaultkey store).
 *    Changing the password = re-wrapping the VaultKey, without re-encrypting the data.
 *  - identity/sessions/contacts/messages: cifrados com VaultKey.
 *  - receipts: plaintext (signed by the server; they are not secrets).
 */
const DB_NAME = 'deaddrop-vault';
const DB_VERSION = 1;
const PBKDF2_ITERATIONS = 600_000;
const STORES = ['vaultkey', 'identity', 'sessions', 'contacts', 'messages', 'receipts'] as const;

export interface Envelope {
  salt: string; // b64
  iv: string;   // b64
  ct: string;   // b64
}

export interface VaultIdentity {
  username: string;
  ikPriv: string;
  ikPub: string;
  sigPriv: string;
  sigPub: string;
  spk: { keyId: number; priv: string; pub: string; sig: string };
  spkCounter: number;
  opks: { keyId: number; priv: string; pub: string }[]; // remaining OPKs (not consumed)
  opkCounter: number;
  createdAt: number;
}

export interface LocalMessage {
  uuid: string;
  peer: string;
  direction: 'in' | 'out';
  kind: 'normal' | 'drop';
  text: string;
  sentAt: number;
  dropMeta: DropMeta | null;
  status: 'pending' | 'queued' | 'released' | 'read' | 'burned' | 'error';
  error?: string;
  releasedAt?: number | null;
  readAt?: number | null;
}

export interface Contact {
  username: string;
  identityKey: string;
  addedAt: number;
}

export interface PeerSession {
  state: Record<string, unknown>;
  peerIk: string;
  updatedAt: number;
}


/** TS 5.7+ torna Uint8Array generico (ArrayBufferLike). Normaliza para ArrayBuffer
 *  para as APIs Web Crypto que exigem BufferSource. */
type U8 = Uint8Array<ArrayBuffer>;
function u8ab(u: Uint8Array): U8 {
  return new Uint8Array(u.buffer as ArrayBuffer, u.byteOffset, u.byteLength);
}

type StoreName = (typeof STORES)[number];

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      for (const s of STORES) {
        if (!db.objectStoreNames.contains(s)) db.createObjectStore(s);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('failed to open vault db'));
  });
}

function tx<T>(db: IDBDatabase, store: StoreName, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = db.transaction(store, mode);
    const req = fn(t.objectStore(store));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error(`vault ${store} op failed`));
  });
}

function txAll(db: IDBDatabase, store: StoreName): Promise<unknown[]> {
  return new Promise((resolve, reject) => {
    const t = db.transaction(store, 'readonly');
    const req = t.objectStore(store).getAll();
    req.onsuccess = () => resolve(req.result as unknown[]);
    req.onerror = () => reject(req.error ?? new Error(`vault ${store} getAll failed`));
  });
}

async function deriveKek(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: u8ab(salt), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function importVaultKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', u8ab(raw), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

class Vault {
  private db: IDBDatabase | null = null;
  private key: CryptoKey | null = null;

  get unlocked(): boolean {
    return this.key !== null;
  }

  private async ensureDb(): Promise<IDBDatabase> {
    if (!this.db) this.db = await openDb();
    return this.db;
  }

  async hasVault(): Promise<boolean> {
    const db = await this.ensureDb();
    return tx<unknown>(db, 'vaultkey', 'readonly', (s) => s.get('self')).then((v) => v !== undefined);
  }

  /** Creates a new vault (only called on registration). */
  async create(password: string): Promise<void> {
    const db = await this.ensureDb();
    const raw = crypto.getRandomValues(new Uint8Array(32));
    this.key = await importVaultKey(raw);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const kek = await deriveKek(password, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, raw));
    await tx(db, 'vaultkey', 'readwrite', (s) =>
      s.put({ salt: bytesToB64(salt), iv: bytesToB64(iv), ct: bytesToB64(ct) }, 'self'),
    );
  }

  /** Unlocks the vault with the password (login). Throws if the password is wrong. */
  async unlock(password: string): Promise<void> {
    const db = await this.ensureDb();
    const env = await tx<Envelope | undefined>(db, 'vaultkey', 'readonly', (s) => s.get('self'));
    if (!env) throw new Error('No local vault found — register in this browser first');
    const kek = await deriveKek(password, b64ToBytes(env.salt));
    let raw: ArrayBuffer;
    try {
      raw = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: u8ab(b64ToBytes(env.iv)) },
        kek,
        u8ab(b64ToBytes(env.ct)),
      );
    } catch {
      throw new Error('Incorrect password');
    }
    this.key = await importVaultKey(new Uint8Array(raw));
  }

  lock(): void {
    this.key = null;
  }

  private async wrap(plain: Uint8Array): Promise<Envelope> {
    if (!this.key) throw new Error('vault locked');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, u8ab(plain)));
    return { salt: '', iv: bytesToB64(iv), ct: bytesToB64(ct) };
  }

  private async unwrap(env: Envelope): Promise<Uint8Array> {
    if (!this.key) throw new Error('vault locked');
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: u8ab(b64ToBytes(env.iv)) },
        this.key,
        u8ab(b64ToBytes(env.ct)),
      ),
    );
  }

  // ---- identity ----
  async setIdentity(id: VaultIdentity): Promise<void> {
    const db = await this.ensureDb();
    const env = await this.wrap(new TextEncoder().encode(JSON.stringify(id)));
    await tx(db, 'identity', 'readwrite', (s) => s.put(env, 'self'));
  }

  async getIdentity(): Promise<VaultIdentity | null> {
    const db = await this.ensureDb();
    const env = await tx<Envelope | undefined>(db, 'identity', 'readonly', (s) => s.get('self'));
    if (!env) return null;
    const raw = await this.unwrap(env);
    return JSON.parse(new TextDecoder().decode(raw)) as VaultIdentity;
  }

  // ---- sessions ----
  async putSession(peer: string, s: PeerSession): Promise<void> {
    const db = await this.ensureDb();
    const env = await this.wrap(new TextEncoder().encode(JSON.stringify(s)));
    await tx(db, 'sessions', 'readwrite', (st) => st.put(env, peer));
  }

  async getSession(peer: string): Promise<PeerSession | null> {
    const db = await this.ensureDb();
    const env = await tx<Envelope | undefined>(db, 'sessions', 'readonly', (st) => st.get(peer));
    if (!env) return null;
    const raw = await this.unwrap(env);
    return JSON.parse(new TextDecoder().decode(raw)) as PeerSession;
  }

  async deleteSession(peer: string): Promise<void> {
    const db = await this.ensureDb();
    await tx(db, 'sessions', 'readwrite', (st) => st.delete(peer));
  }

  // ---- contacts ----
  async putContact(c: Contact): Promise<void> {
    const db = await this.ensureDb();
    const env = await this.wrap(new TextEncoder().encode(JSON.stringify(c)));
    await tx(db, 'contacts', 'readwrite', (st) => st.put(env, c.username));
  }

  async getContact(username: string): Promise<Contact | null> {
    const db = await this.ensureDb();
    const env = await tx<Envelope | undefined>(db, 'contacts', 'readonly', (st) => st.get(username));
    if (!env) return null;
    const raw = await this.unwrap(env);
    return JSON.parse(new TextDecoder().decode(raw)) as Contact;
  }

  async listContacts(): Promise<Contact[]> {
    const db = await this.ensureDb();
    const envs = (await txAll(db, 'contacts')) as Envelope[];
    const out: Contact[] = [];
    for (const env of envs) {
      const raw = await this.unwrap(env);
      out.push(JSON.parse(new TextDecoder().decode(raw)) as Contact);
    }
    return out.sort((a, b) => a.username.localeCompare(b.username));
  }

  // ---- messages ----
  async putMessage(m: LocalMessage): Promise<void> {
    const db = await this.ensureDb();
    const env = await this.wrap(new TextEncoder().encode(JSON.stringify(m)));
    await tx(db, 'messages', 'readwrite', (st) => st.put(env, m.uuid));
  }

  async getMessage(uuid: string): Promise<LocalMessage | null> {
    const db = await this.ensureDb();
    const env = await tx<Envelope | undefined>(db, 'messages', 'readonly', (st) => st.get(uuid));
    if (!env) return null;
    const raw = await this.unwrap(env);
    return JSON.parse(new TextDecoder().decode(raw)) as LocalMessage;
  }

  async hasMessage(uuid: string): Promise<boolean> {
    return (await this.getMessage(uuid)) !== null;
  }

  async listMessagesForPeer(peer: string): Promise<LocalMessage[]> {
    const db = await this.ensureDb();
    const envs = (await txAll(db, 'messages')) as Envelope[];
    const out: LocalMessage[] = [];
    for (const env of envs) {
      const raw = await this.unwrap(env);
      const m = JSON.parse(new TextDecoder().decode(raw)) as LocalMessage;
      if (m.peer === peer) out.push(m);
    }
    return out.sort((a, b) => a.sentAt - b.sentAt);
  }

  // ---- receipts (plaintext, signed by the server) ----
  async putReceipt(r: DeletionReceipt): Promise<void> {
    const db = await this.ensureDb();
    await tx(db, 'receipts', 'readwrite', (st) => st.put(r, r.id));
  }

  async listReceipts(): Promise<DeletionReceipt[]> {
    const db = await this.ensureDb();
    return (await txAll(db, 'receipts')) as DeletionReceipt[];
  }
}

export const vault = new Vault();
