import { isDropReleased, signReceipt, randomUuid, type DeletionReceipt, type DropMeta } from '@deaddrop/shared';
import type { Store } from './store.js';

export type NotifyFn = (userId: number, event: { type: string; data?: unknown }) => void;

const MS_PER_DAY = 86_400_000;

/**
 * Scheduler de drops (dead man's switch + release_at + TTL).
 * Runs every 10s:
 *  1. releases drops whose condition was met (state queued -> released)
 *  2. applies TTL to expired released messages and generates deletion receipts
 */
export function startDropScheduler(
  store: Store,
  serverSigningPriv: Uint8Array,
  notify: NotifyFn,
  intervalMs = 10_000,
): { stop: () => void } {
  const tick = () => {
    const now = Date.now();
    try {
      const pending = store.listPendingDrops();
      for (const p of pending) {
        const meta = JSON.parse(p.drop_meta!) as DropMeta;
        const senderLastSeen = store.getLastSeen(p.sender_id);
        if (isDropReleased(meta, senderLastSeen, now)) {
          const ttlDeadline = meta.ttlDays !== null ? now + meta.ttlDays * MS_PER_DAY : null;
          store.setReleased(p.msg_uuid, now, ttlDeadline);
          const owners = store.getMessageOwners(p.msg_uuid);
          if (owners) notify(owners.recipient_id, { type: 'message', data: { uuid: p.msg_uuid } });
        }
      }
      const due = store.listReleasedDueTtl(now);
      for (const m of due) {
        deleteWithReceipt(store, serverSigningPriv, m.msg_uuid, 'ttl', notify);
      }
    } catch (err) {
      console.error('[drops] scheduler error:', err);
    }
  };
  const timer = setInterval(tick, intervalMs);
  tick();
  return { stop: () => clearInterval(timer) };
}

/**
 * Deletes the message and generates a server-signed deletion receipt (if not yet present).
 * Returns the generated receipt, or null if the message does not exist / was already deleted.
 */
export function deleteWithReceipt(
  store: Store,
  serverSigningPriv: Uint8Array,
  msgUuid: string,
  reason: DeletionReceipt['reason'],
  notify?: NotifyFn,
): DeletionReceipt | null {
  const owners = store.getMessageOwners(msgUuid);
  if (!owners) return null;
  const sender = store.getUserById(owners.sender_id);
  const recipient = store.getUserById(owners.recipient_id);
  if (!sender || !recipient) return null;

  const now = Date.now();
  const receipt: DeletionReceipt = {
    id: randomUuid(),
    messageId: msgUuid,
    recipient: recipient.username,
    deletedAt: now,
    reason,
    sig: '',
  };
  const sig = signReceipt(serverSigningPriv, receipt);
  receipt.sig = bytesToB64(sig);
  store.insertReceipt(receipt, owners.sender_id, owners.recipient_id);
  store.setDeleted(msgUuid, now);
  if (notify) notify(owners.sender_id, { type: 'receipt', data: receipt });
  return receipt;
}

function bytesToB64(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!);
  return btoa(s);
}
