import type { DropMeta } from './types.js';

const MS_PER_DAY = 86_400_000;

/**
 * Evaluates whether a drop is released for delivery.
 * rule: release_at reached OR (dms && sender inactive for timeout_days) OR no condition (immediate).
 */
export function isDropReleased(meta: DropMeta, senderLastSeenAt: number, now: number): boolean {
  if (meta.releaseAt !== null && now >= meta.releaseAt) return true;
  if (meta.dms && meta.timeoutDays !== null) {
    if (senderLastSeenAt + meta.timeoutDays * MS_PER_DAY <= now) return true;
  }
  if (meta.releaseAt === null && !meta.dms) return true;
  return false;
}

export function validateDropMeta(meta: DropMeta): void {
  if (meta.releaseAt !== null && meta.releaseAt <= Date.now() + 60_000) {
    throw new Error('releaseAt must be at least 1 minute in the future');
  }
  if (meta.dms && meta.timeoutDays === null) {
    throw new Error('dms requires timeoutDays');
  }
  if (meta.timeoutDays !== null && (meta.timeoutDays < 1 || meta.timeoutDays > 3650)) {
    throw new Error('timeoutDays out of range');
  }
  if (meta.ttlDays !== null && (meta.ttlDays < 1 / 24 || meta.ttlDays > 3650)) {
    throw new Error('ttlDays out of range');
  }
  if (meta.releaseAt === null && !meta.dms) {
    // immediate drop: needs at least a TTL or burn so it is not the same as a normal message
    if (!meta.burn && meta.ttlDays === null) throw new Error('immediate drop requires burn or ttlDays');
  }
}
