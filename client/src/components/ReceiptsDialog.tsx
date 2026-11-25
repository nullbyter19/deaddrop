import { b64ToBytes, verifyReceipt } from '@deaddrop/shared';
import type { DeletionReceipt } from '@deaddrop/shared';

interface Props {
  receipts: DeletionReceipt[];
  serverKeyPub: string;
  onClose: () => void;
}

const REASON_LABEL: Record<DeletionReceipt['reason'], string> = {
  burn: 'burn (after read)',
  ttl: 'TTL expired',
  explicit: 'explicit deletion',
  'dms-ttl': 'DMS timeout',
};

function fmt(ts: number): string {
  return new Date(ts).toLocaleString('en-GB');
}

export default function ReceiptsDialog({ receipts, serverKeyPub, onClose }: Props) {
  return (
    <div className="overlay" onClick={onClose}>
      <div className="dialog" onClick={(e) => e.stopPropagation()}>
        <h3>Deletion receipts</h3>
        <p className="muted" style={{ fontSize: 13, marginTop: 0 }}>
          Signed (Ed25519) proofs from the server that your messages/drops were deleted —
          {receipts.length} in total.
        </p>
        {receipts.length === 0 && <p className="muted center">No receipts yet.</p>}
        {[...receipts].reverse().map((r) => {
          const ok = verifyReceipt(b64ToBytes(serverKeyPub), r);
          return (
            <div key={r.id} className="receipt-item">
              <div><strong>{REASON_LABEL[r.reason]}</strong></div>
              <div className="row">
                <span>msg: {r.messageId.slice(0, 8)}…</span>
                <span>to: {r.recipient}</span>
              </div>
              <div className="row">
                <span>{fmt(r.deletedAt)}</span>
                <span className={ok ? 'sig-ok' : 'sig-bad'}>
                  {ok ? '✓ valid signature' : '✗ INVALID signature'}
                </span>
              </div>
            </div>
          );
        })}
        <div className="center" style={{ marginTop: 12 }}>
          <button className="ghost" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
