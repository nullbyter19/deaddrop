import { safetyNumber, formatSafetyNumber } from '@deaddrop/shared';

interface Props {
  peer: string;
  ownIk: string;
  peerIk: string;
  onClose: () => void;
}

export default function SafetyDialog({ peer, ownIk, peerIk, onClose }: Props) {
  const sn = safetyNumber(ownIk, peerIk);
  return (
    <div className="overlay" onClick={onClose}>
      <div className="dialog" onClick={(e) => e.stopPropagation()}>
        <h3>Safety number — {peer}</h3>
        <p className="muted" style={{ fontSize: 13, marginTop: 0 }}>
          Compare this number with {peer} over a secure channel (in person, another platform).
          It is derived from both X25519 identity keys (SHA-256, byte-wise sorted) — if the
          server intercepts a prekey, the numbers diverge.
        </p>
        <div className="safety-digits">{formatSafetyNumber(sn.groups)}</div>
        <p className="muted" style={{ fontSize: 12 }}>
          Your identity key: <code>{ownIk.slice(0, 32)}…</code>
          <br />
          {peer}'s identity key: <code>{peerIk.slice(0, 32)}…</code>
        </p>
        <div className="center">
          <button className="ghost" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
