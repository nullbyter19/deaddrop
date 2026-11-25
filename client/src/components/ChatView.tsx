import { useEffect, useRef, useState } from 'react';
import type { DropMeta } from '@deaddrop/shared';
import type { LocalMessage } from '../vault';

type DropMode = 'normal' | 'burn' | 'ttl' | 'scheduled' | 'dms';

interface Props {
  peer: string;
  peerIk: string | null;
  messages: LocalMessage[];
  onSend: (text: string, drop: DropMeta | null) => Promise<void>;
  onMarkRead: (uuid: string) => void;
  onOpenSafety: () => void;
}

function fmtTime(ts: number): string {
  return new Date(ts).toLocaleString('en-GB', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function badgeFor(m: LocalMessage): { cls: string; label: string } | null {
  if (m.direction === 'out') {
    switch (m.status) {
      case 'queued': return { cls: 'queued', label: '⏳ scheduled' };
      case 'released': return { cls: 'released', label: 'released' };
      case 'read': return { cls: 'read', label: 'read' };
      case 'burned': return { cls: 'burned', label: '🔥 burned' };
      case 'error': return { cls: 'error', label: '⚠ error' };
      default: return null;
    }
  }
  if (m.status === 'burned') return { cls: 'burned', label: '🔥 burned' };
  if (m.kind === 'drop') return { cls: 'drop', label: 'drop' };
  return null;
}

export default function ChatView({ peer, peerIk, messages, onSend, onMarkRead, onOpenSafety }: Props) {
  const [text, setText] = useState('');
  const [mode, setMode] = useState<DropMode>('normal');
  const [ttlDays, setTtlDays] = useState(1);
  const [releaseAt, setReleaseAt] = useState('');
  const [timeoutDays, setTimeoutDays] = useState(7);
  const [burnScheduled, setBurnScheduled] = useState(false);
  const [sending, setSending] = useState(false);
  const endRef = useRef<HTMLDivElement | null>(null);
  const markedRef = useRef<Set<string>>(new Set());

  // burn: mark as read ~1.2s after render (deletes on server + receipt)
  useEffect(() => {
    for (const m of messages) {
      if (m.direction === 'in' && m.dropMeta?.burn && m.status === 'released' && !m.readAt && !markedRef.current.has(m.uuid)) {
        markedRef.current.add(m.uuid);
        const uuid = m.uuid;
        const t = window.setTimeout(() => onMarkRead(uuid), 1200);
        window.setTimeout(() => markedRef.current.delete(uuid), 60000);
        void t;
      }
    }
  }, [messages, onMarkRead]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages.length, peer]);

  function buildDrop(): DropMeta | null {
    switch (mode) {
      case 'burn':
        return { releaseAt: null, timeoutDays: null, dms: false, burn: true, ttlDays: null };
      case 'ttl':
        return { releaseAt: null, timeoutDays: null, dms: false, burn: false, ttlDays };
      case 'scheduled': {
        const ts = releaseAt ? new Date(releaseAt).getTime() : 0;
        if (!releaseAt || Number.isNaN(ts)) {
          alert('Choose the release date/time for the drop.');
          return null;
        }
        return { releaseAt: ts, timeoutDays: null, dms: false, burn: burnScheduled, ttlDays: null };
      }
      case 'dms':
        return { releaseAt: null, timeoutDays, dms: true, burn: false, ttlDays: null };
      default:
        return null;
    }
  }

  async function submit(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    const t = text.trim();
    if (!t || sending) return;
    let drop: DropMeta | null = null;
    if (mode !== 'normal') {
      drop = buildDrop();
      if (!drop) return;
    }
    setSending(true);
    try {
      await onSend(t, drop);
      setText('');
      setMode('normal');
    } catch (err) {
      alert(`Failed to send: ${(err as Error).message}`);
    } finally {
      setSending(false);
    }
  }

  return (
    <section className="chat">
      <div className="chat-head">
        <div>
          <div className="peer">{peer}</div>
          {peerIk && <div className="peer-ik">identity key: {peerIk.slice(0, 24)}…</div>}
        </div>
        <div className="chat-actions">
          <button className="ghost" onClick={onOpenSafety}>
            Safety number
          </button>
        </div>
      </div>
      <div className="msgs">
        {messages.length === 0 && <div className="empty-chat">No messages yet. Send something 🔒</div>}
        {messages.map((m) => {
          const badge = badgeFor(m);
          return (
            <div key={m.uuid} className={`bubble ${m.direction === 'in' ? 'in' : 'out'}`}>
              <div>{m.text || (m.status === 'error' ? '(no text — local failure)' : '')}</div>
              <div className="meta">
                <span>{fmtTime(m.sentAt)}</span>
                {m.kind === 'drop' && <span className="badge drop">drop</span>}
                {badge && <span className={`badge ${badge.cls}`}>{badge.label}</span>}
              </div>
              {m.error && <div className="msg-error">{m.error}</div>}
            </div>
          );
        })}
        <div ref={endRef} />
      </div>
      <form className="composer" onSubmit={(e) => void submit(e)}>
        <div className="composer-options">
          <select value={mode} onChange={(e) => setMode(e.target.value as DropMode)}>
            <option value="normal">Normal message</option>
            <option value="burn">Immediate burn drop 🔥</option>
            <option value="ttl">Immediate drop with TTL</option>
            <option value="scheduled">Scheduled drop</option>
            <option value="dms">DMS drop (dead man's switch)</option>
          </select>
          {mode === 'ttl' && (
            <>
              <label>TTL (days):</label>
              <input type="number" min={1 / 24} max={3650} step={1 / 24} value={ttlDays} onChange={(e) => setTtlDays(Number(e.target.value))} style={{ width: 90 }} />
            </>
          )}
          {mode === 'scheduled' && (
            <>
              <input type="datetime-local" value={releaseAt} onChange={(e) => setReleaseAt(e.target.value)} />
              <label><input type="checkbox" checked={burnScheduled} onChange={(e) => setBurnScheduled(e.target.checked)} /> burn on read</label>
            </>
          )}
          {mode === 'dms' && (
            <>
              <label>Timeout (days, 1-3650):</label>
              <input type="number" min={1} max={3650} value={timeoutDays} onChange={(e) => setTimeoutDays(Number(e.target.value))} style={{ width: 90 }} />
            </>
          )}
        </div>
        <div className="composer-row">
          <textarea
            placeholder={`E2EE message to ${peer}…`}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <button className="primary" disabled={sending || !text.trim()}>
            {sending ? '…' : 'Send'}
          </button>
        </div>
        {mode === 'dms' && (
          <p className="drop-note">
            The drop is released automatically if you stop sending heartbeats for {timeoutDays} day(s).
            The app sends a heartbeat every 30s while open.
          </p>
        )}
        {mode === 'scheduled' && (
          <p className="drop-note">
            Released from the chosen date (minimum 1 minute in the future). {burnScheduled ? 'Deleted after being read.' : 'No TTL — stays until manually deleted.'}
          </p>
        )}
      </form>
    </section>
  );
}
