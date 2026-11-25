import { useState } from 'react';
import type { Contact } from '../vault';

interface Props {
  username: string;
  contacts: Contact[];
  selected: string | null;
  receiptsCount: number;
  onSelect: (username: string) => void;
  onSearch: (q: string) => Promise<{ username: string; identityKey: string }[]>;
  onAddContact: (username: string, identityKey: string) => Promise<void>;
  onOpenReceipts: () => void;
  onLogout: () => void;
}

export default function Sidebar({
  username, contacts, selected, receiptsCount,
  onSelect, onSearch, onAddContact, onOpenReceipts, onLogout,
}: Props) {
  const [q, setQ] = useState('');
  const [results, setResults] = useState<{ username: string; identityKey: string }[]>([]);
  const [searching, setSearching] = useState(false);

  async function search(term: string): Promise<void> {
    setQ(term);
    if (term.trim().length < 2) {
      setResults([]);
      return;
    }
    setSearching(true);
    try {
      setResults(await onSearch(term.trim()));
    } catch {
      setResults([]);
    } finally {
      setSearching(false);
    }
  }

  async function add(u: string, ik: string): Promise<void> {
    await onAddContact(u, ik);
    setResults([]);
    setQ('');
    onSelect(u);
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-head">
        <h2>DeadDrop</h2>
        <div className="sidebar-user">
          <span className="un">{username}</span>
          <span className="me">you</span>
        </div>
      </div>
      <div className="search-box">
        <input
          placeholder="Search users…"
          value={q}
          onChange={(e) => void search(e.target.value)}
        />
      </div>
      {results.length > 0 && (
        <div className="search-results">
          {results.map((r) => (
            <button key={r.username} onClick={() => void add(r.username, r.identityKey)}>
              {r.username}
            </button>
          ))}
        </div>
      )}
      {searching && <p className="muted center">searching…</p>}
      <div className="contact-list">
        {contacts.length === 0 && (
          <p className="muted center" style={{ marginTop: 20 }}>
            Search for a user to start an encrypted conversation.
          </p>
        )}
        {contacts.map((c) => (
          <button
            key={c.username}
            className={`contact-item${selected === c.username ? ' active' : ''}`}
            onClick={() => onSelect(c.username)}
          >
            <span className="name">{c.username}</span>
            <span className="sub">🔒 E2EE</span>
          </button>
        ))}
      </div>
      <div className="sidebar-foot">
        <button className="ghost" onClick={onOpenReceipts}>
          Receipts {receiptsCount > 0 ? `(${receiptsCount})` : ''}
        </button>
        <button className="ghost" style={{ marginLeft: 'auto' }} onClick={onLogout}>
          Log out
        </button>
      </div>
    </aside>
  );
}
