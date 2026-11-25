import { useCallback, useEffect, useRef, useState } from 'react';
import type { DeletionReceipt, ServerKeyInfo, WireMessage } from '@deaddrop/shared';
import { api, Live } from './api';
import { vault, type Contact, type LocalMessage } from './vault';
import { decryptIncoming, maybeRefillOpks, sendMessage } from './sessions';
import AuthScreen from './components/AuthScreen';
import Sidebar from './components/Sidebar';
import ChatView from './components/ChatView';
import SafetyDialog from './components/SafetyDialog';
import ReceiptsDialog from './components/ReceiptsDialog';

export default function App() {
  const [authed, setAuthed] = useState(false);
  const [token, setToken] = useState('');
  const [username, setUsername] = useState('');
  const [serverKey, setServerKey] = useState<ServerKeyInfo | null>(null);
  const [ownIk, setOwnIk] = useState('');
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [messages, setMessages] = useState<LocalMessage[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [receipts, setReceipts] = useState<DeletionReceipt[]>([]);
  const [showReceipts, setShowReceipts] = useState(false);
  const [showSafety, setShowSafety] = useState(false);

  const liveRef = useRef<Live | null>(null);
  const syncTimer = useRef<number | null>(null);
  const syncing = useRef(false);

  const reloadLocal = useCallback(async () => {
    const cs = await vault.listContacts();
    setContacts(cs);
    const rs = await vault.listReceipts();
    setReceipts(rs);
    if (selected) setMessages(await vault.listMessagesForPeer(selected));
  }, [selected]);

  const syncAll = useCallback(async () => {
    if (syncing.current) return;
    syncing.current = true;
    try {
      const [inbox, outbox, rc] = await Promise.all([
        api.getMessages(token),
        api.getOutbox(token),
        api.getReceipts(token),
      ]);

      // input: decrypts updates
      for (const wm of inbox.messages) {
        if (await vault.hasMessage(wm.id)) continue;
        try {
          const lm = await decryptIncoming(wm);
          if (!(await vault.getContact(wm.from))) {
            await vault.putContact({ username: wm.from, identityKey: wm.sik, addedAt: Date.now() });
          }
        } catch (err) {
          const lm = await vault.getMessage(wm.id);
          if (!lm) {
            await vault.putMessage({
              uuid: wm.id,
              peer: wm.from,
              direction: 'in',
              kind: wm.drop ? 'drop' : 'normal',
              text: '',
              sentAt: wm.sentAt,
              dropMeta: wm.drop,
              status: 'error',
              error: (err as Error).message,
            });
          }
        }
      }

      // output: updates the state of our messages
      for (const row of outbox.messages) {
        const lm = await vault.getMessage(row.payload.id);
        if (!lm) continue;
        const upd: LocalMessage = { ...lm };
        if (row.state === 'released' && upd.status === 'queued') {
          upd.status = 'released';
          upd.releasedAt = row.releasedAt;
        }
        if (row.state === 'read' && upd.status === 'released') {
          upd.status = 'read';
          upd.readAt = row.readAt;
        }
        if (row.deletedAt !== null) upd.status = 'burned';
        await vault.putMessage(upd);
      }

      // receipts: marks as burned/removed + refreshes the list
      for (const r of rc.receipts) {
        const lm = await vault.getMessage(r.messageId);
        if (lm && lm.direction === 'out' && lm.status !== 'burned') {
          await vault.putMessage({ ...lm, status: 'burned' });
        }
        await vault.putReceipt(r);
      }

      await maybeRefillOpks(token);
      await reloadLocal();
    } catch {
      // transient network errors do not take the app down
    } finally {
      syncing.current = false;
    }
  }, [token, reloadLocal]);

  const handleAuth = useCallback(
    async (tk: string, un: string, sk: ServerKeyInfo) => {
      setToken(tk);
      setUsername(un);
      setServerKey(sk);
      const id = await vault.getIdentity();
      if (!id) throw new Error('Identity missing in vault');
      setOwnIk(id.ikPub);
      await maybeRefillOpks(tk);
      await reloadLocal();
      setAuthed(true);
      await syncAll();

      // sync periodico (15s) — pega drops liberados pelo scheduler
      syncTimer.current = window.setInterval(() => void syncAll(), 15_000);

      const live = new Live(tk);
      live.onEvent = (ev) => {
        if (ev.type === 'message') void syncAll();
      };
      live.start();
      liveRef.current = live;
    },
    [reloadLocal, syncAll],
  );

  useEffect(() => {
    return () => {
      if (syncTimer.current !== null) window.clearInterval(syncTimer.current);
      liveRef.current?.stop();
    };
  }, []);

  async function handleSearch(q: string): Promise<{ username: string; identityKey: string }[]> {
    return (await api.searchUsers(q, token)).users;
  }

  async function handleAddContact(u: string, ik: string): Promise<void> {
    await vault.putContact({ username: u, identityKey: ik, addedAt: Date.now() });
    await reloadLocal();
  }

  async function handleSend(text: string, drop: LocalMessage['dropMeta']): Promise<void> {
    if (!selected) return;
    await sendMessage(selected, text, drop, username, token);
    await reloadLocal();
  }

  async function handleMarkRead(uuid: string): Promise<void> {
    try {
      await api.markRead(uuid, token);
    } catch {
      /* drop already deleted or unavailable */
    }
    const lm = await vault.getMessage(uuid);
    if (lm) {
      await vault.putMessage({ ...lm, status: 'burned', readAt: Date.now() });
      await reloadLocal();
    }
  }

  async function handleLogout(): Promise<void> {
    if (syncTimer.current !== null) {
      window.clearInterval(syncTimer.current);
      syncTimer.current = null;
    }
    liveRef.current?.stop();
    liveRef.current = null;
    try {
      await api.logout(token);
    } catch {
      /* ignore */
    }
    vault.lock();
    setAuthed(false);
    setToken('');
    setUsername('');
    setServerKey(null);
    setOwnIk('');
    setContacts([]);
    setMessages([]);
    setSelected(null);
    setReceipts([]);
  }

  if (!authed) {
    return <AuthScreen onAuth={handleAuth} />;
  }

  const peerIk =
    selected && (contacts.find((c) => c.username === selected)?.identityKey ?? null);

  return (
    <div className="app">
      <Sidebar
        username={username}
        contacts={contacts}
        selected={selected}
        receiptsCount={receipts.length}
        onSelect={(u) => {
          setSelected(u);
          void reloadLocal();
        }}
        onSearch={handleSearch}
        onAddContact={handleAddContact}
        onOpenReceipts={() => setShowReceipts(true)}
        onLogout={() => void handleLogout()}
      />
      {selected ? (
        <ChatView
          peer={selected}
          peerIk={peerIk}
          messages={messages}
          onSend={handleSend}
          onMarkRead={(u) => void handleMarkRead(u)}
          onOpenSafety={() => setShowSafety(true)}
        />
      ) : (
        <div className="empty-chat" style={{ flex: 1 }}>
          Select a contact to get started.
        </div>
      )}
      {showSafety && selected && peerIk && (
        <SafetyDialog peer={selected} ownIk={ownIk} peerIk={peerIk} onClose={() => setShowSafety(false)} />
      )}
      {showReceipts && serverKey && (
        <ReceiptsDialog receipts={receipts} serverKeyPub={serverKey.publicKey} onClose={() => setShowReceipts(false)} />
      )}
    </div>
  );
}
