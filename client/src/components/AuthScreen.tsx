import { useState } from 'react';
import {
  bytesToB64, createOneTimePreKey, createSignedPreKey, generateIdentity,
} from '@deaddrop/shared';
import type { ServerKeyInfo } from '@deaddrop/shared';
import { api } from '../api';
import { vault } from '../vault';

interface Props {
  onAuth: (token: string, username: string, serverKey: ServerKeyInfo) => Promise<void>;
}

export default function AuthScreen({ onAuth }: Props) {
  const [tab, setTab] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [password2, setPassword2] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function doLogin(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const res = await api.login(username, password);
      if (!(await vault.hasVault())) {
        throw new Error(
          `No local vault found in this browser. DeadDrop is zero-knowledge: your private keys ` +
          `live only in the browser where you registered — never on the server. If you registered ` +
          `before, you may be using a different URL (e.g. localhost vs. your LAN IP), a different ` +
          `browser, or your browser may have cleared site data. Switch to the browser/URL where you ` +
          `registered, or create a new account here.`,
        );
      }
      await vault.unlock(password);
      const id = await vault.getIdentity();
      if (!id || id.username !== res.username) {
        throw new Error(
          `The local vault belongs to "${id?.username}" — it can only unlock that account. ` +
          `To use "${res.username}" in this browser, register a new account.`,
        );
      }
      await onAuth(res.token, res.username, res.serverKey);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  async function doRegister(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setError('');
    if (password !== password2) {
      setError('Passwords do not match');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    setBusy(true);
    try {
      // 1. local identity (X25519 E2EE + Ed25519 signing)
      const id = generateIdentity();
      const spkCounter = Math.floor(Math.random() * 1_000_000) + 1;
      const spk = createSignedPreKey(id.signing.privateKey, spkCounter);
      const opkBase = Math.floor(Math.random() * 1_000_000) + 2_000_000;
      const opks = Array.from({ length: 10 }, (_, i) => createOneTimePreKey(opkBase + i));

      // 2. register on the API (public keys only)
      const res = await api.register({
        username,
        password,
        identityKey: bytesToB64(id.ik.publicKey),
        signingKey: bytesToB64(id.signing.publicKey),
        signedPreKey: {
          keyId: spk.keyId,
          publicKey: bytesToB64(spk.keyPair.publicKey),
          signature: bytesToB64(spk.signature),
        },
        oneTimePreKeys: opks.map((k) => ({
          keyId: k.keyId,
          publicKey: bytesToB64(k.keyPair.publicKey),
        })),
      });

      // 3. encrypted local vault — holds the private keys
      await vault.create(password);
      await vault.setIdentity({
        username: res.username,
        ikPriv: bytesToB64(id.ik.privateKey),
        ikPub: bytesToB64(id.ik.publicKey),
        sigPriv: bytesToB64(id.signing.privateKey),
        sigPub: bytesToB64(id.signing.publicKey),
        spk: {
          keyId: spk.keyId,
          priv: bytesToB64(spk.keyPair.privateKey),
          pub: bytesToB64(spk.keyPair.publicKey),
          sig: bytesToB64(spk.signature),
        },
        spkCounter,
        opks: opks.map((k) => ({
          keyId: k.keyId,
          priv: bytesToB64(k.keyPair.privateKey),
          pub: bytesToB64(k.keyPair.publicKey),
        })),
        opkCounter: opkBase + 10,
        createdAt: Date.now(),
      });

      await onAuth(res.token, res.username, res.serverKey);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap">
      <form className="auth-card" onSubmit={tab === 'login' ? doLogin : doRegister}>
        <h1>DeadDrop</h1>
        <p className="sub">E2EE messenger — X3DH + Double Ratchet, drops with burn/TTL/DMS</p>
        <div className="auth-tabs">
          <button type="button" className={tab === 'login' ? 'active' : ''} onClick={() => setTab('login')}>
            Log in
          </button>
          <button type="button" className={tab === 'register' ? 'active' : ''} onClick={() => setTab('register')}>
            Create account
          </button>
        </div>
        <label>Username (3-32 chars, [a-z0-9_])</label>
        <input
          value={username}
          onChange={(e) => setUsername(e.target.value.toLowerCase())}
          autoFocus
          required
          pattern="[a-z0-9_]{3,32}"
        />
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} />
        {tab === 'register' && (
          <>
            <label>Confirm password</label>
            <input type="password" value={password2} onChange={(e) => setPassword2(e.target.value)} required minLength={8} />
            <p className="auth-note">
              Your E2EE keys are generated locally and stored in an encrypted IndexedDB vault
              (PBKDF2 600k iterations + AES-GCM). The server never sees private keys.
            </p>
          </>
        )}
        <div style={{ marginTop: 18 }}>
          <button className="primary" disabled={busy} style={{ width: '100%' }}>
            {busy ? 'Please wait…' : tab === 'login' ? 'Log in' : 'Create account'}
          </button>
        </div>
        {error && <p className="auth-error">{error}</p>}
        <p className="auth-hint">
          {tab === 'login'
            ? 'Logging in unlocks the local vault with your password. If you never registered in this browser, create an account.'
            : 'After registering, log in with the same password to unlock the vault.'}
        </p>
      </form>
    </div>
  );
}
