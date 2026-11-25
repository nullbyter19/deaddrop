# DeadDrop 🔒

**Zero-knowledge E2EE messenger** with conditional *drops* (ephemeral messages with scheduled release, TTL and self-destruction on read) and server-signed **deletion proofs**.

- **Cryptography**: X3DH + Double Ratchet (Signal protocol) over Curve25519, AES-256-GCM, HKDF-SHA256
- **Server**: Fastify + SQLite (Node ≥ 22.5; the `run.mjs` launcher manages the `--experimental-sqlite` flag) — stores ciphertext + metadata only
- **Client**: React/Vite (SPA served by the server itself, same origin), local vault encrypted in IndexedDB
- **UI language**: English

```
┌──────────────┐          ┌──────────────────────┐          ┌──────────────┐
│  Alice       │  HTTPS   │  DeadDrop Server     │  HTTPS   │  Bob         │
│  (browser)   │─────────▶│  Fastify + SQLite    │◀────────│  (browser)   │
│  X3DH/DR     │  JWTs    │  ciphertext+meta only│  JWTs    │  X3DH/DR     │
└──────────────┘          └──────────────────────┘          └──────────────┘
```

---

## Architecture

npm workspaces (`npm workspaces`):

| Workspace | Role |
|---|---|
| `shared/` | Cryptographic core and wire types: X3DH, Double Ratchet, AEAD, SPK/OPK, safety numbers, deletion receipts, drop validation, base64/utf8 codec. Used by server and client. |
| `server/` | REST API + WebSocket + drop scheduler. Bearer token authentication, SQLite persistence, Ed25519 receipt signing, serves the client build (`client/dist`) as a SPA. |
| `client/` | React 19 + Vite SPA. Local encrypted vault (IndexedDB), persisted ratchet sessions, polling + WebSocket sync, UI in English. |

### Message flow (first session)

1. **Alice registers** and sends the server: identity key (X25519), signing key (Ed25519), a signed Signed PreKey (SPK) and 10 One-Time PreKeys (OPKs). She receives `serverKey` (the server's Ed25519 public key, used to verify receipts).
2. **Alice fetches Bob's bundle** (`GET /users/:username/bundle`) → IK, SPK + signature, 1 OPK. She **verifies the SPK signature** with Bob's signing key (protection against a malicious server swapping prekeys).
3. **X3DH (initiator)**: `SK = HKDF(FF*32 ‖ DH1(IKA,SPKB) ‖ DH2(EKA,IKB) ‖ DH3(EKA,SPKB) ‖ [DH4(EKA,OPKB)])`.
4. **Double Ratchet**: Alice starts with `initAlice(SK, EKA, SPKB)`; the first message header carries `dh = EKA` plus the `spkId`/`opkId` used.
5. **Bob reconstructs**: `x3dhResponder(IKBpriv, SPKBpriv, OPKBpriv, IKApub, EKApub)` → same SK → `initBob` → decrypts. He consumes the local OPK (the server already removed it from the bundle).
6. Following messages use the **same session** (header with `dh`, `pn`, `ns`, `n`, `mtype`); the ratchet advances with new DHs every round (forward secrecy).
7. The server **never sees** the keys or the plaintext — only the envelope (header + ciphertext + routing metadata).

### Drops (ephemeral messages)

- **Scheduled**: `releaseAt` ≥ now + 60 s (validated on the server); the drop stays `queued` and the scheduler (every 10 s) releases it → `released` (it remains inaccessible in the recipient's inbox until then).
- **TTL**: `ttlDays` (1/24–3650); the server deletes the message automatically after the deadline.
- **Burn**: on marking as read (`POST /messages/:uuid/read`), the server deletes it and generates a **signed deletion receipt** for the sender.
- **DMS (Disappearing)**: a drop with neither `releaseAt` nor `burn`, released on first read; it requires `ttlDays` or `burn` to be valid as "immediate".
- **Receipts**: `DeletionReceipt { messageId, recipient, deletedAt, reason: burn|explicit, sig }` signed with the server's Ed25519 key; `shared.verifyReceipt(serverPub, receipt)` validates it.

### REST API (`/api/v1`)

| Method | Route | Description |
|---|---|---|
| POST | `/register` | Creates a user, returns `{ token, serverKey }` |
| GET | `/users/:username/bundle` | Bundle (IK, signing, SPK, 1 OPK) to start a session |
| POST | `/keys/one-time` | OPK refill (1–100), validates the base64 format |
| POST | `/messages` | Publishes an encrypted envelope (or drop) |
| GET | `/messages?since=` | Inbox (`released` only), incremental cursor |
| POST | `/messages/:uuid/read` | Marks as read; triggers burn + receipt when applicable |
| DELETE | `/messages/:uuid` | Deletion with receipt (recipient/sender) |
| GET | `/outbox?since=` | Sent messages + states (queued/released/read/deleted) |
| GET | `/receipts?since=` | Deletion receipts for the sender |
| POST | `/heartbeat` | Updates last-seen (DMS) |
| WS | `/ws` | Push notifications (message/read/delete/receipt) |
| GET | `/api/v1/health` | Healthcheck |

### Client (local vault)

- **IndexedDB** `deaddrop-vault` v1: stores `vaultkey`, `identity`, `sessions`, `contacts`, `messages`, `receipts`.
- **KEK**: PBKDF2-SHA256 (600,000 iterations) derived from the password; the AES-256-GCM vault key is wrapped by that KEK; identity/sessions/messages/contacts encrypted; receipts in cleartext (already signed by the server).
- **Per-peer session** (username), state serialized with `exportState`/`importState` — allows reloading and resuming the ratchet.
- **OPK refill**: when `opks.length ≤ 2`, it generates 10 new ones (incremental `opkCounter`) and sends them to the server.
- **Sync**: `GET /messages?since=` polling + WebSocket; dedupe by `uuid`; the `since` cursor only advances by the server's `lastId` (late-released drops are not lost). The outbox dedupes/updates by `uuid`.
- **Safety number**: 12 groups of 5 digits (Signal style), `SHA256("DeadDrop-SafetyNumber-v1" ‖ min(IKA,IKB) ‖ max(IKA,IKB))`.

---

## Threat model

Assumptions: honest-but-curious server (follows the protocol but tries to read the content); the adversary may be a compromised server, a network observer, or a third party with database access.

| Threat | Mitigation | Status |
|---|---|---|
| Server reads message content | End-to-end encryption (X3DH + Double Ratchet); the server only sees ciphertext | ✅ mitigated |
| Server swaps Bob's SPK/OPK for MITM | Ed25519 SPK signature verified by the client; a consumed OPK is destroyed after one use | ✅ mitigated |
| Compromise of an old session key | Forward secrecy: ratchet with new DHs + per-message KDF | ✅ mitigated |
| Compromise of the client password/DB | Encrypted AES-256-GCM vault with a PBKDF2 600k-iteration KEK | ✅ mitigated |
| Server forges a message deletion | Ed25519-signed receipts, verifiable with `serverKey` | ✅ mitigated |
| Server reads metadata (who talks to whom, when) | **Not mitigated** — routing metadata stays in cleartext (design limitation, same as Signal) | ⚠️ residual |
| Replay of old messages | Incremental `since` + per-uuid dedupe on the client; ratchet state detects repeated headers (skipped/duplicates) | ✅ mitigated (partial) |
| Active adversary (network MITM) | TLS mandatory in production; safety number for out-of-band verification | ⚠️ depends on TLS deployment + manual verification |
| Vault key loss / password reset | There is no key recovery by design (zero-knowledge); a reset creates a new identity and loses history | ✅ by design |
| DDoS / registration abuse | No rate limiting implemented — **pending for production** | ❌ pending |

### Honest limitations
- The server knows **who** exchanges messages with **whom**, plus sizes and times (metadata).
- Long-term secret: the **identity key** is not rotated; compromising it (together with the prekeys) breaks retroactive confidentiality.
- The client depends on the integrity of the served code (no subresource integrity / JS bundle signature — like any webapp).

---

## Local deployment

Prerequisites: **Node ≥ 22.5** (the native `node:sqlite` module was introduced in Node 22.5). The `server/run.mjs` launcher applies `--experimental-sqlite` automatically only on Node 22.5–23.3; on Node ≥ 23.4 the module is stable and runs without the flag; on Node < 22.5 the server aborts with a clear error.

```bash
# 1. dependencies + build
cd DeadDrop
npm install
npm run build            # shared -> server -> client

# 2. server (SPA + API on the same origin, port 8080)
npm run start            # node run.mjs dist/index.js (version-aware launcher)

# 3. open
open http://127.0.0.1:8080
```

Linux server deployment (no desktop):

```bash
# check the version (requires >= 22.5; Node 22 LTS or 24 recommended)
node -v

# extract the project (e.g. from DeadDrop-*.tar.gz) into /opt/DeadDrop and:
npm install
npm run build            # shared -> server -> client
npm run start            # API + SPA on http://127.0.0.1:8080

# healthcheck
curl http://127.0.0.1:8080/api/v1/health

# server as a service (systemd)
# /etc/systemd/system/deaddrop.service:
#   [Unit]
#   Description=DeadDrop E2EE messenger
#   After=network.target
#   [Service]
#   WorkingDirectory=/opt/DeadDrop/server
#   ExecStart=/usr/bin/node run.mjs dist/index.js
#   Restart=on-failure
#   User=deaddrop
#   [Install]
#   WantedBy=multi-user.target
```

### Exposing on the LAN — HTTPS is mandatory

The client vault uses `crypto.subtle` (Web Crypto API), which browsers only enable in
**secure contexts** (HTTPS or `localhost`). Served over plain HTTP on a LAN IP, the app does
not work. That is why the server has **built-in TLS** through `DEADDROP_TLS_CERT`/`DEADDROP_TLS_KEY`:

```bash
# 1. generate a self-signed certificate (adjust the SAN IP/DNS for your machine)
mkdir -p /opt/DeadDrop/certs && cd /opt/DeadDrop/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout key.pem -out cert.pem \
  -subj "/CN=deaddrop" -addext "subjectAltName=IP:192.0.2.10,DNS:deaddrop.local"

# 2. open the port in the firewall
sudo ufw allow 8080/tcp

# 3. start the server exposed on the LAN with TLS (restricted key permissions)
chmod 600 /opt/DeadDrop/certs/key.pem
cd /opt/DeadDrop
DEADDROP_HOST=0.0.0.0 \
DEADDROP_TLS_CERT=/opt/DeadDrop/certs/cert.pem \
DEADDROP_TLS_KEY=/opt/DeadDrop/certs/key.pem \
npm run start

# 4. find the machine IP and access it from another device
hostname -I
# https://192.0.2.10:8080  (accept the self-signed certificate warning)
```

Equivalent alternative: `DEADDROP_HOST=0.0.0.0` **behind a TLS reverse proxy**
(Caddy/Nginx) — the client detects `https` on its own and works the same way. In any topology,
**verify the safety numbers out-of-band** between users: TLS protects the transport,
but the safety numbers are what protect against a server MITM.

Development (hot reload):

```bash
npm run dev:server       # tsx watch (API on :8080)
npm run dev:client       # vite dev server (SPA on :5173, proxy /api -> :8080)
```

Configuration through env (`server/src/config.ts`):

| Variable | Default | Description |
|---|---|---|
| `DEADDROP_PORT` | `8080` | Server port |
| `DEADDROP_HOST` | `127.0.0.1` | Bind address (use `0.0.0.0` when exposing) |
| `DEADDROP_DATA_DIR` | `<cwd>/data` | Data directory (DB + signing key) |
| `DEADDROP_DB_PATH` | `$DEADDROP_DATA_DIR/deaddrop.db` | SQLite file |
| `DEADDROP_WS_PING_MS` | `30000` | WebSocket ping interval |
| `DEADDROP_LOG_LEVEL` | `info` | Fastify log level |
| `DEADDROP_TLS_CERT` | *(empty)* | TLS certificate path — enables built-in HTTPS (e.g. `/opt/DeadDrop/certs/cert.pem`) |
| `DEADDROP_TLS_KEY` | *(empty)* | TLS private key path — use together with `DEADDROP_TLS_CERT` |

> The client build is served from `../client/dist` relative to the server's cwd — run the server through `npm run start` (the `server/` workspace) so the path resolves correctly. There is no env var for this.

The receipt signing key lives in `server/data/server_signing_key.json` (mode 0600), generated on first run — **back it up** if you want receipts to remain verifiable across restarts.

## Tests

```bash
npm test -w @deaddrop/shared     # unit: crypto (6) + ratchet (7) — 13 tests
# E2E against the real server (Alice↔Bob) — run with the server up:
node e2e/smoke.mjs          # registration, bundle+SPK, two-way X3DH/DR, burn drop, receipts
node e2e/client-flow.mjs    # mirrors the client logic: refill, OPK, outbox, receipts
```

## Structure

```
DeadDrop/
├── shared/src/   keys.ts x3dh.ts ratchet.ts cipher.ts hkdf.ts receipts.ts safety.ts drops.ts types.ts util.ts
├── server/src/   index.ts api.ts store.ts db.ts ws.ts drops.ts config.ts
├── client/src/   main.tsx App.tsx api.ts vault.ts sessions.ts styles.css
│                 components/{AuthScreen,Sidebar,ChatView,SafetyDialog,ReceiptsDialog}.tsx
└── README.md
```

## License

MIT — see [LICENSE](LICENSE).
