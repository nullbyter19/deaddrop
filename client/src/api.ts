import type {
  AuthResponse, DeletionReceipt, PreKeyBundle, RegisterPayload,
  ServerKeyInfo, WireMessage,
} from '@deaddrop/shared';

const BASE = '/api/v1';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface OutboxRow {
  payload: WireMessage;
  serverId: number;
  state: 'queued' | 'released' | 'read';
  releasedAt: number | null;
  readAt: number | null;
  deletedAt: number | null;
}

export async function j<T>(
  path: string,
  opts: { method?: string; body?: unknown; token?: string | null } = {},
): Promise<T> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  const res = await fetch(BASE + path, {
    method: opts.method ?? 'GET',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    /* sem corpo */
  }
  if (!res.ok) {
    const msg = (data as { error?: string } | null)?.error ?? `HTTP ${res.status}`;
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

export const api = {
  serverKey: () => j<ServerKeyInfo>('/server-key'),
  register: (body: RegisterPayload) => j<AuthResponse>('/register', { method: 'POST', body }),
  login: (username: string, password: string) =>
    j<AuthResponse>('/auth/login', { method: 'POST', body: { username, password } }),
  logout: (token: string) => j<{ ok: boolean }>('/auth/logout', { method: 'POST', token }),
  searchUsers: (q: string, token: string) =>
    j<{ users: { username: string; identityKey: string }[] }>(
      `/users/search?q=${encodeURIComponent(q)}`,
      { token },
    ),
  bundle: (username: string, token: string) =>
    j<PreKeyBundle>(`/users/${encodeURIComponent(username)}/bundle`, { token }),
  postMessage: (wm: WireMessage, token: string) =>
    j<{ id: string; state: string }>('/messages', { method: 'POST', body: wm, token }),
  getMessages: (token: string) =>
    j<{ messages: WireMessage[]; lastId: number }>('/messages?since=0', { token }),
  getOutbox: (token: string) =>
    j<{ messages: OutboxRow[]; lastId: number }>('/outbox?since=0', { token }),
  markRead: (uuid: string, token: string) =>
    j<{ ok: boolean }>(`/messages/${encodeURIComponent(uuid)}/read`, { method: 'POST', token }),
  deleteMessage: (uuid: string, token: string) =>
    j<{ ok: boolean; receipt: DeletionReceipt | null }>(
      `/messages/${encodeURIComponent(uuid)}`,
      { method: 'DELETE', token },
    ),
  getReceipts: (token: string) =>
    j<{ receipts: DeletionReceipt[]; lastId: number }>('/receipts?since=0', { token }),
  heartbeat: (token: string) => j<{ ok: boolean }>('/heartbeat', { method: 'POST', token }),
  refillOneTimeKeys: (oneTimePreKeys: { keyId: number; publicKey: string }[], token: string) =>
    j<{ ok: boolean; count: number }>('/keys/one-time', { method: 'POST', body: { oneTimePreKeys }, token }),
};

/** WebSocket connection with exponential reconnect + heartbeat (30s, keeps DMS alive). */
export class Live {
  private ws: WebSocket | null = null;
  private retry = 0;
  private stopped = false;
  private heartbeatTimer: number | null = null;
  onEvent: ((ev: { type: string; data?: unknown }) => void) | null = null;

  constructor(private token: string) {}

  start(): void {
    if (this.stopped) return;
    this.connect();
    this.heartbeatTimer = window.setInterval(() => {
      void api.heartbeat(this.token).catch(() => undefined);
    }, 30_000);
  }

  private connect(): void {
    if (this.stopped) return;
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(this.token)}`);
    this.ws = ws;
    ws.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data as string) as { type: string; data?: unknown };
        if (m.type === 'ping') ws.send(JSON.stringify({ type: 'pong' }));
        this.onEvent?.(m);
      } catch {
        /* ignore */
      }
    };
    ws.onclose = () => {
      this.ws = null;
      if (this.stopped) return;
      const delay = Math.min(1000 * 2 ** this.retry, 30_000);
      this.retry += 1;
      window.setTimeout(() => this.connect(), delay);
    };
    ws.onerror = () => {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    };
  }

  stop(): void {
    this.stopped = true;
    try {
      this.ws?.close();
    } catch {
      /* ignore */
    }
    this.ws = null;
    if (this.heartbeatTimer !== null) window.clearInterval(this.heartbeatTimer);
  }
}
