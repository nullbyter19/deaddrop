import type { FastifyInstance } from 'fastify';
import type { WebSocket } from 'ws';
import type { Store } from './store.js';

/** Registro userId -> sockets conectados. */
export function registerWs(app: FastifyInstance, store: Store): { notify: (userId: number, event: { type: string; data?: unknown }) => void } {
  const clients = new Map<number, Set<WebSocket>>();

  app.register(async (wsApp) => {
    wsApp.get('/ws', { websocket: true }, (socket, req) => {
      const url = new URL(req.url, 'http://localhost');
      const token = url.searchParams.get('token');
      const user = token ? store.getUserByToken(token) : undefined;
      if (!user) {
        socket.send(JSON.stringify({ type: 'error', data: 'unauthorized' }));
        socket.close(1008, 'unauthorized');
        return;
      }
      const userId = user.id;
      let set = clients.get(userId);
      if (!set) {
        set = new Set();
        clients.set(userId, set);
      }
      set.add(socket);
      socket.send(JSON.stringify({ type: 'hello', data: { username: user.username } }));

      socket.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          if (msg?.type === 'ping') socket.send(JSON.stringify({ type: 'pong' }));
        } catch { /* ignore */ }
      });
      socket.on('close', () => {
        set!.delete(socket);
        if (set!.size === 0) clients.delete(userId);
      });
    });
  });

  const notify = (userId: number, event: { type: string; data?: unknown }): void => {
    const set = clients.get(userId);
    if (!set) return;
    const frame = JSON.stringify(event);
    for (const socket of set) {
      if (socket.readyState === socket.OPEN) socket.send(frame);
    }
  };

  return { notify };
}
