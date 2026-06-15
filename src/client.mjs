// Lightweight client for the warden daemon. Imports only node:net — none of the
// classifier — so the hook's fast path stays cheap.
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

export function wardenSocket() {
  if (process.env.WARDEN_SOCKET) return process.env.WARDEN_SOCKET;
  return process.platform === 'win32' ? '\\\\.\\pipe\\warden' : path.join(os.tmpdir(), 'warden.sock');
}

/**
 * Send one { action, skillText } to the daemon and resolve its verdict.
 * Resolves null on ANY failure (no daemon, timeout, bad reply) so the caller
 * can fall back to an in-process check.
 */
export function daemonCheck(payload, { socketPath = wardenSocket(), timeoutMs = 1500 } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; try { sock.destroy(); } catch {} resolve(v); } };
    const sock = net.connect(socketPath);
    const to = setTimeout(() => finish(null), timeoutMs);
    let buf = '';
    sock.on('connect', () => sock.write(JSON.stringify(payload) + '\n'));
    sock.on('data', (d) => {
      buf += d.toString();
      const i = buf.indexOf('\n');
      if (i >= 0) { clearTimeout(to); try { finish(JSON.parse(buf.slice(0, i))); } catch { finish(null); } }
    });
    sock.on('error', () => { clearTimeout(to); finish(null); });
    sock.on('close', () => { clearTimeout(to); finish(null); });
  });
}
