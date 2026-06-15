// Lightweight client for the warden daemon. Imports only node:net — none of the
// classifier — so the hook's fast path stays cheap.
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

export function wardenSocket() {
  if (process.env.WARDEN_SOCKET) return process.env.WARDEN_SOCKET;
  return process.platform === 'win32' ? '\\\\.\\pipe\\warden' : path.join(os.tmpdir(), 'warden.sock');
}

/**
 * Discovery file the daemon writes (0600) with its loopback fast-hook port + pid.
 * The native client (warden-fast) reads this to find the daemon — same path on
 * every platform, so the compiled binary needs zero platform-specific logic.
 */
export function wardenInfoFile() {
  if (process.env.WARDEN_INFO) return process.env.WARDEN_INFO;
  const home = process.env.USERPROFILE || process.env.HOME || os.homedir();
  return path.join(home, '.warden', 'daemon.json');
}

/**
 * Send one { action, skillText } to the daemon and resolve its verdict.
 * Resolves null on ANY failure (no daemon, timeout, bad reply) so the caller
 * can fall back to an in-process check.
 */
// The daemon's capability token, read from the 0600 discovery file. Only a
// process that can read that file (the owner) can authenticate.
export function wardenToken() {
  try { return JSON.parse(fs.readFileSync(wardenInfoFile(), 'utf8')).token || undefined; } catch { return undefined; }
}

export function daemonCheck(payload, { socketPath = wardenSocket(), timeoutMs = 1500 } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; try { sock.destroy(); } catch {} resolve(v); } };
    const sock = net.connect(socketPath);
    const to = setTimeout(() => finish(null), timeoutMs);
    let buf = '';
    const msg = { ...payload, token: payload.token ?? wardenToken() };
    sock.on('connect', () => sock.write(JSON.stringify(msg) + '\n'));
    sock.on('data', (d) => {
      buf += d.toString();
      const i = buf.indexOf('\n');
      // An { error } reply (e.g. unauthorized) resolves to null so the caller
      // falls back to an in-process check — screening continues, never fails open.
      if (i >= 0) { clearTimeout(to); try { const r = JSON.parse(buf.slice(0, i)); finish(r && r.error ? null : r); } catch { finish(null); } }
    });
    sock.on('error', () => { clearTimeout(to); finish(null); });
    sock.on('close', () => { clearTimeout(to); finish(null); });
  });
}
