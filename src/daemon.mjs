// warden daemon — a long-lived process that loads the classifier + policy once
// and answers verdicts over a local socket. Maintains a persistent hash-chained
// audit, hot-reloads policy on file change, and (optionally) runs the judge tier.
//
// Two request shapes, one handler:
//   { action, skillText }            -> verdict JSON   (node library client)
//   { tool_name, tool_input, ... }   -> raw hook bytes (native fast client)
// The cc-hook shape lets the compiled `warden-fast` binary stay a dumb byte
// pipe: it forwards Claude Code's hook stdin verbatim and writes back whatever
// the daemon returns. All mapping/classification/formatting stays here in JS.
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { check, checkAsync } from './index.mjs';
import { ChainedFileAudit } from './audit.mjs';
import { loadPolicy } from './policy.mjs';
import { wardenSocket, wardenInfoFile } from './client.mjs';
import { ccToAction, verdictToHook } from './cc-hook.mjs';

// Exact bytes a PreToolUse hook should print on stdout for a verdict.
// deny/ask -> a hookSpecificOutput object; defer/allow -> nothing.
function hookStdout(verdict, strict) {
  const d = verdictToHook(verdict, strict);
  if (d.kind === 'deny' || d.kind === 'ask') {
    return JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: d.kind, permissionDecisionReason: d.reason } });
  }
  return '';
}

export function startDaemon({
  socketPath = wardenSocket(), configPath = null, auditPath = null, judge = null,
  tcp = false, tcpPort = 0, infoFile = wardenInfoFile(), onLog = () => {},
} = {}) {
  let policy = configPath ? loadPolicy(configPath) : {};
  // Tamper-evident, streaming audit straight to disk (no in-memory buffer to leak).
  const fileAudit = auditPath ? new ChainedFileAudit(auditPath) : null;
  // Capability token: published only into the 0600 discovery file, so only a
  // process that can read that file (the owner) can talk to the daemon. Closes
  // the unauth'd-local-process vectors (LLM-proxy abuse via the judge tier,
  // audit pollution). Enforced whenever a token exists; honors WARDEN_TOKEN.
  const token = (tcp || process.env.WARDEN_TOKEN) ? (process.env.WARDEN_TOKEN || crypto.randomBytes(18).toString('base64url')) : null;
  let served = 0;

  // Hot-reload policy on change. unref() so the watcher never keeps the process
  // alive on its own — the listeners do that, and once they close we want exit.
  let watcher = null;
  if (configPath) {
    try { watcher = fs.watch(configPath, () => { policy = loadPolicy(configPath); onLog('policy reloaded'); }); watcher.unref(); } catch {}
  }

  const onConnection = (sock) => {
    let buf = '';
    sock.setTimeout(30000, () => sock.destroy()); // drop idle / half-open connections (handle leak)
    sock.on('data', async (d) => {
      buf += d.toString();
      if (buf.length > 1 << 20) { sock.destroy(); return; } // 1 MB cap — a client that never sends \n can't OOM the daemon
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        let req;
        try { req = JSON.parse(line); } catch { sock.write(JSON.stringify({ error: 'bad json' }) + '\n'); continue; }

        // CC hook fast path: a raw Claude Code PreToolUse payload.
        const isHook = req.tool_name !== undefined || req.hook_event_name !== undefined;

        // Reject unauthenticated callers. Hook shape gets an empty line (the
        // client reads that as "defer" and falls back to its own in-process
        // check — fail-safe, never fail-open); action shape gets an error.
        if (token && req.token !== token) {
          sock.write((isHook ? '' : JSON.stringify({ error: 'unauthorized' })) + '\n'); continue;
        }

        if (req.cmd === 'stats' && req.action === undefined && req.tool_name === undefined) {
          sock.write(JSON.stringify({ served, pid: process.pid }) + '\n'); continue;
        }

        const action = isHook ? ccToAction(req.tool_name, req.tool_input || {}) : req.action;

        try {
          const v = judge
            ? await checkAsync(action, policy, { skillText: req.skillText || '', judge })
            : check(action, policy, { skillText: req.skillText || '' });
          served++;
          if (fileAudit) fileAudit.record({
            ts: new Date().toISOString(), tool: action && action.tool, tier: v.tier,
            decision: v.decision, why: v.why, via: isHook ? 'cc-hook' : 'action',
          });
          if (isHook) sock.write(hookStdout(v, !!(policy && policy.strict)) + '\n');
          else sock.write(JSON.stringify(v) + '\n');
        } catch (e) {
          // Hook path fails open (empty -> defer); action path returns the error.
          sock.write((isHook ? '' : JSON.stringify({ error: String((e && e.message) || e) })) + '\n');
        }
      }
    });
    sock.on('error', () => {});
  };

  if (process.platform !== 'win32') { try { fs.unlinkSync(socketPath); } catch {} } // clear stale socket
  const server = net.createServer(onConnection);
  server.on('error', (e) => onLog('listen error: ' + e.message));
  server.listen(socketPath, () => onLog('listening on ' + socketPath));

  // Optional loopback TCP listener for the native fast client. Bound to
  // 127.0.0.1 only (no network exposure); the ephemeral port is published to
  // the 0600 discovery file so the binary needs no config.
  let tcpServer = null;
  const cleanupInfo = () => { try { fs.unlinkSync(infoFile); } catch {} };
  if (tcp) {
    tcpServer = net.createServer(onConnection);
    tcpServer.on('error', (e) => onLog('tcp listen error: ' + e.message));
    tcpServer.listen(tcpPort, '127.0.0.1', () => {
      const port = tcpServer.address().port;
      try {
        fs.mkdirSync(path.dirname(infoFile), { recursive: true });
        fs.writeFileSync(infoFile, JSON.stringify({ port, pid: process.pid, socket: socketPath, token, started: new Date().toISOString() }), { mode: 0o600 });
      } catch (e) { onLog('info-file write failed: ' + e.message); }
      onLog('fast-hook tcp on 127.0.0.1:' + port);
    });
    for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => { cleanupInfo(); process.exit(0); });
    process.once('exit', cleanupInfo);
  }

  return {
    server, tcp: tcpServer,
    address: () => (tcpServer ? tcpServer.address() : null),
    close(cb) {
      let n = tcpServer ? 2 : 1;
      const done = () => { if (--n <= 0 && cb) cb(); };
      if (tcpServer) cleanupInfo(); // only delete the info file WE wrote — a non-TCP daemon must NOT wipe the live daemon.json
      try { if (watcher) watcher.close(); } catch {}
      try { server.close(done); } catch { done(); }
      if (tcpServer) { try { tcpServer.close(done); } catch { done(); } }
    },
  };
}
