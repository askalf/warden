// warden daemon — a long-lived process that loads the classifier + policy once
// and answers verdicts over a local socket. Maintains a persistent hash-chained
// audit, hot-reloads policy on file change, and (optionally) runs the judge tier.
import net from 'node:net';
import fs from 'node:fs';
import { check, checkAsync } from './index.mjs';
import { AuditLog } from './audit.mjs';
import { loadPolicy } from './policy.mjs';
import { wardenSocket } from './client.mjs';

export function startDaemon({ socketPath = wardenSocket(), configPath = null, auditPath = null, judge = null, onLog = () => {} } = {}) {
  let policy = configPath ? loadPolicy(configPath) : {};
  const audit = new AuditLog();
  let served = 0;

  if (configPath) {
    try { fs.watch(configPath, () => { policy = loadPolicy(configPath); onLog('policy reloaded'); }); } catch {}
  }

  const server = net.createServer((sock) => {
    let buf = '';
    sock.on('data', async (d) => {
      buf += d.toString();
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        let req;
        try { req = JSON.parse(line); } catch { sock.write(JSON.stringify({ error: 'bad json' }) + '\n'); continue; }
        if (req.action === undefined && req.cmd === 'stats') { sock.write(JSON.stringify({ served }) + '\n'); continue; }
        try {
          const v = judge
            ? await checkAsync(req.action, policy, { audit, skillText: req.skillText || '', judge })
            : check(req.action, policy, { audit, skillText: req.skillText || '' });
          served++;
          if (auditPath) {
            try { fs.appendFileSync(auditPath, JSON.stringify({ ts: new Date().toISOString(), tool: req.action && req.action.tool, tier: v.tier, decision: v.decision, why: v.why }) + '\n'); } catch {}
          }
          sock.write(JSON.stringify(v) + '\n');
        } catch (e) {
          sock.write(JSON.stringify({ error: String(e && e.message || e) }) + '\n');
        }
      }
    });
    sock.on('error', () => {});
  });

  if (process.platform !== 'win32') { try { fs.unlinkSync(socketPath); } catch {} } // clear stale socket
  server.on('error', (e) => onLog('listen error: ' + e.message));
  server.listen(socketPath, () => onLog('listening on ' + socketPath));
  return server;
}
