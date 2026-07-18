// Real-world smoke test for the native fast client: spawn the compiled binary
// exactly the way Claude Code invokes a PreToolUse hook — UTF-8 JSON on stdin,
// read one line of stdout — and confirm it relays the daemon's verdict.
// Run: node native/smoke.mjs   (after building the binary; see native/README.md)
import { startDaemon } from '../src/daemon.mjs';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const dir = path.dirname(fileURLToPath(import.meta.url));
const exe = path.join(dir, process.platform === 'win32' ? 'warden-fast.exe' : 'warden-fast-linux-amd64');
if (!fs.existsSync(exe)) { console.error('binary not built:', exe, '\n(see native/README.md)'); process.exit(2); }

const infoFile = path.join(os.tmpdir(), `warden-smoke-${process.pid}.json`);
const sock = process.platform === 'win32' ? `\\\\.\\pipe\\warden-smoke-${process.pid}` : path.join(os.tmpdir(), `warden-smoke-${process.pid}.sock`);

// Async spawn (not spawnSync): the daemon runs in THIS process, so blocking the
// event loop would deadlock the connection. Writes UTF-8 stdin, like CC does.
const run = (payload, extra = {}) => new Promise((resolve) => {
  const c = spawn(exe, [], { env: { ...process.env, WARDEN_INFO: infoFile, ...extra } });
  let out = '';
  c.stdout.on('data', (d) => { out += d.toString(); });
  c.on('close', (code) => resolve({ out, code }));
  c.stdin.end(JSON.stringify(payload));
});

// Send one raw line to the loopback daemon and return the first line back. Used
// to prove the token gate is REAL (an unauthenticated caller gets an empty line)
// — so the malicious case below proves warden-fast authenticated past that gate,
// not that the daemon happens to be open.
const rawAsk = (obj, port) => new Promise((resolve) => {
  const c = net.connect(port, '127.0.0.1');
  let out = '';
  c.on('connect', () => c.write(JSON.stringify(obj) + '\n'));
  c.on('data', (buf) => { out += buf; const i = out.indexOf('\n'); if (i >= 0) { c.end(); resolve(out.slice(0, i)); } });
  c.on('error', () => resolve(null));
  setTimeout(() => { c.destroy(); resolve(out.split('\n')[0]); }, 3000);
});

const d = startDaemon({ socketPath: sock, configPath: null, tcp: true, infoFile });
await new Promise((r) => setTimeout(r, 200));
let ok = true;
try {
  // Precondition: a tcp daemon publishes a per-start capability token, and the
  // loopback listener REQUIRES it. warden-fast must read that token from the
  // discovery file and inject it; if it doesn't, the daemon answers hook-shaped
  // requests with an empty line and the client fails OPEN. Assert the gate is
  // active + rejecting unauthenticated callers, so the deny below is meaningful.
  const info = JSON.parse(fs.readFileSync(infoFile, 'utf8'));
  assert.ok(typeof info.token === 'string' && info.token.length > 0, 'daemon should publish a token');
  const unauth = await rawAsk({ tool_name: 'Bash', tool_input: { command: 'rm -rf /' }, hook_event_name: 'PreToolUse' }, info.port);
  assert.equal(unauth, '', 'unauthenticated hook request must get an empty line (gate active)');
  console.log('token gate -> unauth request rejected  ✓   (empty line, no fail-open)');

  const mal = await run({ tool_name: 'Bash', tool_input: { command: 'rm -rf /' }, hook_event_name: 'PreToolUse' });
  const j = JSON.parse(mal.out);
  assert.equal(j.hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(mal.code, 0);
  console.log('malicious -> deny   ✓   exit', mal.code, ' (authenticated past the token gate) ', mal.out);

  const ben = await run({ tool_name: 'Read', tool_input: { file_path: 'README.md' }, hook_event_name: 'PreToolUse' });
  assert.equal(ben.out, '');
  assert.equal(ben.code, 0);
  console.log('benign    -> defer  ✓   exit', ben.code, '  (empty stdout)');

  // daemon-down must fail SAFE: warden-fast falls back to the node hook, which
  // still screens in-process. A malicious task is denied even with no daemon.
  const noDaemon = {
    WARDEN_INFO: path.join(os.tmpdir(), 'nope-' + process.pid + '.json'),
    WARDEN_SOCKET: process.platform === 'win32' ? `\\\\.\\pipe\\warden-nope-${process.pid}` : path.join(os.tmpdir(), `warden-nope-${process.pid}.sock`),
    WARDEN_NODE: process.execPath,
    WARDEN_FALLBACK_HOOK: path.join(dir, '..', 'src', 'cc-hook.mjs'),
  };
  const down = await run({ tool_name: 'Bash', tool_input: { command: 'rm -rf /' }, hook_event_name: 'PreToolUse' }, noDaemon);
  const dj = JSON.parse(down.out);
  assert.equal(dj.hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(down.code, 0);
  console.log('no daemon -> node fallback SCREENS  ✓   exit', down.code, ' ', down.out.slice(0, 60), '…');
} catch (e) {
  ok = false;
  console.error('FAIL:', e.message);
} finally {
  await new Promise((r) => d.close(r));
}
console.log(ok ? '\nnative smoke PASS' : '\nnative smoke FAIL');
process.exit(ok ? 0 : 1);
