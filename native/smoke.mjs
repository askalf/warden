// Real-world smoke test for the native fast client: spawn the compiled binary
// exactly the way Claude Code invokes a PreToolUse hook — UTF-8 JSON on stdin,
// read one line of stdout — and confirm it relays the daemon's verdict.
// Run: node native/smoke.mjs   (after building the binary; see native/README.md)
import { startDaemon } from '../src/daemon.mjs';
import { spawn } from 'node:child_process';
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
const run = (payload, info = infoFile) => new Promise((resolve) => {
  const c = spawn(exe, [], { env: { ...process.env, WARDEN_INFO: info } });
  let out = '';
  c.stdout.on('data', (d) => { out += d.toString(); });
  c.on('close', (code) => resolve({ out, code }));
  c.stdin.end(JSON.stringify(payload));
});

const d = startDaemon({ socketPath: sock, configPath: null, tcp: true, infoFile });
await new Promise((r) => setTimeout(r, 200));
let ok = true;
try {
  const mal = await run({ tool_name: 'Bash', tool_input: { command: 'rm -rf /' }, hook_event_name: 'PreToolUse' });
  const j = JSON.parse(mal.out);
  assert.equal(j.hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(mal.code, 0);
  console.log('malicious -> deny   ✓   exit', mal.code, ' ', mal.out);

  const ben = await run({ tool_name: 'Read', tool_input: { file_path: 'README.md' }, hook_event_name: 'PreToolUse' });
  assert.equal(ben.out, '');
  assert.equal(ben.code, 0);
  console.log('benign    -> defer  ✓   exit', ben.code, '  (empty stdout)');

  // daemon-down path must fail open (exit 0, no output) so CC never blocks.
  const down = await run({ tool_name: 'Bash', tool_input: { command: 'ls' } }, path.join(os.tmpdir(), 'nope-' + process.pid + '.json'));
  assert.equal(down.out, '');
  assert.equal(down.code, 0);
  console.log('no daemon -> defer  ✓   exit', down.code, '  (fail-open)');
} catch (e) {
  ok = false;
  console.error('FAIL:', e.message);
} finally {
  await new Promise((r) => d.close(r));
}
console.log(ok ? '\nnative smoke PASS' : '\nnative smoke FAIL');
process.exit(ok ? 0 : 1);
