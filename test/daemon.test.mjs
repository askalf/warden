import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startDaemon } from '../src/daemon.mjs';
import { daemonCheck } from '../src/client.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const sock = process.platform === 'win32'
  ? '\\\\.\\pipe\\warden-test-' + process.pid
  : '/tmp/warden-test-' + process.pid + '.sock';

// Private, unguessable temp dir (random name, 0700) — no predictable tmpdir paths.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-daemon-'));

test('daemon round-trip: block + allow', async () => {
  const server = startDaemon({ socketPath: sock, configPath: null });
  await new Promise((r) => setTimeout(r, 150));
  try {
    const blk = await daemonCheck({ action: { tool: 'shell', input: { command: 'rm -rf / --no-preserve-root' } } }, { socketPath: sock });
    assert.equal(blk.decision, 'block');
    assert.equal(blk.tier, 'black');
    const ok = await daemonCheck({ action: { tool: 'read', input: { path: 'x' } } }, { socketPath: sock });
    assert.equal(ok.decision, 'allow');
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test('client returns null when no daemon (fallback signal)', async () => {
  const bogus = process.platform === 'win32' ? '\\\\.\\pipe\\warden-none-xyz' : '/tmp/warden-none-xyz.sock';
  const v = await daemonCheck({ action: { tool: 'read', input: {} } }, { socketPath: bogus, timeoutMs: 600 });
  assert.equal(v, null);
});

test('a non-TCP daemon close() does NOT delete a pre-existing info file (cleanup guard)', async () => {
  // regression: a tcp:false daemon (default infoFile) once wiped the live ~/.warden/daemon.json on close.
  const sentinel = path.join(dir, 'sentinel.json');
  fs.writeFileSync(sentinel, JSON.stringify({ pid: 999999, port: 1 }));
  const s2 = process.platform === 'win32' ? '\\\\.\\pipe\\warden-t2-' + process.pid : '/tmp/warden-t2-' + process.pid + '.sock';
  const d = startDaemon({ socketPath: s2, configPath: null, infoFile: sentinel }); // tcp defaults false → does not own the info file
  await new Promise((r) => setTimeout(r, 100));
  await new Promise((r) => d.close(r));
  assert.equal(fs.existsSync(sentinel), true, 'a non-TCP daemon must not delete a pre-existing info file');
  try { fs.unlinkSync(sentinel); } catch {}
});
