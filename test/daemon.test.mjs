import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startDaemon } from '../src/daemon.mjs';
import { daemonCheck } from '../src/client.mjs';

const sock = process.platform === 'win32'
  ? '\\\\.\\pipe\\warden-test-' + process.pid
  : '/tmp/warden-test-' + process.pid + '.sock';

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
