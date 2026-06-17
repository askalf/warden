// The native fast client is a dumb byte pipe: it forwards Claude Code's raw hook
// stdin to the daemon over loopback TCP and prints back exactly one line. These
// tests exercise that wire contract from the daemon side (a tiny TCP client
// standing in for the compiled binary), so the .exe stays trivially correct.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startDaemon } from '../src/daemon.mjs';

// Private, unguessable temp dir (random name, 0700) — no predictable tmpdir paths.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-fast-'));
const tmp = (n) => path.join(dir, String(n));
const sockPath = (n) => (process.platform === 'win32' ? `\\\\.\\pipe\\warden-fast-${process.pid}-${n}` : tmp(n) + '.sock');

// One round-trip exactly as the native binary does it: write `<raw hook json>\n`,
// read until the first newline, return the bytes before it (verbatim stdout).
function tcpHook(port, payload, token) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1');
    let buf = '';
    const to = setTimeout(() => { sock.destroy(); reject(new Error('timeout')); }, 2000);
    sock.on('connect', () => sock.write(JSON.stringify(token === undefined ? payload : { ...payload, token }) + '\n'));
    sock.on('data', (d) => {
      buf += d.toString();
      const i = buf.indexOf('\n');
      if (i >= 0) { clearTimeout(to); sock.destroy(); resolve(buf.slice(0, i)); }
    });
    sock.on('error', (e) => { clearTimeout(to); reject(e); });
  });
}

test('fast-hook: block -> exact deny bytes; benign -> empty line; discovery file written', async () => {
  const infoFile = tmp('info') + '.json';
  const d = startDaemon({ socketPath: sockPath('a'), configPath: null, tcp: true, infoFile });
  await new Promise((r) => setTimeout(r, 150));
  try {
    const port = d.address().port;
    assert.ok(port > 0, 'ephemeral port assigned');
    const token = JSON.parse(fs.readFileSync(infoFile, 'utf8')).token;
    assert.ok(token && token.length >= 16, 'a capability token is published');

    // catastrophic shell -> deny, with the precise CC hook envelope
    const denyLine = await tcpHook(port, { tool_name: 'Bash', tool_input: { command: 'rm -rf /' }, hook_event_name: 'PreToolUse' }, token);
    const deny = JSON.parse(denyLine);
    assert.equal(deny.hookSpecificOutput.hookEventName, 'PreToolUse');
    assert.equal(deny.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(deny.hookSpecificOutput.permissionDecisionReason, /warden blocked \(black\)/);

    // benign read -> defer, i.e. the binary prints nothing
    const allowLine = await tcpHook(port, { tool_name: 'Read', tool_input: { file_path: 'README.md' }, hook_event_name: 'PreToolUse' }, token);
    assert.equal(allowLine, '', 'defer emits an empty line (no stdout)');

    // approve-tier under the default (non-strict) policy also defers
    const infraLine = await tcpHook(port, { tool_name: 'Bash', tool_input: { command: 'kubectl delete namespace prod' }, hook_event_name: 'PreToolUse' }, token);
    assert.equal(infraLine, '', 'non-strict policy does not gate approve-tier');

    // UNAUTHENTICATED hook request -> empty line (rejected, not processed)
    const noAuth = await tcpHook(port, { tool_name: 'Bash', tool_input: { command: 'rm -rf /' }, hook_event_name: 'PreToolUse' }, 'wrong-token');
    assert.equal(noAuth, '', 'unauthorized hook request is rejected (defer), never processed');

    // discovery file: 0600-ish, has the port + our pid
    const info = JSON.parse(fs.readFileSync(infoFile, 'utf8'));
    assert.equal(info.port, port);
    assert.equal(info.pid, process.pid);
  } finally {
    await new Promise((r) => d.close(r));
  }
});

test('fast-hook: strict policy gates approve-tier as ask', async () => {
  const cfg = tmp('cfg') + '.json';
  fs.writeFileSync(cfg, JSON.stringify({ strict: true }));
  const infoFile = tmp('info2') + '.json';
  const d = startDaemon({ socketPath: sockPath('b'), configPath: cfg, tcp: true, infoFile });
  await new Promise((r) => setTimeout(r, 150));
  try {
    const port = d.address().port;
    const token = JSON.parse(fs.readFileSync(infoFile, 'utf8')).token;
    const line = await tcpHook(port, { tool_name: 'Bash', tool_input: { command: 'terraform destroy -auto-approve' }, hook_event_name: 'PreToolUse' }, token);
    const v = JSON.parse(line);
    assert.equal(v.hookSpecificOutput.permissionDecision, 'ask');
    assert.match(v.hookSpecificOutput.permissionDecisionReason, /warden flagged \(red\)/);
  } finally {
    await new Promise((r) => d.close(r));
    try { fs.unlinkSync(cfg); } catch {}
  }
});

test('daemon forwards the judge to checkAsync (evasion gray -> judge -> block)', async () => {
  // Guards the daemon-level wiring: startDaemon must pass `judge` INTO checkAsync,
  // not just branch on it. A green+gray evasion request must come back blocked.
  const judge = async () => ({ tier: 'black', reason: 'deobfuscated to rm -rf /' });
  const infoFile = tmp('infoj') + '.json';
  const d = startDaemon({ socketPath: sockPath('j'), configPath: null, tcp: true, judge, infoFile });
  await new Promise((r) => setTimeout(r, 150));
  try {
    const port = d.address().port;
    const token = JSON.parse(fs.readFileSync(infoFile, 'utf8')).token;
    const line = await tcpHook(port, { action: { tool: 'shell', input: { command: 'X=rm; $X -rf /' } } }, token);
    const v = JSON.parse(line);
    assert.equal(v.decision, 'block');
    assert.equal(v.tier, 'black');
  } finally {
    await new Promise((r) => d.close(r));
  }
});
