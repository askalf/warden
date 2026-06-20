import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AuditLog, ChainedFileAudit, verifyAuditFile, lastHashOf } from '../src/audit.mjs';

// Private, unguessable temp dir (random name, 0700) — no predictable tmpdir paths.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-audit-'));

test('chain verifies when untouched', () => {
  const a = new AuditLog();
  a.record({ x: 1 });
  a.record({ x: 2 });
  assert.equal(a.verify(), true);
});

test('tampering with a past entry breaks verify()', () => {
  const a = new AuditLog();
  a.record({ decision: 'block', tool: 'shell' });
  a.record({ decision: 'allow', tool: 'read' });
  assert.equal(a.verify(), true);
  a.entries[0].decision = 'allow'; // attacker hides a block
  assert.equal(a.verify(), false);
});

test('ChainedFileAudit persists a verifiable chain to disk', () => {
  const p = path.join(dir, 'a.jsonl');
  try { fs.unlinkSync(p); } catch {}
  const a = new ChainedFileAudit(p);
  a.record({ tool: 'shell', decision: 'block' });
  a.record({ tool: 'read', decision: 'allow' });
  assert.deepEqual(verifyAuditFile(p), { ok: true, entries: 2 });
  // a NEW appender continues the chain across "restarts" (seeds from last hash)
  const b = new ChainedFileAudit(p);
  b.record({ tool: 'fetch', decision: 'approve' });
  assert.deepEqual(verifyAuditFile(p), { ok: true, entries: 3 });
  fs.unlinkSync(p);
});

test('editing a line in the on-disk audit is detected', () => {
  const p = path.join(dir, 'b.jsonl');
  try { fs.unlinkSync(p); } catch {}
  const a = new ChainedFileAudit(p);
  a.record({ tool: 'shell', decision: 'block', why: ['rm -rf /'] });
  a.record({ tool: 'read', decision: 'allow' });
  const lines = fs.readFileSync(p, 'utf8').trim().split('\n');
  const e = JSON.parse(lines[0]); e.decision = 'allow';        // attacker rewrites a past verdict
  lines[0] = JSON.stringify(e);
  fs.writeFileSync(p, lines.join('\n') + '\n');
  assert.equal(verifyAuditFile(p).ok, false);
  fs.unlinkSync(p);
});

test('lastHashOf returns GENESIS for a missing/empty file', () => {
  assert.equal(lastHashOf(path.join(dir, 'nope.jsonl')), '0'.repeat(64));
});

test('an oversized final record does not re-root the chain across a restart', () => {
  const p = path.join(dir, 'big.jsonl');
  try { fs.unlinkSync(p); } catch {}
  const a = new ChainedFileAudit(p);
  a.record({ tool: 'shell', decision: 'allow' });
  // a record larger than the 8 KB tail window (e.g. a verdict with a huge `why`)
  a.record({ tool: 'shell', decision: 'block', why: ['x'.repeat(20000)] });
  // lastHashOf must recover the real chain head, not fall back to GENESIS
  const lines = fs.readFileSync(p, 'utf8').trim().split('\n');
  const realHead = JSON.parse(lines[lines.length - 1]).hash;
  assert.equal(lastHashOf(p), realHead);
  assert.notEqual(lastHashOf(p), '0'.repeat(64));
  // a "restart" must CONTINUE the chain (no second GENESIS root mid-file)
  const b = new ChainedFileAudit(p);
  b.record({ tool: 'read', decision: 'allow' });
  assert.deepEqual(verifyAuditFile(p), { ok: true, entries: 3 });
  fs.unlinkSync(p);
});
