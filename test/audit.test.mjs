import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AuditLog, ChainedFileAudit, verifyAuditFile, lastHashOf, chainStateOf, readCheckpoint } from '../src/audit.mjs';

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

test('an interspersed un-chained record is skipped, not read as tampering', () => {
  // A second, non-chained writer (e.g. an in-process hook fallback) can append raw
  // records — no prev/hash — into the same file. The crypto chain around them is
  // still intact, so verify must report ok:true and count them as `unchained`, not
  // hard-fail as if a chained verdict were edited.
  const p = path.join(dir, 'foreign.jsonl');
  try { fs.unlinkSync(p); } catch {}
  const a = new ChainedFileAudit(p);
  a.record({ tool: 'shell', decision: 'block' });
  a.record({ tool: 'read', decision: 'allow' });
  // splice a foreign line into the MIDDLE (between the two chained records)
  const lines = fs.readFileSync(p, 'utf8').trim().split('\n');
  const foreign = JSON.stringify({ tool: 'Read', decision: 'approve', ts: 'x' }); // no prev/hash
  fs.writeFileSync(p, [lines[0], foreign, lines[1]].join('\n') + '\n');
  assert.deepEqual(verifyAuditFile(p), { ok: true, entries: 2, unchained: 1 });
  fs.unlinkSync(p);
});

test('appending a junk line cannot defeat verification of an intact chain', () => {
  const p = path.join(dir, 'junktail.jsonl');
  try { fs.unlinkSync(p); } catch {}
  const a = new ChainedFileAudit(p);
  a.record({ tool: 'shell', decision: 'block' });
  a.record({ tool: 'read', decision: 'allow' });
  fs.appendFileSync(p, JSON.stringify({ note: 'not part of the chain' }) + '\n');
  assert.deepEqual(verifyAuditFile(p), { ok: true, entries: 2, unchained: 1 });
  fs.unlinkSync(p);
});

test('stripping a record’s prev/hash to disguise an edit is still caught', () => {
  // Attacker edits a past verdict AND deletes its prev/hash so it looks un-chained
  // (hoping it gets skipped). The next chained record’s prev no longer links →break.
  const p = path.join(dir, 'strip.jsonl');
  try { fs.unlinkSync(p); } catch {}
  const a = new ChainedFileAudit(p);
  a.record({ tool: 'shell', decision: 'block', why: ['rm -rf /'] });
  a.record({ tool: 'read', decision: 'allow' });
  const lines = fs.readFileSync(p, 'utf8').trim().split('\n');
  const e0 = JSON.parse(lines[0]); e0.decision = 'allow'; delete e0.prev; delete e0.hash;
  lines[0] = JSON.stringify(e0);
  fs.writeFileSync(p, lines.join('\n') + '\n');
  assert.equal(verifyAuditFile(p).ok, false);
  fs.unlinkSync(p);
});

test('lastHashOf returns GENESIS for a missing/empty file', () => {
  assert.equal(lastHashOf(path.join(dir, 'nope.jsonl')), '0'.repeat(64));
});

// ── tail-truncation (the gap a plain hash chain can't see) ──

test('tail-truncation IS caught against a checkpoint', () => {
  const p = path.join(dir, 'trunc.jsonl');
  try { fs.unlinkSync(p); fs.unlinkSync(p + '.chk'); } catch {}
  const a = new ChainedFileAudit(p, { checkpoint: true });
  a.record({ tool: 'read', msg: 'benign 1' });
  a.record({ tool: 'shell', msg: 'MALICIOUS' }); // the entry an attacker wants gone
  a.record({ tool: 'read', msg: 'benign 3' });
  // the sidecar anchors {count:3, head}
  assert.deepEqual(readCheckpoint(p), { head: a.head, count: 3 });
  assert.equal(verifyAuditFile(p).ok, true);
  // attacker truncates back to the first (benign) record — a valid PREFIX
  const lines = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean);
  fs.writeFileSync(p, lines[0] + '\n');
  const r = verifyAuditFile(p);
  assert.equal(r.ok, false, 'truncated tail must be detected');
  assert.equal(r.reason, 'truncated');
  fs.unlinkSync(p); fs.unlinkSync(p + '.chk');
});

test('a restart continues the checkpointed chain and truncation stays detectable', () => {
  const p = path.join(dir, 'trunc-restart.jsonl');
  try { fs.unlinkSync(p); fs.unlinkSync(p + '.chk'); } catch {}
  let a = new ChainedFileAudit(p, { checkpoint: true });
  a.record({ tool: 'shell', msg: '1' });
  a.record({ tool: 'shell', msg: '2' });
  a = new ChainedFileAudit(p, { checkpoint: true }); // "restart": re-seeds head AND count
  assert.equal(a.count, 2);
  a.record({ tool: 'shell', msg: '3' });
  assert.equal(verifyAuditFile(p).ok, true);
  // even after a restart, lopping off the last record is caught
  const lines = fs.readFileSync(p, 'utf8').split('\n').filter(Boolean);
  fs.writeFileSync(p, lines.slice(0, 2).join('\n') + '\n');
  assert.equal(verifyAuditFile(p).ok, false);
  fs.unlinkSync(p); fs.unlinkSync(p + '.chk');
});

test('deleting the whole log is caught when a checkpoint expected records', () => {
  const p = path.join(dir, 'trunc-gone.jsonl');
  try { fs.unlinkSync(p); fs.unlinkSync(p + '.chk'); } catch {}
  const a = new ChainedFileAudit(p, { checkpoint: true });
  a.record({ tool: 'shell', msg: '1' });
  fs.unlinkSync(p); // file gone, sidecar remains
  const r = verifyAuditFile(p);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'truncated');
  fs.unlinkSync(p + '.chk');
});

test('rollback (replaying an older-but-valid chain) is caught against a checkpoint', () => {
  const p = path.join(dir, 'rollback.jsonl');
  try { fs.unlinkSync(p); } catch {}
  const a = new ChainedFileAudit(p);
  a.record({ tool: 'shell', msg: '1' });
  a.record({ tool: 'shell', msg: '2' });
  const good = chainStateOf(p); // remember {head, count:2} out-of-band
  // attacker rewrites the log to a DIFFERENT but internally-valid 1-record chain
  try { fs.unlinkSync(p); } catch {}
  const b = new ChainedFileAudit(p);
  b.record({ tool: 'read', msg: 'forged' });
  assert.equal(verifyAuditFile(p).ok, true, 'the forged chain is internally consistent');
  const r = verifyAuditFile(p, good);
  assert.equal(r.ok, false, 'but it does not match the trusted checkpoint');
  fs.unlinkSync(p);
});

test('a stale checkpoint does NOT false-alarm on a log that grew past it', () => {
  const p = path.join(dir, 'grew.jsonl');
  try { fs.unlinkSync(p); } catch {}
  const a = new ChainedFileAudit(p);
  a.record({ tool: 'shell', msg: '1' });
  a.record({ tool: 'shell', msg: '2' });
  const cp = chainStateOf(p);          // trusted checkpoint at count:2
  a.record({ tool: 'shell', msg: '3' }); // legitimate growth past the checkpoint
  a.record({ tool: 'shell', msg: '4' });
  assert.equal(verifyAuditFile(p, cp).ok, true, 'growth past a checkpoint verifies — only the prefix is pinned');
  fs.unlinkSync(p);
});

test('truncate-and-regrow to the same length is caught by a trusted checkpoint', () => {
  const p = path.join(dir, 'regrow.jsonl');
  try { fs.unlinkSync(p); } catch {}
  const a = new ChainedFileAudit(p);
  a.record({ tool: 'read',  msg: '1' });
  a.record({ tool: 'shell', msg: 'MALICIOUS 2' });
  a.record({ tool: 'read',  msg: '3' });
  const cp = chainStateOf(p);          // trusted {head, count:3} kept off-box
  // attacker truncates entry 1's chain and rebuilds 3 forged records
  try { fs.unlinkSync(p); } catch {}
  const b = new ChainedFileAudit(p);
  b.record({ tool: 'read', msg: '1' });
  b.record({ tool: 'read', msg: 'forged 2' });
  b.record({ tool: 'read', msg: 'forged 3' });
  assert.equal(verifyAuditFile(p).ok, true, 'the forged 3-record chain is internally consistent');
  const r = verifyAuditFile(p, cp);
  assert.equal(r.ok, false, 'but the checkpointed head is not at position 3');
  assert.equal(r.reason, 'rollback');
  fs.unlinkSync(p);
});

test('no checkpoint → verifyAuditFile shape is unchanged (back-compat)', () => {
  const p = path.join(dir, 'nochk.jsonl');
  try { fs.unlinkSync(p); } catch {}
  const a = new ChainedFileAudit(p); // default: no sidecar written
  a.record({ tool: 'shell', decision: 'block' });
  a.record({ tool: 'read', decision: 'allow' });
  assert.equal(readCheckpoint(p), null);
  assert.deepEqual(verifyAuditFile(p), { ok: true, entries: 2 }); // exact legacy shape
  fs.unlinkSync(p);
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
