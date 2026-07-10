import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { queryAudit, buildInitPolicy, formatVerify } from '../src/cli.mjs';
import { ChainedFileAudit, verifyAuditFile } from '../src/audit.mjs';

test('queryAudit summarizes and filters', () => {
  const lines = [
    { decision: 'allow', tier: 'green', tool: 'read' },
    { decision: 'block', tier: 'black', tool: 'shell' },
    { decision: 'approve', tier: 'red', tool: 'shell' },
    { decision: 'block', tier: 'black', tool: 'write' },
  ];
  const all = queryAudit(lines);
  assert.equal(all.total, 4);
  assert.deepEqual(all.byDecision, { allow: 1, block: 2, approve: 1 });
  assert.equal(queryAudit(lines, { blocksOnly: true }).shown, 2);
  assert.equal(queryAudit(lines, { tier: 'black' }).shown, 2);
  assert.equal(queryAudit(lines, { tail: 1 }).rows.length, 1);
});

test('queryAudit normalizes the legacy "kind" field to a decision', () => {
  const lines = [{ tier: 'black', kind: 'deny', tool: 'shell' }, { tier: 'green', kind: 'defer', tool: 'read' }];
  assert.equal(queryAudit(lines, { blocksOnly: true }).shown, 1);
  assert.equal(queryAudit(lines).byDecision.block, 1);
});

// ── `warden verify` — CLI surface for the tamper-evident audit (#47) ──
test('formatVerify: intact chain → exit 0, entry count', () => {
  const r = formatVerify({ ok: true, entries: 3 });
  assert.equal(r.exitCode, 0);
  assert.match(r.message, /audit intact — 3 chained entries/);
});

test('formatVerify: intact with unchained/foreign lines is surfaced, not a failure', () => {
  const r = formatVerify({ ok: true, entries: 2, unchained: 1 });
  assert.equal(r.exitCode, 0);
  assert.match(r.message, /2 chained entries \(1 unchained\/foreign line skipped\)/);
});

test('formatVerify: tamper → exit 2 with the offending index', () => {
  const r = formatVerify({ ok: false, at: 4 });
  assert.equal(r.exitCode, 2);
  assert.match(r.message, /TAMPER DETECTED at entry 4/);
});

test('warden verify end-to-end: intact passes, a tampered entry is caught', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-verify-'));
  const p = path.join(dir, 'audit.jsonl');
  const a = new ChainedFileAudit(p);
  a.record({ ts: 't1', tool: 'read', tier: 'green', decision: 'allow', why: [] });
  a.record({ ts: 't2', tool: 'shell', tier: 'black', decision: 'block', why: ['rce'] });

  // intact
  const intact = formatVerify(verifyAuditFile(p));
  assert.equal(intact.exitCode, 0);
  assert.match(intact.message, /audit intact — 2 chained entries/);

  // tamper: edit a chained entry's tier in place, re-verify
  const lines = fs.readFileSync(p, 'utf8').trim().split('\n');
  lines[1] = lines[1].replace('"tier":"black"', '"tier":"green"');
  fs.writeFileSync(p, lines.join('\n') + '\n');
  const tampered = formatVerify(verifyAuditFile(p));
  assert.equal(tampered.exitCode, 2);
  assert.match(tampered.message, /TAMPER DETECTED at entry 1/);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('warden verify: a missing audit file is treated as empty/intact (exit 0)', () => {
  const r = formatVerify(verifyAuditFile(path.join(os.tmpdir(), 'warden-verify-nope-' + process.pid + '.jsonl')));
  assert.equal(r.exitCode, 0);
  assert.match(r.message, /audit intact — 0 chained entries/);
});

test('buildInitPolicy returns a valid policy shape', () => {
  const p = buildInitPolicy(process.cwd()); // the warden repo
  assert.ok(Array.isArray(p.egressAllow) && p.egressAllow.some((h) => h === 'api.anthropic.com'));
  assert.equal(p.strict, false);
  assert.ok(Array.isArray(p.deny));
  assert.ok(p.writeRoots && p.writeRoots.includes('src/'));
});
