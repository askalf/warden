import { test } from 'node:test';
import assert from 'node:assert/strict';
import { queryAudit, buildInitPolicy } from '../src/cli.mjs';

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

test('buildInitPolicy returns a valid policy shape', () => {
  const p = buildInitPolicy(process.cwd()); // the warden repo
  assert.ok(Array.isArray(p.egressAllow) && p.egressAllow.includes('api.anthropic.com'));
  assert.equal(p.strict, false);
  assert.ok(Array.isArray(p.deny));
  assert.ok(p.writeRoots && p.writeRoots.includes('src/'));
});
