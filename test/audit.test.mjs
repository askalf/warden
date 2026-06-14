import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AuditLog } from '../src/audit.mjs';

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
