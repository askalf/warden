import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkAsync } from '../src/index.mjs';
import { stubJudge } from '../src/judge.mjs';

test('judge escalates a gray-zone action', async () => {
  const judge = stubJudge({ write: { tier: 'red', reason: 'touches prod config' } });
  const v = await checkAsync({ tool: 'write', input: { path: 'src/x' } }, {}, { judge });
  assert.equal(v.tier, 'red');
  assert.equal(v.decision, 'approve');
});

test('judge is never consulted for a deterministic black (cannot lower it)', async () => {
  let called = false;
  const judge = async () => { called = true; return { tier: 'green', reason: 'looks fine' }; };
  const v = await checkAsync({ tool: 'shell', input: { command: 'rm -rf /' } }, {}, { judge });
  assert.equal(v.decision, 'block');
  assert.equal(called, false);
});

test('judge is not consulted for clean green actions', async () => {
  let called = false;
  const judge = async () => { called = true; return null; };
  await checkAsync({ tool: 'read', input: { path: 'x' } }, {}, { judge });
  assert.equal(called, false);
});

test('judge failure is fail-safe (keeps deterministic verdict)', async () => {
  const judge = async () => { throw new Error('endpoint down'); };
  const v = await checkAsync({ tool: 'write', input: { path: 'src/x' } }, {}, { judge });
  assert.equal(v.decision, 'allow'); // yellow stays allow; failure didn't crash
});
