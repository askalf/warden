import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchRule, loadPolicy, DEFAULT_POLICY } from '../src/policy.mjs';

test('matchRule globs on the right tool', () => {
  assert.ok(matchRule('shell(npm run test:*)', { tool: 'shell', input: { command: 'npm run test:unit' } }));
  assert.ok(!matchRule('shell(npm run test:*)', { tool: 'shell', input: { command: 'git push' } }));
  assert.ok(matchRule('shell(sudo*)', { tool: 'shell', input: { command: 'sudo rm' } }));
  assert.ok(!matchRule('write(src/*)', { tool: 'shell', input: { command: 'x' } }));
});

test('loadPolicy on a missing file returns defaults (never throws)', () => {
  assert.deepEqual(loadPolicy('/no/such/file.json'), { ...DEFAULT_POLICY });
});
