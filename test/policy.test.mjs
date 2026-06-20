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

test('matchRule glob spans newlines (a deny rule can not be bypassed with \\n)', () => {
  // `.`-based globs stopped at \n, silently failing multi-line commands.
  assert.ok(matchRule('shell(*--danger*)', { tool: 'shell', input: { command: 'mytool --danger' } }));
  assert.ok(matchRule('shell(*--danger*)', { tool: 'shell', input: { command: 'echo setup\nmytool --danger' } }));
  assert.ok(matchRule('shell(*rm -rf*)', { tool: 'shell', input: { command: 'cd /tmp\nrm -rf /' } }));
});

test('matchRule is anchored and keeps `.` literal (no regex semantics leak)', () => {
  assert.ok(matchRule('fetch(api.github.com)', { tool: 'fetch', input: { url: 'api.github.com' } }));
  assert.ok(!matchRule('fetch(api.github.com)', { tool: 'fetch', input: { url: 'apiXgithubXcom' } })); // `.` is literal
  assert.ok(!matchRule('shell(npm run test:*)', { tool: 'shell', input: { command: 'x npm run test:unit' } })); // anchored start
  assert.ok(matchRule('shell(*)', { tool: 'shell', input: { command: 'anything\nat all' } }));
});

test('matchRule has no catastrophic backtracking (ReDoS guard)', () => {
  // The old `*`→`.*` compile took minutes on a many-star rule vs a non-matching
  // newline-bearing subject. The linear matcher must return effectively instantly.
  const pat = 'shell(' + '*'.repeat(64) + 'ZZZ)';
  const action = { tool: 'shell', input: { command: 'a'.repeat(2000) + '\n' + 'b'.repeat(2000) } };
  const t = process.hrtime.bigint();
  assert.equal(matchRule(pat, action), false);
  const ms = Number(process.hrtime.bigint() - t) / 1e6;
  assert.ok(ms < 100, `matchRule took ${ms}ms — expected < 100ms (ReDoS regression)`);
});
