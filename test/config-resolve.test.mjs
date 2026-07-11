// The project-config rename: `redstamp init` writes redstamp.config.json, but an
// existing warden.config.json (pre-rename) is still read transparently so a
// project set up before the rename keeps working. resolveConfig() is the shared
// chokepoint for `check` and the MCP proxy. (Global ~/.warden/config.json and
// WARDEN_* env vars are intentionally kept — not covered here.)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveConfig, DEFAULT_CONFIG, LEGACY_CONFIG, loadPolicy } from '../src/policy.mjs';

const mkdir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'rs-config-'));

test('the rename constants: redstamp.config.json (new) with warden.config.json legacy', () => {
  assert.equal(DEFAULT_CONFIG, 'redstamp.config.json');
  assert.equal(LEGACY_CONFIG, 'warden.config.json');
});

test('resolveConfig: an explicit --policy path always wins', () => {
  assert.equal(resolveConfig('my.policy.json', mkdir()), 'my.policy.json');
});

test('resolveConfig: prefers redstamp.config.json when both exist', () => {
  const d = mkdir();
  fs.writeFileSync(path.join(d, 'redstamp.config.json'), '{}');
  fs.writeFileSync(path.join(d, 'warden.config.json'), '{}');
  assert.equal(resolveConfig(null, d), path.join(d, 'redstamp.config.json'));
});

test('resolveConfig: falls back to an existing warden.config.json (pre-rename project)', () => {
  const d = mkdir();
  fs.writeFileSync(path.join(d, 'warden.config.json'), '{}');
  assert.equal(resolveConfig(null, d), path.join(d, 'warden.config.json'));
});

test('resolveConfig: defaults to redstamp.config.json when neither exists', () => {
  const d = mkdir();
  assert.equal(resolveConfig(null, d), path.join(d, 'redstamp.config.json'));
});

test('end to end: a legacy warden.config.json policy is still loaded by default', () => {
  const d = mkdir();
  fs.writeFileSync(path.join(d, 'warden.config.json'), JSON.stringify({ deny: ['shell(rm*)'] }));
  const p = loadPolicy(resolveConfig(null, d)); // no --policy → resolver finds warden.config.json
  assert.deepEqual(p.deny, ['shell(rm*)'], 'the pre-rename config still drives policy');
});
