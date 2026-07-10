#!/usr/bin/env node
// warden-serve — run the daemon. Reads policy from ~/.warden/config.json,
// audits to ~/.warden/audit.jsonl, listens on the platform socket.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startDaemon } from './daemon.mjs';
import { wardenSocket, wardenInfoFile } from './client.mjs';
import { makeJudge } from './judge.mjs';

const HOME = process.env.USERPROFILE || process.env.HOME || os.homedir();
const configPath = process.env.WARDEN_CONFIG || path.join(HOME, '.warden', 'config.json');
const auditPath = process.env.WARDEN_AUDIT || path.join(HOME, '.warden', 'audit.jsonl');

// Opt-in LLM judge tier: set WARDEN_JUDGE_ENDPOINT (any Anthropic-compatible
// endpoint or gateway) to have the daemon deobfuscate gray-zone / evasion-bucket
// commands. No endpoint -> deterministic only (unchanged). Catches regex-evasion
// the gate can't.
const judge = process.env.WARDEN_JUDGE_ENDPOINT
  ? makeJudge({
      endpoint: process.env.WARDEN_JUDGE_ENDPOINT,
      model: process.env.WARDEN_JUDGE_MODEL || 'claude-sonnet-4-6',
      apiKey: process.env.WARDEN_JUDGE_KEY || process.env.ANTHROPIC_API_KEY,
    })
  : null;

// Don't double-start: if a live daemon already published its info file, bail.
try {
  const prev = JSON.parse(fs.readFileSync(wardenInfoFile(), 'utf8'));
  if (prev && prev.pid) {
    try { process.kill(prev.pid, 0); process.stderr.write('[warden] already running (pid ' + prev.pid + ') — exiting\n'); process.exit(0); }
    catch (e) { if (e && e.code === 'EPERM') { process.stderr.write('[warden] already running (pid ' + prev.pid + ') — exiting\n'); process.exit(0); } }
  }
} catch {}

// Cross-call taint is on by default (catches split-exfil across calls on one
// connection); --no-taint or WARDEN_NO_TAINT=1 restores the per-call path.
const taint = !(process.argv.includes('--no-taint') || process.env.WARDEN_NO_TAINT === '1');

startDaemon({ configPath, auditPath, tcp: true, judge, taint, onLog: (m) => process.stderr.write('[warden] ' + m + '\n') });
process.stderr.write('[warden] serve on ' + wardenSocket() + ' (+ loopback fast-hook)' + (judge ? ' + judge tier → ' + process.env.WARDEN_JUDGE_ENDPOINT : '') + ' — Ctrl-C to stop\n');
