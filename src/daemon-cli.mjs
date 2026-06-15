#!/usr/bin/env node
// warden serve — run the daemon. Reads policy from ~/.warden/config.json,
// audits to ~/.warden/audit.jsonl, listens on the platform socket.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startDaemon } from './daemon.mjs';
import { wardenSocket, wardenInfoFile } from './client.mjs';

const HOME = process.env.USERPROFILE || process.env.HOME || os.homedir();
const configPath = process.env.WARDEN_CONFIG || path.join(HOME, '.warden', 'config.json');
const auditPath = process.env.WARDEN_AUDIT || path.join(HOME, '.warden', 'audit.jsonl');

// Don't double-start: if a live daemon already published its info file, bail.
try {
  const prev = JSON.parse(fs.readFileSync(wardenInfoFile(), 'utf8'));
  if (prev && prev.pid) {
    try { process.kill(prev.pid, 0); process.stderr.write('[warden] already running (pid ' + prev.pid + ') — exiting\n'); process.exit(0); }
    catch (e) { if (e && e.code === 'EPERM') { process.stderr.write('[warden] already running (pid ' + prev.pid + ') — exiting\n'); process.exit(0); } }
  }
} catch {}

startDaemon({ configPath, auditPath, tcp: true, onLog: (m) => process.stderr.write('[warden] ' + m + '\n') });
process.stderr.write('[warden] serve on ' + wardenSocket() + ' (+ loopback fast-hook) — Ctrl-C to stop\n');
