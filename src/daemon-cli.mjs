#!/usr/bin/env node
// warden serve — run the daemon. Reads policy from ~/.warden/config.json,
// audits to ~/.warden/audit.jsonl, listens on the platform socket.
import os from 'node:os';
import path from 'node:path';
import { startDaemon } from './daemon.mjs';
import { wardenSocket } from './client.mjs';

const HOME = process.env.USERPROFILE || process.env.HOME || os.homedir();
const configPath = process.env.WARDEN_CONFIG || path.join(HOME, '.warden', 'config.json');
const auditPath = process.env.WARDEN_AUDIT || path.join(HOME, '.warden', 'audit.jsonl');

startDaemon({ configPath, auditPath, onLog: (m) => process.stderr.write('[warden] ' + m + '\n') });
process.stderr.write('[warden] serve on ' + wardenSocket() + ' — Ctrl-C to stop\n');
