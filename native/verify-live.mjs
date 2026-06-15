// Verify warden-fast against the LIVE daemon (~/.warden/daemon.json) — an ops
// check for "is my installed fast-hook actually screening?". Spawns the binary
// the way Claude Code does (UTF-8 stdin) and confirms deny/allow.
// Run: node native/verify-live.mjs
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dir = path.dirname(fileURLToPath(import.meta.url));
const exe = path.join(dir, process.platform === 'win32' ? 'warden-fast.exe' : 'warden-fast-linux-amd64');
const info = process.env.WARDEN_INFO || path.join(os.homedir(), '.warden', 'daemon.json');
if (!fs.existsSync(exe)) { console.error('binary not built:', exe); process.exit(2); }
if (!fs.existsSync(info)) { console.error('no live daemon info file:', info); process.exit(2); }
console.log('live daemon:', fs.readFileSync(info, 'utf8').trim());

const run = (p) => new Promise((r) => {
  const c = spawn(exe, []); // default WARDEN_INFO -> the live daemon
  let o = '';
  c.stdout.on('data', (d) => { o += d.toString(); });
  c.on('close', (code) => r({ o, code }));
  c.stdin.end(JSON.stringify(p));
});

// build the catastrophic command from parts so this file/command never trips a
// live substring scanner while we're testing the live scanner.
const mal = await run({ tool_name: 'Bash', tool_input: { command: ['rm', '-rf', '/'].join(' ') }, hook_event_name: 'PreToolUse' });
const ben = await run({ tool_name: 'Read', tool_input: { file_path: 'README.md' }, hook_event_name: 'PreToolUse' });

let ok = true;
try {
  const j = JSON.parse(mal.o);
  if (j.hookSpecificOutput.permissionDecision !== 'deny') throw new Error('expected deny');
  console.log('malicious -> deny  ✓  ', mal.o);
} catch (e) { ok = false; console.log('malicious FAIL:', JSON.stringify(mal.o), '-', e.message); }
if (ben.o === '') console.log('benign    -> allow ✓   (empty stdout)');
else { ok = false; console.log('benign FAIL (expected empty):', JSON.stringify(ben.o)); }

console.log(ok ? '\nLIVE daemon screening OK' : '\nLIVE verify FAILED');
process.exit(ok ? 0 : 1);
