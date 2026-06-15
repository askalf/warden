// Reproducible latency benchmark: native warden-fast vs the node PreToolUse hook,
// both talking to the same warden daemon (run in a SEPARATE process so neither
// hook can deadlock it). Clean UTF-8 payloads, like Claude Code sends.
// Run: node native/bench.mjs [iterations]
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const dir = path.dirname(fileURLToPath(import.meta.url));
const repo = path.dirname(dir);
const exe = path.join(dir, process.platform === 'win32' ? 'warden-fast.exe' : 'warden-fast-linux-amd64');
const ccHook = path.join(repo, 'src', 'cc-hook.mjs');
if (!fs.existsSync(exe)) { console.error('binary not built:', exe); process.exit(2); }

const N = Number(process.argv[2] || 25);
const info = path.join(os.tmpdir(), `warden-bench-${process.pid}.json`);
const sock = process.platform === 'win32' ? `\\\\.\\pipe\\warden-bench-${process.pid}` : path.join(os.tmpdir(), `warden-bench-${process.pid}.sock`);
const audit = path.join(os.tmpdir(), `warden-bench-${process.pid}.jsonl`);
const env = { ...process.env, WARDEN_SOCKET: sock, WARDEN_INFO: info, WARDEN_AUDIT: audit, WARDEN_CONFIG: path.join(os.homedir(), '.warden', 'config.json') };
const PAYLOAD = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: 'README.md' }, hook_event_name: 'PreToolUse' });

const timeOne = (cmd, args, e) => new Promise((resolve) => {
  const t0 = process.hrtime.bigint();
  const c = spawn(cmd, args, { env: e });
  c.stdout.on('data', () => {});
  c.stderr.on('data', () => {});
  c.on('close', () => resolve(Number(process.hrtime.bigint() - t0) / 1e6));
  c.stdin.end(PAYLOAD);
});
const median = (a) => { const s = [...a].sort((x, y) => x - y); const n = s.length; return n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2; };
const stat = (a) => `median ${median(a).toFixed(1).padStart(6)}  min ${Math.min(...a).toFixed(1).padStart(6)}  max ${Math.max(...a).toFixed(1).padStart(6)}`;

const daemon = spawn(process.execPath, [path.join(repo, 'src', 'daemon-cli.mjs')], { env, stdio: 'ignore' });
try {
  for (let i = 0; i < 60 && !fs.existsSync(info); i++) await new Promise((r) => setTimeout(r, 50));
  if (!fs.existsSync(info)) throw new Error('daemon never came up');
  console.log(`daemon up (port ${JSON.parse(fs.readFileSync(info, 'utf8')).port}); ${N} iterations, benign payload\n`);

  // warm both once (page caches, JIT) then measure
  await timeOne(process.execPath, [ccHook], env); await timeOne(exe, [], env);
  const node = [], fast = [];
  for (let i = 0; i < N; i++) { node.push(await timeOne(process.execPath, [ccHook], env)); fast.push(await timeOne(exe, [], env)); }
  console.log('node cc-hook.mjs :', stat(node), 'ms');
  console.log('warden-fast.exe  :', stat(fast), 'ms');
  console.log(`\nspeedup (median) : ${(median(node) / median(fast)).toFixed(1)}x   (saves ~${Math.round(median(node) - median(fast))}ms per tool call)`);
} finally {
  daemon.kill();
}
