#!/usr/bin/env node
// warden as a Claude Code PreToolUse hook.
// Fast path: ask the warden daemon (shared classifier + audit). Fallback: run an
// in-process check if the daemon isn't running. Fail-open: any error -> defer,
// so a warden bug never bricks your tooling.
//
// Posture: black -> deny; approve-tier -> ask only in strict mode; else defer.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadPolicy } from './policy.mjs';
import { daemonCheck } from './client.mjs';

/** Map a Claude Code tool_name + tool_input to a warden action. */
export function ccToAction(toolName, ti = {}) {
  const t = (toolName || '').toLowerCase();
  if (t === 'bash' || t === 'powershell' || t === 'shell') return { tool: 'shell', input: { command: ti.command || ti.cmd || '' } };
  if (t === 'write') return { tool: 'write', input: { path: ti.file_path || ti.path || '', content: ti.file_text || ti.content || '' } };
  if (t === 'edit' || t === 'multiedit') return { tool: 'edit', input: { path: ti.file_path || ti.path || '' } };
  if (t === 'notebookedit') return { tool: 'edit', input: { path: ti.notebook_path || ti.file_path || '' } };
  if (t === 'read') return { tool: 'read', input: { path: ti.file_path || ti.path || '' } };
  if (t === 'webfetch' || t === 'fetch') return { tool: 'fetch', input: { url: ti.url || '', method: 'GET' } };
  if (t === 'websearch') return { tool: 'read', input: { query: ti.query || '' } };
  if (t === 'grep') return { tool: 'grep', input: { pattern: ti.pattern || '' } };
  if (t === 'glob' || t === 'ls') return { tool: 'list', input: { pattern: ti.pattern || '' } };
  return { tool: t || 'unknown', input: ti };
}

/** Map a warden verdict to a Claude Code hook decision. */
export function verdictToHook(verdict, strict) {
  if (verdict.decision === 'block') return { kind: 'deny', reason: `⛔ warden blocked (${verdict.tier}): ${verdict.why.join('; ')}` };
  if (verdict.decision === 'approve' && strict) return { kind: 'ask', reason: `warden flagged (${verdict.tier}): ${verdict.why.join('; ')}` };
  return { kind: 'defer' };
}

const out = (permissionDecision, reason) =>
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision, permissionDecisionReason: reason } }));

function readStdin() {
  return new Promise((res) => {
    let d = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (d += c));
    process.stdin.on('end', () => res(d));
    setTimeout(() => res(d), 2500);
  });
}

async function main() {
  const HOME = process.env.USERPROFILE || process.env.HOME || os.homedir();
  const CFG = process.env.WARDEN_CONFIG || path.join(HOME, '.warden', 'config.json');
  const AUDIT = process.env.WARDEN_AUDIT || path.join(HOME, '.warden', 'audit.jsonl');
  let payload;
  try { payload = JSON.parse((await readStdin()) || '{}'); } catch { process.exit(0); } // fail-open
  try {
    const policy = loadPolicy(CFG);
    const strict = policy.strict || !!process.env.WARDEN_STRICT;
    const action = ccToAction(payload.tool_name, payload.tool_input || {});
    // Long read timeout: a daemon with the judge tier may think for seconds on a
    // gray command. Connect still fails fast (daemon down -> in-process fallback).
    const readMs = Number(process.env.WARDEN_READ_MS) || 15000;
    let v = await daemonCheck({ action, skillText: '' }, { timeoutMs: readMs }); // fast path (daemon also audits)
    const auditedByDaemon = !!v;
    if (!v) { const { check } = await import('./index.mjs'); v = check(action, policy, {}); } // fallback
    if (!auditedByDaemon) {
      try { fs.mkdirSync(path.dirname(AUDIT), { recursive: true }); fs.appendFileSync(AUDIT, JSON.stringify({ ts: new Date().toISOString(), tool: payload.tool_name, tier: v.tier, decision: v.decision, why: v.why }) + '\n'); } catch {}
    }
    const d = verdictToHook(v, strict);
    if (d.kind === 'deny') out('deny', d.reason);
    else if (d.kind === 'ask') out('ask', d.reason);
    process.exit(0);
  } catch (e) {
    process.stderr.write('warden-hook error (fail-open): ' + (e && e.message || e) + '\n');
    process.exit(0); // fail-open
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
