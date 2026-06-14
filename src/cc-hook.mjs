#!/usr/bin/env node
// warden as a Claude Code PreToolUse hook. Reads the hook payload on stdin,
// firewalls the tool call, and returns a permission decision.
//
// Posture (daily-driver safe):
//   black (RCE / exfil / poisoned-skill / deny-rule) -> deny
//   approve-tier -> ask ONLY in strict mode (policy.strict or WARDEN_STRICT=1)
//   everything else -> defer (let Claude Code's normal flow proceed)
// Fail-open: any error -> defer, so a warden bug never bricks your tooling.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { check, loadPolicy } from './index.mjs';

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

/** Pure decision: { kind: 'defer'|'deny'|'ask', tier, reason, verdict }. */
export function hookDecision(payload, policy) {
  const action = ccToAction(payload.tool_name, payload.tool_input || {});
  const v = check(action, policy);
  if (v.decision === 'block') return { kind: 'deny', tier: v.tier, reason: `⛔ warden blocked (${v.tier}): ${v.why.join('; ')}`, verdict: v };
  if (v.decision === 'approve' && policy.strict) return { kind: 'ask', tier: v.tier, reason: `warden flagged (${v.tier}): ${v.why.join('; ')}`, verdict: v };
  return { kind: 'defer', tier: v.tier, verdict: v };
}

const out = (permissionDecision, reason) =>
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision, permissionDecisionReason: reason } }));

function readStdin() {
  return new Promise((res) => {
    let d = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (d += c));
    process.stdin.on('end', () => res(d));
    setTimeout(() => res(d), 2500); // safety: never hang the tool call
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
    policy.strict = policy.strict || !!process.env.WARDEN_STRICT;
    const d = hookDecision(payload, policy);
    try { fs.mkdirSync(path.dirname(AUDIT), { recursive: true }); fs.appendFileSync(AUDIT, JSON.stringify({ ts: new Date().toISOString(), tool: payload.tool_name, tier: d.tier, kind: d.kind, why: d.verdict.why }) + '\n'); } catch {}
    if (d.kind === 'deny') out('deny', d.reason);
    else if (d.kind === 'ask') out('ask', d.reason);
    // defer: no output
    process.exit(0);
  } catch (e) {
    process.stderr.write('warden-hook error (fail-open): ' + (e?.message || e) + '\n');
    process.exit(0); // fail-open
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
