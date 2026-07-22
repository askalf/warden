#!/usr/bin/env node
// redstamp CLI: check an action, scan an MCP manifest, init a policy, query the audit log.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { resolveConfig } from './policy.mjs';

const HOME = process.env.USERPROFILE || process.env.HOME || os.homedir();

/** Scan a project dir + git remotes -> a sensible starter policy. */
// Hosts every policy needs regardless of where it was created.
const BASE_EGRESS = ['api.anthropic.com', 'registry.npmjs.org'];

// A GLOBAL policy governs projects that have nothing to do with the directory
// `init --global` happened to run in, so it must not inherit that directory's
// git remotes or its layout.
//
// NOTE: it deliberately does NOT seed github.com either. Allowlisting a host
// suppresses the BLACK secret-exfil verdict for that host (decide() only raises
// BLACK when a secret meets an EXTERNAL host), and GitHub issues/gists/comments
// accept arbitrary attacker-readable content -- so trusting them would turn a
// stolen-token drop into a silently-deferred RED. Routine read traffic is
// already green without the allowlist; only a session already tainted by a
// secret is affected, which is exactly the case that should be scrutinised.
// See #81 for making GitHub ergonomic without reopening that hole.

/** Build an init policy. Per-PROJECT (default) derives egress + write roots from
 *  `cwd`, which is correct: that policy governs that project. GLOBAL derives
 *  NEITHER -- it seeds universal dev hosts and leaves writeRoots null, because a
 *  machine-wide policy inheriting one arbitrary directory's layout would flag
 *  every write outside it (writeRoots is enforced as RED in decide()). */
export function buildInitPolicy(cwd = process.cwd(), { global: isGlobal = false } = {}) {
  const egress = new Set(BASE_EGRESS);

  if (isGlobal) {
    // No CWD-derived remotes, no CWD-derived writeRoots, no blanket host trust.
    return { strict: false, deny: ['shell(sudo*)'], egressAllow: [...egress], writeRoots: null };
  }

  const roots = [];
  for (const d of ['src', 'lib', 'app', 'pages', 'components', 'docs', 'scripts', 'test', 'tests']) {
    try { if (fs.statSync(path.join(cwd, d)).isDirectory()) roots.push(d + '/'); } catch {}
  }
  try {
    const gitcfg = fs.readFileSync(path.join(cwd, '.git', 'config'), 'utf8');
    for (const m of gitcfg.matchAll(/url\s*=\s*\S*?([a-z0-9.-]+\.[a-z]{2,})[:/]/gi)) egress.add(m[1].toLowerCase());
  } catch {}
  return { strict: false, deny: ['shell(sudo*)'], egressAllow: [...egress], writeRoots: roots.length ? roots : null };
}

/** Summarize + filter parsed audit-log rows. */
const KIND2DECISION = { deny: 'block', ask: 'approve', defer: 'allow' };
export function queryAudit(lines, { tier = null, blocksOnly = false, tail = 0 } = {}) {
  // tolerate both the current `decision` field and the legacy `kind` field.
  let rows = lines.map((r) => ({ ...r, decision: r.decision || KIND2DECISION[r.kind] || r.kind || 'unknown' }));
  if (tier) rows = rows.filter((r) => r.tier === tier);
  if (blocksOnly) rows = rows.filter((r) => r.decision === 'block');
  if (tail) rows = rows.slice(-tail);
  const tally = (k) => rows.reduce((a, r) => ((a[r[k]] = (a[r[k]] || 0) + 1), a), {});
  return { total: lines.length, shown: rows.length, byDecision: tally('decision'), byTier: tally('tier'), rows };
}

/**
 * Format a verifyAuditFile() result for the `warden verify` CLI: a human line
 * plus the process exit code (0 intact / 2 tamper) so it's usable in CI and
 * monitoring. Pure — the command wrapper only prints and exits. `unchained`
 * (foreign/legacy lines interspersed in the log) is surfaced, not a failure —
 * it matches verifyAuditFile's semantics.
 */
export function formatVerify(r) {
  if (r && r.ok) {
    const extra = r.unchained ? ` (${r.unchained} unchained/foreign line${r.unchained === 1 ? '' : 's'} skipped)` : '';
    return { ok: true, exitCode: 0, message: `✓ audit intact — ${r.entries} chained ${r.entries === 1 ? 'entry' : 'entries'}${extra}` };
  }
  const reason = r && r.reason ? ` (${r.reason})` : '';
  return { ok: false, exitCode: 2, message: `✗ TAMPER DETECTED at entry ${r ? r.at : '?'}${reason}` };
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const flag = (n) => argv.includes(n);
  const val = (n, d) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };

  if (cmd === 'check') {
    const { check, loadPolicy } = await import('./index.mjs');
    const json = argv.find((a) => a.trim().startsWith('{'));
    if (!json) { console.error('usage: redstamp check \'{"tool":"shell","input":{"command":"..."}}\''); process.exit(2); }
    const v = check(JSON.parse(json), loadPolicy(val('--policy', null) || resolveConfig()));
    console.log(JSON.stringify(v, null, 2));
    process.exit(v.decision === 'block' ? 1 : 0);
  } else if (cmd === 'scan-mcp') {
    const { scanMcpTools } = await import('./mcp.mjs');
    const file = argv.slice(1).find((a) => !a.startsWith('--'));
    if (!file) { console.error('usage: redstamp scan-mcp <tools.json>'); process.exit(2); }
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    const f = scanMcpTools(Array.isArray(data) ? data : data.tools || []);
    if (f.length) { console.log(JSON.stringify(f, null, 2)); process.exit(1); }
    console.log('✓ no poisoned tool descriptions found');
  } else if (cmd === 'init') {
    const isGlobal = flag('--global');
    const policy = buildInitPolicy(process.cwd(), { global: isGlobal });
    const target = isGlobal ? path.join(HOME, '.warden', 'config.json') : resolveConfig();
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, JSON.stringify(policy, null, 2) + '\n');
    console.log('wrote ' + target + '\n');
    console.log(JSON.stringify(policy, null, 2));
  } else if (cmd === 'audit') {
    const auditPath = process.env.WARDEN_AUDIT || path.join(HOME, '.warden', 'audit.jsonl');
    let lines = [];
    try { lines = fs.readFileSync(auditPath, 'utf8').trim().split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean); } catch {}
    const q = queryAudit(lines, { tier: val('--tier', null), blocksOnly: flag('--blocks'), tail: parseInt(val('--tail', '0'), 10) || 0 });
    console.log(`audit: ${q.total} entries  ·  by decision ${JSON.stringify(q.byDecision)}  ·  by tier ${JSON.stringify(q.byTier)}`);
    if (flag('--blocks') || val('--tier', null) || parseInt(val('--tail', '0'), 10)) {
      for (const r of q.rows.slice(-60)) console.log(`  ${(r.ts || '').slice(11, 19)}  ${(r.decision || '').padEnd(7)} ${(r.tier || '').padEnd(6)} ${(r.tool || '').padEnd(12)} ${(r.why || []).join('; ').slice(0, 90)}`);
    }
  } else if (cmd === 'verify') {
    // Surface the tamper-evident audit chain through the CLI — the one question
    // the hash-chain exists to answer ("has my audit log been edited?"), with an
    // exit code CI / monitoring can alert on. All logic stays in the tested
    // verifyAuditFile; this only formats + sets the exit code.
    const { verifyAuditFile } = await import('./audit.mjs');
    const auditPath = val('--audit', process.env.WARDEN_AUDIT || path.join(HOME, '.warden', 'audit.jsonl'));
    const r = formatVerify(verifyAuditFile(auditPath));
    (r.ok ? console.log : console.error)(r.message);
    process.exit(r.exitCode);
  } else {
    console.log(`redstamp — own your agent security
  redstamp check '<action-json>' [--policy f]           firewall one action
  redstamp scan-mcp <tools.json>                         scan an MCP tool manifest for poisoning
  redstamp init [--global]                               scan project -> starter redstamp.config.json
  redstamp audit [--blocks] [--tier black] [--tail N]    summarize / query the audit log
  redstamp verify [--audit f]                            verify the tamper-evident audit chain (exit 2 on tamper)

  (\`warden*\` CLI aliases still work; an existing warden.config.json is read
  automatically, and the WARDEN_* env vars are unchanged.)`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
