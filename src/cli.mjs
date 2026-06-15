#!/usr/bin/env node
// warden CLI: check an action, scan an MCP manifest, init a policy, query the audit log.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const HOME = process.env.USERPROFILE || process.env.HOME || os.homedir();

/** Scan a project dir + git remotes -> a sensible starter policy. */
export function buildInitPolicy(cwd = process.cwd()) {
  const roots = [];
  for (const d of ['src', 'lib', 'app', 'pages', 'components', 'docs', 'scripts', 'test', 'tests']) {
    try { if (fs.statSync(path.join(cwd, d)).isDirectory()) roots.push(d + '/'); } catch {}
  }
  const egress = new Set(['api.anthropic.com', 'registry.npmjs.org']);
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

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const flag = (n) => argv.includes(n);
  const val = (n, d) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };

  if (cmd === 'check') {
    const { check, loadPolicy } = await import('./index.mjs');
    const json = argv.find((a) => a.trim().startsWith('{'));
    if (!json) { console.error('usage: warden check \'{"tool":"shell","input":{"command":"..."}}\''); process.exit(2); }
    const v = check(JSON.parse(json), loadPolicy(val('--policy', 'warden.config.json')));
    console.log(JSON.stringify(v, null, 2));
    process.exit(v.decision === 'block' ? 1 : 0);
  } else if (cmd === 'scan-mcp') {
    const { scanMcpTools } = await import('./mcp.mjs');
    const file = argv.slice(1).find((a) => !a.startsWith('--'));
    if (!file) { console.error('usage: warden scan-mcp <tools.json>'); process.exit(2); }
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    const f = scanMcpTools(Array.isArray(data) ? data : data.tools || []);
    if (f.length) { console.log(JSON.stringify(f, null, 2)); process.exit(1); }
    console.log('✓ no poisoned tool descriptions found');
  } else if (cmd === 'init') {
    const policy = buildInitPolicy();
    const target = flag('--global') ? path.join(HOME, '.warden', 'config.json') : path.join(process.cwd(), 'warden.config.json');
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
  } else {
    console.log(`warden — own your agent security
  warden check '<action-json>' [--policy f]            firewall one action
  warden scan-mcp <tools.json>                          scan an MCP tool manifest for poisoning
  warden init [--global]                                scan project -> starter warden.config.json
  warden audit [--blocks] [--tier black] [--tail N]     summarize / query the audit log`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
