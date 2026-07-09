#!/usr/bin/env node
// Arena adapter: AEGIS (github.com/Justin0504/Aegis) — the first arena
// competitor with a genuine THREE-tier verdict (allow / block / pending),
// scored through its documented pre-execution `POST /api/v1/check` endpoint.
// Needs a running gateway on :8080 (the Arena CI workflow builds + starts it
// from a pinned commit). If it isn't reachable this adapter emits no verdicts
// and the runner marks AEGIS unavailable rather than scoring a bogus 0%.
//
// Design choices, all in the direction of representing AEGIS faithfully:
//
//   - blocking:true — AEGIS's headline feature is human-in-the-loop. In
//     blocking mode a HIGH/CRITICAL risky call returns `pending` (escalate to
//     a human) instead of a hard `block`. We map pending → gated, so AEGIS
//     gets full credit on the arena's +gate recall column (blocked OR
//     escalated both stop silent execution). Its hard-recall(block) number is
//     deliberately low BECAUSE it escalates — read the +gate column for AEGIS.
//   - A fresh agent_id per sample. AEGIS's L2 behavioral-anomaly layer needs a
//     per-agent learning baseline that a stateless corpus can't build (its own
//     docs: agents start in a "learning" phase). A distinct id per sample
//     keeps every call in that phase, so the verdict comes purely from the
//     deterministic L1 policy + classifier + L3 DSL layer — which is what a
//     one-shot corpus can fairly score, and what makes the double-run pass.
//   - Out-of-box `standard` policy template (shell/supply-chain/prompt-injection
//     → block, file/db → MEDIUM, network → LOW); no operator-authored DSL rules.
//
// The /api/v1/check route is an open route in AEGIS (no API key required), so
// no secret is needed here.
import readline from 'node:readline';

const BASE = process.env.AEGIS_URL || 'http://127.0.0.1:8080';
const CHECK = `${BASE}/api/v1/check`;
const CONCURRENCY = 8;

async function check(sample, attempt = 0) {
  const res = await fetch(CHECK, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      // unique per sample → L2 stays in learning phase → deterministic L1/L3 verdict
      agent_id: `arena-${sample.id}`,
      tool_name: sample.tool || 'tool',
      arguments: (sample.action && typeof sample.action.input === 'object' && sample.action.input) || {},
      blocking: true, // let AEGIS escalate risky calls to pending (its HITL tier)
    }),
  });
  if (res.status === 429 || res.status >= 500) {
    if (attempt >= 3) throw new Error(`HTTP ${res.status} after ${attempt} retries`);
    await new Promise((r) => setTimeout(r, (attempt + 1) * 500));
    return check(sample, attempt + 1);
  }
  const body = await res.json().catch(() => null);
  if (!res.ok || !body || typeof body.decision !== 'string') {
    throw new Error(`HTTP ${res.status}${body && body.error ? ' ' + JSON.stringify(body.error) : ''}`);
  }
  return body; // { decision: 'allow'|'block'|'pending', risk_level, latency_ms, ... }
}

// One reachability probe — no gateway → exit with zero verdicts.
try {
  await check({ id: 'probe', tool: 'read', action: { input: {} } });
} catch {
  process.exit(0);
}

function verdict(sample, body) {
  const d = body.decision;
  return {
    id: sample.id,
    blocked: d === 'block',
    gated: d === 'pending', // escalate-to-human — counts toward +gate recall, not hard block
    tier: d,
    ms: typeof body.latency_ms === 'number' ? body.latency_ms : undefined,
  };
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
const samples = [];
for await (const line of rl) {
  const s = line.trim();
  if (!s) continue;
  try { samples.push(JSON.parse(s)); } catch { /* ignore noise */ }
}

let next = 0;
await Promise.all(Array.from({ length: Math.min(CONCURRENCY, samples.length) }, async () => {
  while (next < samples.length) {
    const sample = samples[next++];
    try {
      const body = await check(sample);
      process.stdout.write(JSON.stringify(verdict(sample, body)) + '\n');
    } catch (e) {
      // A firewall that errors is not a firewall that allowed.
      process.stdout.write(JSON.stringify({ id: sample.id, blocked: false, error: String((e && e.message) || e) }) + '\n');
    }
  }
}));
