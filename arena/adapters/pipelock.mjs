#!/usr/bin/env node
// Arena adapter: Pipelock (https://github.com/luckyPipewrench/pipelock) —
// scored through its Scan API, the surface Pipelock's own docs designate for
// exactly this job ("Control plane evaluator: forward agent tool calls through
// the scan API before execution"). Needs a running pipelock daemon with
// scan_api enabled:
//
//   pipelock run --config arena/adapters/pipelock.arena.yaml
//
// (The Arena CI workflow does this automatically — .github/workflows/arena.yml.)
// If the daemon isn't reachable, this adapter emits no verdicts and the runner
// marks Pipelock unavailable rather than scoring a misleading 0%.
//
// Fairness: every sample is given EVERY applicable documented scan kind, and a
// deny from any of them counts as a block — this composition can only raise
// Pipelock's recall, never lower it:
//   - tool_call        — always (DLP + injection on argument text, plus
//                        mcp_tool_policy rules when configured; the arena runs
//                        the out-of-box posture: no operator-written rules)
//   - dlp              — on the raw command string (adds Pipelock's
//                        embedded-URL pipeline: exfil URLs, SSRF, encoded
//                        secrets — tool_call alone doesn't run it)
//   - prompt_injection — on skill text (poisoned-skill samples)
// The scan API is binary allow/deny (proxy-mode warn/ask isn't exposed here),
// so `gated` is always false and +gate recall equals hard recall.
import readline from 'node:readline';

const SCAN_URL = process.env.PIPELOCK_SCAN_URL || 'http://127.0.0.1:9090/api/v1/scan';
const TOKEN = process.env.PIPELOCK_SCAN_TOKEN || 'arena-token';
const CONCURRENCY = 8;

async function scan(kind, input, attempt = 0) {
  const res = await fetch(SCAN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify({ kind, input }),
  });
  if (res.status === 429 || res.status === 503) {
    // rate-limited or scan-deadline — both documented retryable
    if (attempt >= 3) throw new Error(`HTTP ${res.status} after ${attempt} retries`);
    const wait = Number(res.headers.get('retry-after')) || 1;
    await new Promise((r) => setTimeout(r, wait * 1000));
    return scan(kind, input, attempt + 1);
  }
  const body = await res.json().catch(() => null);
  if (!res.ok || !body || body.status !== 'completed') {
    throw new Error(`HTTP ${res.status}${body && body.errors ? ' ' + JSON.stringify(body.errors) : ''}`);
  }
  return body; // { decision: 'allow'|'deny', duration_ms, findings? }
}

// One reachability probe — no daemon (or a bad token) → exit with zero
// verdicts, which the runner reports as "unavailable" instead of 0%.
try {
  await scan('tool_call', { tool_name: 'arena-probe', arguments: { probe: true } });
} catch {
  process.exit(0);
}

async function verdict(sample) {
  const scans = [['tool_call', {
    tool_name: sample.tool || 'tool',
    ...(sample.action && sample.action.input !== undefined ? { arguments: sample.action.input } : {}),
  }]];
  if (typeof sample.command === 'string' && sample.command) scans.push(['dlp', { text: sample.command }]);
  if (typeof sample.skill === 'string' && sample.skill) scans.push(['prompt_injection', { content: sample.skill }]);

  let denied = false, ms = 0, err = null;
  for (const [kind, input] of scans) {
    try {
      const r = await scan(kind, input);
      if (typeof r.duration_ms === 'number') ms += r.duration_ms;
      if (r.decision === 'deny') denied = true;
    } catch (e) {
      err = String((e && e.message) || e);
    }
  }
  if (denied) return { id: sample.id, blocked: true, gated: false, tier: 'deny', ms };
  // A scanner that failed is not a scanner that allowed — score as error.
  if (err) return { id: sample.id, blocked: false, error: err };
  return { id: sample.id, blocked: false, gated: false, tier: 'allow', ms };
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
    const v = await verdict(samples[next++]);
    process.stdout.write(JSON.stringify(v) + '\n');
  }
}));
