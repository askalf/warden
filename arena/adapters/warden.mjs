#!/usr/bin/env node
// Arena adapter: warden (this repo), in its default posture — deterministic,
// offline, no LLM judge. Reads corpus samples as JSONL on stdin, emits one
// verdict line per sample. See ../protocol.md.
import readline from 'node:readline';
import { performance } from 'node:perf_hooks';
import { decide } from '../../src/index.mjs';

// The same policy the internal bench uses (bench/run.mjs): a token egress
// allowlist + write roots, so egress/write-scope rules are exercised.
const policy = { egressAllow: ['api.example.com'], writeRoots: ['src/', 'docs/'] };

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  const s = line.trim();
  if (!s) continue;
  let sample;
  try { sample = JSON.parse(s); } catch { continue; }
  try {
    const t0 = performance.now();
    const v = decide(sample.action, policy, sample.skill || '');
    const ms = performance.now() - t0;
    process.stdout.write(JSON.stringify({
      id: sample.id,
      blocked: v.decision === 'block',
      gated: v.decision === 'approve',
      tier: v.tier,
      ms: Number(ms.toFixed(3)),
    }) + '\n');
  } catch (e) {
    // A firewall that throws is a firewall that failed — report it, don't allow.
    process.stdout.write(JSON.stringify({ id: sample.id, blocked: false, error: String((e && e.message) || e) }) + '\n');
  }
}
