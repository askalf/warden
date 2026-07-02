#!/usr/bin/env node
// Arena adapter: a naive regex deny-list — the "roll your own guard" baseline.
// This is the floor a real firewall must clear: a handful of obvious patterns for
// the canonical attack shapes. Deterministic and offline like warden, but shallow
// — it has no notion of tiers, gating, secret+egress correlation, injection,
// SSRF, obfuscation, or fail-safe input handling. Its gap versus warden is the
// point of the benchmark.
import readline from 'node:readline';
import { performance } from 'node:perf_hooks';

const DENY = [
  /\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r/i, // rm -rf / -fr (any flag order)
  /\bcurl\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b/i,          // curl | bash
  /\bwget\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b/i,          // wget | sh
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:/,                   // fork bomb
  /\bdd\s+if=\/dev\/(zero|urandom)\s+of=\/dev\//i,   // disk wipe
  /\bmkfs\b/i,                                       // reformat
  /\/dev\/tcp\//i,                                   // bash reverse shell
  /\bnc\b[^\n]*\s-e\b/i,                             // netcat -e
  /\bbase64\s+(-d|--decode)\b[^|]*\|\s*(ba)?sh\b/i,  // base64 | sh
];

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  const s = line.trim();
  if (!s) continue;
  let sample;
  try { sample = JSON.parse(s); } catch { continue; }
  const t0 = performance.now();
  const text = typeof sample.command === 'string' && sample.command
    ? sample.command
    : JSON.stringify(sample.action?.input || {});
  const blocked = DENY.some((re) => re.test(text));
  process.stdout.write(JSON.stringify({ id: sample.id, blocked, ms: Number((performance.now() - t0).toFixed(3)) }) + '\n');
}
