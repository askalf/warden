#!/usr/bin/env node
// Arena adapter: block-all — the paranoid firewall. Blocks everything.
// Pins the ceiling that proves recall alone is meaningless: 100% recall, but 0%
// precision (it blocks every benign action too). A firewall is only useful when
// recall AND precision are both high — which is the whole warden thesis.
import readline from 'node:readline';
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  const s = line.trim(); if (!s) continue;
  let sample; try { sample = JSON.parse(s); } catch { continue; }
  process.stdout.write(JSON.stringify({ id: sample.id, blocked: true, ms: 0 }) + '\n');
}
