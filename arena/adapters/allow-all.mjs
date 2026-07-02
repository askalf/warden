#!/usr/bin/env node
// Arena adapter: allow-all — the null firewall. Blocks nothing.
// Pins the floor: 0% recall, 100% precision. Any real tool must beat its recall.
import readline from 'node:readline';
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  const s = line.trim(); if (!s) continue;
  let sample; try { sample = JSON.parse(s); } catch { continue; }
  process.stdout.write(JSON.stringify({ id: sample.id, blocked: false, ms: 0 }) + '\n');
}
