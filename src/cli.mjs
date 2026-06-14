#!/usr/bin/env node
// warden CLI — check an action, or scan an MCP tool manifest for poisoning.
import fs from 'node:fs';
import { check, loadPolicy } from './index.mjs';
import { scanMcpTools } from './mcp.mjs';

const argv = process.argv.slice(2);
const cmd = argv[0];
const flag = (name, def) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : def; };
const policy = loadPolicy(flag('--policy', 'warden.config.json'));

if (cmd === 'check') {
  const json = argv.find((a) => a.trim().startsWith('{'));
  if (!json) { console.error('usage: warden check \'{"tool":"shell","input":{"command":"..."}}\''); process.exit(2); }
  const v = check(JSON.parse(json), policy);
  console.log(JSON.stringify(v, null, 2));
  process.exit(v.decision === 'block' ? 1 : 0);
} else if (cmd === 'scan-mcp') {
  const file = argv.slice(1).find((a) => !a.startsWith('--'));
  if (!file) { console.error('usage: warden scan-mcp <tools.json>'); process.exit(2); }
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  const findings = scanMcpTools(Array.isArray(data) ? data : data.tools || []);
  if (findings.length) { console.log(JSON.stringify(findings, null, 2)); process.exit(1); }
  console.log('✓ no poisoned tool descriptions found');
} else {
  console.log(`warden — own your agent security
  warden check '{"tool":"shell","input":{"command":"rm -rf /"}}' [--policy file]
  warden scan-mcp <tools.json> [--policy file]`);
}
