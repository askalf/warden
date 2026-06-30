// Layer check: MCP client -> warden-mcp (the gate) -> notes MCP server.
//
// No Agents SDK yet — this proves the governance plumbing on its own, with a raw
// @modelcontextprotocol/sdk client (the same SDK the Agents SDK's MCPServerStdio
// uses under the hood):
//   1. tools/list comes back with the poisoned `exfiltrate_helper` STRIPPED.
//   2. a benign write_note call is FORWARDED and really writes a file.
//   3. a malicious run_command (filesystem destruction) is BLOCKED by warden.
//
// NOTE: this file is deliberately named `_plumbing_check.mjs`, NOT
// `_plumbing_test.mjs`. The repo's root `npm test` runs `node --test`, which
// auto-discovers any `*_test.mjs`/`*.test.mjs` file and would try to run it at
// the repo root — where this example's deps are not installed. The `_check`
// suffix keeps it out of that glob, so the root test suite stays green.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import assert from 'node:assert';

const WARDEN_MCP = process.env.WARDEN_MCP;   // path to warden src/mcp-proxy-cli.mjs
const SERVER = process.env.NOTES_SERVER;     // path to notes_mcp_server.mjs
const POLICY = process.env.WARDEN_POLICY || 'warden.config.json';
const AUDIT = process.env.WARDEN_AUDIT || 'plumbing_audit.jsonl';
if (!WARDEN_MCP || !SERVER) { console.error('set WARDEN_MCP and NOTES_SERVER'); process.exit(2); }

const transport = new StdioClientTransport({
  command: 'node',
  args: [WARDEN_MCP, '--policy', POLICY, '--audit', AUDIT, '--', 'node', SERVER],
  env: process.env,
});
const client = new Client({ name: 'plumbing-check', version: '1.0.0' });
await client.connect(transport);

const { tools } = await client.listTools();
const names = tools.map((t) => t.name).sort();
console.log('tools/list (via gate):', names);
assert(!names.includes('exfiltrate_helper'), 'poisoned tool was NOT stripped!');
console.log('  -> poisoned tool stripped:', !names.includes('exfiltrate_helper'));

const w = await client.callTool({ name: 'write_note', arguments: { title: 'governed', body: 'hello from a governed tool call' } });
console.log('write_note ->', w.content[0].text, '| isError:', Boolean(w.isError));
assert(!w.isError, 'benign write was wrongly blocked');

const bad = await client.callTool({ name: 'run_command', arguments: { command: 'r' + 'm -' + 'rf /' } });
console.log('run_command(destroy) ->', String(bad.content[0].text).slice(0, 80), '| isError:', Boolean(bad.isError));
assert(bad.isError, 'malicious command was NOT blocked');

await client.close();
console.log('PLUMBING_PASS');
