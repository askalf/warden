#!/usr/bin/env node
// warden-mcp — wrap any MCP server with the warden firewall.
//   warden-mcp [--policy f] [--allow-approve] [--no-strip] [--no-scan-results] [--no-taint] [--audit f] -- <server-cmd> [args...]
// Example:
//   warden-mcp --policy warden.config.json -- npx -y @modelcontextprotocol/server-filesystem /workspace
import { runProxy } from './mcp-proxy.mjs';
import { loadPolicy } from './index.mjs';
import { AuditLog } from './audit.mjs';

const argv = process.argv.slice(2);
const dd = argv.indexOf('--');
if (dd === -1) {
  console.error('usage: warden-mcp [--policy f] [--allow-approve] [--no-strip] [--no-scan-results] [--no-taint] [--audit f] -- <server-cmd> [args...]');
  process.exit(2);
}
const head = argv.slice(0, dd);
const [command, ...args] = argv.slice(dd + 1);
if (!command) { console.error('warden-mcp: no downstream server command after --'); process.exit(2); }

const flag = (n) => head.includes(n);
const val = (n, d) => { const i = head.indexOf(n); return i >= 0 ? head[i + 1] : d; };
const auditPath = val('--audit', null);

runProxy({
  command, args,
  policy: loadPolicy(val('--policy', 'warden.config.json')),
  allowApprove: flag('--allow-approve'),
  strip: !flag('--no-strip'),
  scanResults: !flag('--no-scan-results'),
  taint: !flag('--no-taint'),
  audit: auditPath ? new AuditLog() : null,
  auditPath,
});
