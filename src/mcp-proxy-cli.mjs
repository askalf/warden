#!/usr/bin/env node
// redstamp-mcp — wrap any MCP server with the redstamp firewall. (`warden-mcp`
// alias still works; an existing warden.config.json is read automatically.)
//   redstamp-mcp [--policy f] [--allow-approve] [--no-strip] [--no-scan-results] [--no-taint] [--audit f] -- <server-cmd> [args...]
// Example:
//   redstamp-mcp --policy redstamp.config.json -- npx -y @modelcontextprotocol/server-filesystem /workspace
import { runProxy } from './mcp-proxy.mjs';
import { loadPolicy, resolveConfig } from './index.mjs';
import { AuditLog } from './audit.mjs';

const argv = process.argv.slice(2);
const dd = argv.indexOf('--');
if (dd === -1) {
  console.error('usage: redstamp-mcp [--policy f] [--allow-approve] [--no-strip] [--no-scan-results] [--no-taint] [--audit f] -- <server-cmd> [args...]');
  process.exit(2);
}
const head = argv.slice(0, dd);
const [command, ...args] = argv.slice(dd + 1);
if (!command) { console.error('redstamp-mcp: no downstream server command after --'); process.exit(2); }

const flag = (n) => head.includes(n);
const val = (n, d) => { const i = head.indexOf(n); return i >= 0 ? head[i + 1] : d; };
const auditPath = val('--audit', null);

runProxy({
  command, args,
  policy: loadPolicy(val('--policy', null) || resolveConfig()),
  allowApprove: flag('--allow-approve'),
  strip: !flag('--no-strip'),
  scanResults: !flag('--no-scan-results'),
  taint: !flag('--no-taint'),
  audit: auditPath ? new AuditLog() : null,
  auditPath,
});
