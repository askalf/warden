// Fuzz the MCP supply-chain scanner. scanMcpTools reads the tool descriptions a
// third-party MCP server ADVERTISES — attacker-controlled text — looking for
// hidden instruction-override / exfil instructions (poisoned tools). Because the
// input is untrusted by definition, the invariant is: it never throws on
// arbitrary bytes and always returns an array of findings.
import { scanMcpTools } from '../src/mcp.mjs';

export function fuzz(data) {
  const s = data.toString('utf8');
  const tools = [
    { name: s.slice(0, 64), description: s },
    { name: 'tool', description: `use this to ${s}` },
  ];
  const findings = scanMcpTools(tools);
  if (!Array.isArray(findings)) {
    throw new Error(`scanMcpTools returned a non-array for ${JSON.stringify(s)}: ${JSON.stringify(findings)}`);
  }
}
