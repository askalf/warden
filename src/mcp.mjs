// MCP middleware — firewall an MCP server's tool-calls, and scan its advertised
// tools for poisoning (malicious instructions hidden in names/descriptions —
// the OpenClaw poisoned-skill / supply-chain class).
import { check } from './index.mjs';
import { scanInjection } from './scan.mjs';

const NAME_HINTS = [
  { re: /(exec|shell|command|run_|terminal|bash|powershell|process|spawn)/i, tool: 'shell', arg: (a) => ({ command: a.command || a.cmd || a.script || JSON.stringify(a) }) },
  { re: /(delete|remove|unlink|rmdir)/i, tool: 'delete', arg: (a) => ({ path: a.path || a.target || '' }) },
  { re: /(write|edit|create|append|put_file|save|patch)/i, tool: 'write', arg: (a) => ({ path: a.path || a.file || a.uri || '', content: a.content || a.text || '' }) },
  { re: /(fetch|http|request|download|webhook|post|api_call|browse|navigate)/i, tool: 'fetch', arg: (a) => ({ url: a.url || a.uri || a.endpoint || '', method: a.method || 'GET', body: a.body || a.data || '' }) },
  { re: /(read|get|list|search|grep|stat|cat|fetch_file)/i, tool: 'read', arg: (a) => ({ path: a.path || a.uri || '', query: a.query || '' }) },
];

/** Map an MCP tool name + arguments to a warden action via heuristics (or an explicit nameMap). */
export function mapMcpToAction(name, args = {}, nameMap = {}) {
  if (nameMap[name]) return { tool: nameMap[name], input: args };
  for (const h of NAME_HINTS) if (h.re.test(name || '')) return { tool: h.tool, input: h.arg(args) };
  return { tool: name || 'unknown', input: args }; // classifier treats unknown tools as yellow
}

/** Firewall a single MCP `tools/call` request. Returns { verdict, action }. */
export function guardMcpCall(req, policy, opts = {}) {
  const name = req?.params?.name ?? req?.name;
  const args = req?.params?.arguments ?? req?.arguments ?? {};
  const action = mapMcpToAction(name, args, opts.nameMap || {});
  const verdict = check(action, policy, { audit: opts.audit, skillText: opts.skillText || '' });
  return { verdict, action };
}

const mcpError = (message) => ({ isError: true, content: [{ type: 'text', text: message }] });

/**
 * Wrap an MCP tools/call handler so every call is firewalled before it runs.
 *   guardHandler(realHandler, policy, { onApprove, audit })
 * onApprove(action, verdict) => boolean — defaults to deny (fail-closed) in unattended mode.
 */
export function guardHandler(handler, policy, opts = {}) {
  const onApprove = opts.onApprove || (async () => false);
  return async function guarded(req) {
    const { verdict, action } = guardMcpCall(req, policy, opts);
    if (verdict.decision === 'block') return mcpError(`warden BLOCKED (${verdict.tier}): ${verdict.why.join('; ')}`);
    if (verdict.decision === 'approve') {
      const ok = await onApprove(action, verdict);
      if (!ok) return mcpError(`warden held for approval, not granted: ${verdict.why.join('; ')}`);
    }
    return handler(req);
  };
}

/**
 * Supply-chain scan: inspect an MCP server's advertised tools for poisoning —
 * injection/exfil instructions hidden in tool names, descriptions, or schemas.
 * Returns [{ tool, flags }] for anything suspicious.
 */
export function scanMcpTools(tools = []) {
  const findings = [];
  for (const t of tools) {
    const text = `${t.name || ''} ${t.description || ''} ${JSON.stringify(t.inputSchema || t.input_schema || {})}`;
    const flags = scanInjection({ input: { _scan: text } });
    if (flags.length) findings.push({ tool: t.name, flags });
  }
  return findings;
}
