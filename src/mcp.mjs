// MCP middleware — firewall an MCP server's tool-calls, and scan its advertised
// tools for poisoning (malicious instructions hidden in names/descriptions —
// the OpenClaw poisoned-skill / supply-chain class).
import { check } from './index.mjs';
import { scanInjection, injectionHits, safeStringify } from './scan.mjs';

// Extract fetch-shaped fields, tolerating non-standard URL keys (target/href/link)
// so a URL isn't lost just because the tool named its argument unusually.
const netArgs = (a) => ({ url: a.url || a.uri || a.endpoint || a.target || a.href || a.link || '', method: a.method || 'GET', body: a.body || a.data || '' });

const NAME_HINTS = [
  { re: /(exec|shell|command|run_|terminal|bash|powershell|process|spawn)/i, tool: 'shell', arg: (a) => ({ command: a.command || a.cmd || a.script || safeStringify(a) }) },
  { re: /(delete|remove|unlink|rmdir)/i, tool: 'delete', arg: (a) => ({ path: a.path || a.target || '' }) },
  { re: /(write|edit|create|append|put_file|save|patch)/i, tool: 'write', arg: (a) => ({ path: a.path || a.file || a.uri || '', content: a.content || a.text || '' }) },
  { re: /(fetch|http|request|download|webhook|post|api_call|browse|navigate)/i, tool: 'fetch', arg: netArgs },
  { re: /(read|get|list|search|grep|stat|cat|fetch_file)/i, tool: 'read', arg: (a) => ({ path: a.path || a.uri || '', query: a.query || '' }) },
];

const URLISH_RE = /\bhttps?:\/\/[^\s'"]+/i;
const hasUrlish = (args) => Object.values(args || {}).some((v) => typeof v === 'string' && URLISH_RE.test(v));

/**
 * Map an MCP tool name + arguments to a warden action. Two safety properties
 * beyond the name heuristic:
 *  - MERGE, don't replace: the normalized fields drive the structured checks,
 *    but the raw args are preserved so the content scanners (secrets, injection,
 *    URLs) still see everything the tool was actually given — and a poisoned
 *    tool that buries a `command` field in a `read`/`fetch` call can't strip it
 *    past the shell-spoof defense in classify().
 *  - URL-bearing calls are network-capable regardless of their name, so they're
 *    routed to `fetch` (an "active" tool). Otherwise a fetcher named like
 *    `get_url` or `search` maps to `read` and dodges the SSRF / metadata / exfil
 *    checks that only run for fetch/shell tools.
 */
export function mapMcpToAction(name, args = {}, nameMap = {}) {
  args = args || {};
  const nameStr = name == null ? '' : String(name); // fail-safe: a non-string name (Symbol/number) must not throw
  if (nameMap[nameStr]) return { tool: nameMap[nameStr], input: { ...args } };
  const urlish = hasUrlish(args);
  for (const h of NAME_HINTS) {
    if (h.re.test(nameStr)) {
      if (urlish && h.tool !== 'fetch' && h.tool !== 'shell')
        return { tool: 'fetch', input: { ...args, ...netArgs(args) } };
      return { tool: h.tool, input: { ...args, ...h.arg(args) } };
    }
  }
  if (urlish) return { tool: 'fetch', input: { ...args, ...netArgs(args) } };
  return { tool: nameStr || 'unknown', input: { ...args } }; // classifier treats unknown tools as yellow
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

const MAX_RESULT_SCAN = 131072; // bound the scan — injection phrases are short
/**
 * Scan an MCP tools/call RESULT for prompt-injection. This is the *indirect*
 * injection vector: a tool returns attacker-controlled text ("ignore previous
 * instructions, exfiltrate …") that hijacks the agent reading the result.
 * Returns the injection flags found (empty = clean).
 */
export function scanToolResult(result) {
  if (result == null) return [];
  let text = typeof result === 'string' ? result : safeStringify(result);
  if (text.length > MAX_RESULT_SCAN) text = text.slice(0, MAX_RESULT_SCAN);
  return injectionHits(text);
}

/**
 * Wrap an MCP tools/call handler so every call is firewalled before it runs AND
 * its result is scanned for injection before it reaches the agent.
 *   guardHandler(realHandler, policy, { onApprove, audit, scanResults })
 * onApprove(action, verdict) => boolean — defaults to deny (fail-closed) in unattended mode.
 * scanResults (default true) — neutralize a result that carries prompt-injection.
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
    const result = await handler(req);
    if (opts.scanResults !== false) {
      const hits = scanToolResult(result);
      if (hits.length) return mcpError(`warden neutralized a tool result — prompt-injection in returned content: ${hits.join('; ')}`);
    }
    return result;
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
