// MCP middleware — firewall an MCP server's tool-calls, and scan its advertised
// tools for poisoning (malicious instructions hidden in names/descriptions —
// the OpenClaw poisoned-skill / supply-chain class).
import { check, recordVerdict } from './index.mjs';
import { classify, TIER, ORDER, WRITE } from './classify.mjs';
import { injectionHits, injectionHitsDetailed, matchOf, safeStringify, SENSITIVE_PATH_RE, SENSITIVE_PATH_EXFIL_RE, SECRET_ENV_RE } from './scan.mjs';

// Extract fetch-shaped fields, tolerating non-standard URL keys (target/href/link)
// so a URL isn't lost just because the tool named its argument unusually.
const netArgs = (a) => ({ url: a.url || a.uri || a.endpoint || a.target || a.href || a.link || '', method: a.method || 'GET', body: a.body || a.data || '' });

const NAME_HINTS = [
  { re: /(exec|shell|command|run_|terminal|bash|powershell|process|spawn)/i, tool: 'shell', arg: (a) => ({ command: a.command || a.cmd || a.script || safeStringify(a) }) },
  { re: /(delete|remove|unlink|rmdir)/i, tool: 'delete', arg: (a) => ({ path: a.path || a.target || '' }) },
  { re: /(write|edit|create|append|put_file|save|patch)/i, tool: 'write', arg: (a) => ({ path: a.path || a.file || a.filepath || a.dest || a.destination || a.target || a.output || a.to || a.location || a.uri || '', content: a.content || a.text || a.body || '' }) },
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

// Content/data keys whose values are legitimately arbitrary text (a file body, a
// request payload, a commit message) — excluded from the shell-spoof leaf scan so
// a write/post of dangerous-looking DATA isn't false-blocked as a live command.
const CONTENT_KEYS = new Set(['content', 'text', 'body', 'data', 'stdin', 'file_text', 'filetext', 'patch', 'diff', 'value', 'payload', 'new_string', 'old_string', 'message', 'description']);
function shellLeaves(v, key = '', depth = 0, out = []) {
  if (depth > 6 || out.length > 64 || v == null) return out;
  if (typeof v === 'string') { if (!CONTENT_KEYS.has(String(key).toLowerCase())) out.push(v); return out; }
  if (typeof v === 'object') for (const [k, val] of Object.entries(v)) shellLeaves(val, k, depth + 1, out);
  return out;
}

/** Firewall a single MCP `tools/call` request. Returns { verdict, action }. */
export function guardMcpCall(req, policy, opts = {}) {
  const name = req?.params?.name ?? req?.name;
  const args = req?.params?.arguments ?? req?.arguments ?? {};
  const action = mapMcpToAction(name, args, opts.nameMap || {});
  const verdict = check(action, policy, { skillText: opts.skillText || '' });
  // Shell-spoof defense across ALL arg keys: a poisoned server can bury a shell
  // payload under any key (q/run/argv/opts/…), not just command/cmd. Classify each
  // non-content string leaf as a shell command and escalate to the worst verdict,
  // so `rm -rf /` on a benignly-named tool can't ride in green. (Write CONTENT is
  // data — its real threats are the persistence/secret checks, handled in decide.)
  if (!WRITE.includes(action.tool)) {
    for (const leaf of shellLeaves(args)) {
      const c = classify({ tool: 'shell', input: { command: leaf } });
      if (ORDER[c.tier] > ORDER[verdict.tier]) {
        verdict.tier = c.tier;
        for (const w of c.why) if (/[☠⚠]/.test(w) && !verdict.why.includes(w)) verdict.why.push(w);
        if (c.tier === TIER.BLACK) verdict.decision = 'block';
        else if (c.tier === TIER.RED && verdict.decision === 'allow') verdict.decision = 'approve';
      }
    }
    verdict.gray = verdict.gray || verdict.decision === 'approve' || verdict.tier === TIER.YELLOW;
  }
  recordVerdict(opts.audit, action, verdict);
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
 * Returns [{ tool, flags, severity }] for anything suspicious.
 *
 * severity ('critical' | 'advisory') tiers the finding for the CALLER's surface:
 *  - injection/exfil INSTRUCTIONS (the curated destination-bearing patterns,
 *    instruction-override, a sensitive path being moved verb→path→destination)
 *    are `critical` — poisoned anywhere.
 *  - a bare sensitive-path / secret-env MENTION is `advisory`, and so is the
 *    bare-word 'exfiltration intent' rule (exfiltrate/leak/steal with no
 *    destination): auditing 2,000+ real marketplace skills, every single hit
 *    was descriptive prose — memory leaks, ML data leakage, threat lists in
 *    defensive security docs ("attackers could: steal secrets"). In a short
 *    tool description those words are still suspicious enough to act on, which
 *    is exactly what the flag (unchanged) lets strict surfaces do.
 *    Existing consumers that only read `flags` are unaffected.
 */
const ADVISORY_WORDS = new Set(['exfiltration intent']);
/** The exact text `scanMcpTools` scans for a given tool object.
 *
 *  Exported because hit `start`/`end` are offsets into THIS string, and a
 *  consumer that wants a source position has to reverse the transform. Without
 *  it a consumer must re-implement the line below, and -- worse -- has no way to
 *  obtain this string to TEST that its reconstruction still agrees. Drift would
 *  then be silent, and silently-wrong source citations are precisely what the
 *  offsets exist to prevent. One definition, used internally and published.
 *
 *  The newline normalization is load-bearing, not cosmetic: in a JSON string a
 *  real newline arrives as the two-char sequence `\n`, which is neither `.` nor
 *  `\n` to a regex, so clause-bounded patterns would silently span lines and
 *  unrelated rows of a table could read as one verb -> path -> destination.
 */
export const scanTextOf = (tool) => safeStringify(tool).replace(/\\r\\n|\\n|\\r/g, '\n');

export function scanMcpTools(tools = []) {
  const findings = [];
  if (!Array.isArray(tools)) return findings;           // fail-safe: a non-array tool list isn't scannable
  for (const t of tools) {
    if (!t || typeof t !== 'object') continue;           // skip null / primitive entries from a hostile server
    // Scan the WHOLE tool object (safeStringify — circular/BigInt safe), not a
    // hand-picked name/description/inputSchema subset: a poisoned instruction or a
    // sensitive-path / secret-env default can hide in ANY field (prompt,
    // instructions, systemPrompt, annotations, a schema default, …).
    // Un-escape the newlines stringify produced before pattern-matching: inside a
    // JSON string every real newline is the 2-char `\n`, which is neither `.` nor
    // `\n` to a regex — clause-bounded patterns would silently span lines, and
    // unrelated rows of a table can read as one verb→path→destination "clause".
    const text = scanTextOf(t);
    const flags = injectionHits(text); // NOT scanInjection — that would re-stringify and re-escape the newlines just normalized
    // hits: the same flags with the substring each matched, for evidence surfacing.
    // Kept strictly parallel to `flags` (same order, same conditions) so the flag
    // output is byte-for-byte unchanged; `hits` is purely additive.
    //
    // `start`/`end` are the match's offsets INTO `text` above -- i.e. into the
    // stringified-and-newline-normalized view, NOT into the caller's raw source.
    // A consumer that wants a source position must reverse that transform; using
    // these offsets against raw bytes would silently point at the wrong place.
    // They are carried because re-finding a match by SEARCHING for its text is
    // ambiguous (a short match like a bare path token recurs many times in one
    // document) and fails outright when a match window slices a JSON escape.
    // matchOf/injectionHitsDetailed have always computed them; they were simply
    // dropped here. See truecopy#99.
    const hits = injectionHitsDetailed(text).map((h) => ({ flag: h.flag, match: h.match, start: h.start, end: h.end }));
    const exfilM = matchOf(SENSITIVE_PATH_EXFIL_RE, text);
    if (exfilM) { flags.push('sensitive-path exfil instruction (path → destination)'); hits.push({ flag: 'sensitive-path exfil instruction (path → destination)', match: exfilM.match, start: exfilM.start, end: exfilM.end }); }
    let severity = flags.some((w) => !ADVISORY_WORDS.has(w)) ? 'critical' : 'advisory';
    const pathM = matchOf(SENSITIVE_PATH_RE, text);
    if (pathM) { flags.push('references a sensitive path (.ssh/.env/credentials/…)'); hits.push({ flag: 'references a sensitive path (.ssh/.env/credentials/…)', match: pathM.match, start: pathM.start, end: pathM.end }); }
    const secretM = matchOf(SECRET_ENV_RE, text);
    if (secretM) { flags.push('reads a secret env var'); hits.push({ flag: 'reads a secret env var', match: secretM.match, start: secretM.start, end: secretM.end }); }
    if (flags.length) findings.push({ tool: t.name, flags, severity, hits });
  }
  return findings;
}
