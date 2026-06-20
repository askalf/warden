// Policy: allow/deny rules + egress allowlist + write roots. Loadable from a
// .warden.json file (Claude-Code-style rule syntax: `tool(glob)`).
import fs from 'node:fs';
import { safeStringify } from './scan.mjs';

export const DEFAULT_POLICY = { allow: [], deny: [], egressAllow: [], writeRoots: null };

// Linear, anchored glob match where only `*` is special (matches any run of
// chars, INCLUDING newlines). Replaces the old `pat.replace(/\*/g,'.*')` + anchored
// RegExp, which had two faults: (1) `.` does not match `\n`, so a rule silently
// FAILED to match a multi-line command — a deny rule was bypassable by adding a
// newline (fail-open); (2) every `*`→`.*` against a non-matching subject caused
// catastrophic backtracking (ReDoS: a multi-star rule could pin a CPU for minutes
// in the firewall's hot path). This greedy left-to-right scan is O(n·segments)
// with no backtracking, and `*` spanning newlines fixes the bypass. (`*`-only
// globs admit a correct greedy match — no `?`/`[]` were ever supported.)
function globMatch(pattern, text) {
  const parts = pattern.split('*');
  if (parts.length === 1) return text === pattern;          // no wildcard → exact
  if (!text.startsWith(parts[0])) return false;             // anchored prefix
  let idx = parts[0].length;
  for (let k = 1; k < parts.length - 1; k++) {              // middle segments, in order
    const seg = parts[k];
    if (!seg) continue;
    const at = text.indexOf(seg, idx);
    if (at < 0) return false;
    idx = at + seg.length;
  }
  const last = parts[parts.length - 1];
  return text.length - last.length >= idx && text.endsWith(last); // anchored suffix
}

/** Does an action match a rule like `shell(npm run test:*)` / `write(src/**)` / `fetch(api.github.com)`? */
export function matchRule(rule, action) {
  const m = /^(\w+)\((.*)\)$/.exec(rule);
  if (!m) return false;
  const [, t, pat] = m;
  if (t.toLowerCase() !== String((action && action.tool) || '').toLowerCase()) return false;
  const i = (action && action.input) || {};
  const subject = i.command || i.path || i.url || i;
  // Coerce safely: a string is itself; an array (split command) joins via
  // map(String) — so a Symbol element can't throw; anything else goes through
  // safeStringify (circular/BigInt/Symbol-safe). A bare String() would throw on
  // a Symbol or a Symbol-bearing array.
  const text = typeof subject === 'string' ? subject
    : Array.isArray(subject) ? subject.map(String).join(' ')
    : safeStringify(subject);
  return globMatch(pat, text);
}

// Coerce a rule list to an array: a scalar/object (e.g. a `.warden.json` with
// `"allow": "shell(*)"` instead of `["shell(*)"]`) must NOT survive as a non-array,
// or the decision engine's `.find()`/`.some()` throws and the hook fails OPEN on a
// black action. A bad value drops to [] (fail closed: nothing pre-allowed).
const asRules = (v) => (Array.isArray(v) ? v : []);

/** Merge a .warden.json file over the defaults. Never throws — bad/missing file → defaults. */
export function loadPolicy(path) {
  try {
    const parsed = JSON.parse(fs.readFileSync(path, 'utf8'));
    return normalizePolicy({ ...DEFAULT_POLICY, ...parsed });
  } catch {
    return { ...DEFAULT_POLICY };
  }
}

/** Force the rule/egress lists to arrays and writeRoots to array|null. Idempotent. */
export function normalizePolicy(policy) {
  const p = policy || {};
  return {
    ...p,
    allow: asRules(p.allow),
    deny: asRules(p.deny),
    egressAllow: asRules(p.egressAllow),
    writeRoots: Array.isArray(p.writeRoots) ? p.writeRoots : null,
  };
}
