// Policy: allow/deny rules + egress allowlist + write roots. Loadable from a
// .warden.json file (Claude-Code-style rule syntax: `tool(glob)`).
import fs from 'node:fs';

export const DEFAULT_POLICY = { allow: [], deny: [], egressAllow: [], writeRoots: null };

/** Does an action match a rule like `shell(npm run test:*)` / `write(src/**)` / `fetch(api.github.com)`? */
export function matchRule(rule, action) {
  const m = /^(\w+)\((.*)\)$/.exec(rule);
  if (!m) return false;
  const [, t, pat] = m;
  if (t.toLowerCase() !== (action.tool || '').toLowerCase()) return false;
  const i = action.input || {};
  const subject = i.command || i.path || i.url || JSON.stringify(i);
  const re = new RegExp('^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
  return re.test(subject);
}

/** Merge a .warden.json file over the defaults. Never throws — bad/missing file → defaults. */
export function loadPolicy(path) {
  try {
    const parsed = JSON.parse(fs.readFileSync(path, 'utf8'));
    return { ...DEFAULT_POLICY, ...parsed };
  } catch {
    return { ...DEFAULT_POLICY };
  }
}
