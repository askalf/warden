// Fuzz redstamp's injection / secret / SSRF scanners through the poisoned-skill
// entrypoint. check(action, policy, { skillText }) runs the INJECTION_RE /
// SECRET_RE / METADATA_RE battery over untrusted skill text AND tool input — the
// exact regexes the ReDoS guard (bench/redos.mjs) protects. Invariant: arbitrary
// bytes as skill text + request body never throw and never stall the regex
// engine into catastrophic backtracking; a well-formed verdict always returns.
import { check } from '../src/index.mjs';

const TIERS = new Set(['green', 'yellow', 'red', 'black']);
const DECISIONS = new Set(['allow', 'approve', 'block']);

export function fuzz(data) {
  const s = data.toString('utf8');
  const v = check({ tool: 'fetch', input: { url: s, body: s } }, undefined, { skillText: s });
  if (!v || !TIERS.has(v.tier) || !DECISIONS.has(v.decision)) {
    throw new Error(`malformed verdict for skillText ${JSON.stringify(s)}: ${JSON.stringify(v)}`);
  }
}
