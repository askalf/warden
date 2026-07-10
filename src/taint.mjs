// Cross-call taint tracking — the stateful layer over the stateless core.
//
// decide() classifies ONE call in isolation, which an attacker evades by
// splitting an exfil across calls: read a secret into a temp file (call 1 —
// looks like a sensitive read), then ship that temp file to an external host
// (call 2 — looks benign, because THIS call carries no visible secret). Only a
// session that remembers call 1 can catch call 2.
//
// TaintSession is opt-in and additive: decide() is untouched and every verdict
// here starts from it. The session can only RAISE risk (like the judge tier),
// never lower a block — so wrapping a stream of calls is always at least as safe
// as calling decide() on each. Deterministic and offline: no model, no network.
import { decide, TIER } from './index.mjs';
import { scanSecrets, isExternal, safeStringify, SENSITIVE_PATH_RE } from './scan.mjs';
import { normalizePolicy } from './policy.mjs';

const ORDER = { green: 0, yellow: 1, red: 2, black: 3 };
const worst = (a, b) => (ORDER[a] >= ORDER[b] ? a : b);

// The command text of an action, symbol/array/circular-safe (never throws).
function cmdText(action) {
  const i = (action && action.input) || {};
  const c = i.command ?? i.cmd;
  if (typeof c === 'string') return c;
  if (Array.isArray(c)) return c.map((x) => (typeof x === 'string' ? x : '')).join(' ');
  return safeStringify(i);
}

// Destinations a command writes secret-bearing output INTO — so the taint flows
// to that file. `cat ~/.ssh/id_rsa > /tmp/x`, `cp .env /tmp/x`, `tar czf /tmp/x`.
function writeDests(cmd) {
  const out = [];
  // redirection: `> file` / `>> file` (not a fd dup like `2>&1`)
  for (const m of cmd.matchAll(/(?<![0-9&])>>?\s*([^\s|;&<>()]{1,200})/g)) out.push(m[1]);
  // cp/mv/install SRC ... DEST  (last non-flag token is the destination)
  for (const m of cmd.matchAll(/\b(?:cp|mv|install)\b((?:\s+-\S+|\s+[^\s|;&]+){2,})/gi)) {
    const toks = m[1].trim().split(/\s+/).filter((t) => !t.startsWith('-'));
    if (toks.length >= 2) out.push(toks[toks.length - 1]);
  }
  // tar/zip archive target: `tar czf DEST ...`, `zip DEST ...`
  for (const m of cmd.matchAll(/\b(?:tar\s+[a-z]*f|zip(?:\s+-\S+)*)\s+([^\s|;&]{1,200})/gi)) out.push(m[1]);
  return out;
}

// Does the command actually SEND data out (vs. a plain GET)? Used to keep the
// weaker in-memory-secret signal precise: reading a secret then GETting an
// external URL is usually benign; POSTing/uploading data after is the concern.
const SEND_SHAPE = /-d\b|--data(?:-binary|-raw)?\b|-F\b|--form\b|-T\b|--upload-file\b|-X\s*POST\b|--request\s+POST\b|\bnc\b|\bncat\b|\bscp\b|\brsync\b|\bsocat\b/i;
function looksLikeSend(cmd, action) {
  if (SEND_SHAPE.test(cmd)) return true;
  const m = ((action && action.input && (action.input.method)) || '');
  return typeof m === 'string' && /^(post|put|patch)$/i.test(m);
}

// (src, dst) pairs so taint propagates through a copy/move of a tainted file.
function copyPairs(cmd) {
  const pairs = [];
  for (const m of cmd.matchAll(/\b(?:cp|mv|install)\b((?:\s+-\S+|\s+[^\s|;&]+){2,})/gi)) {
    const toks = m[1].trim().split(/\s+/).filter((t) => !t.startsWith('-'));
    if (toks.length >= 2) for (let k = 0; k < toks.length - 1; k++) pairs.push([toks[k], toks[toks.length - 1]]);
  }
  return pairs;
}

function escalate(v, tier, why) {
  const t = worst(v.tier, tier);
  const decision = t === TIER.BLACK ? 'block' : t === TIER.RED ? (v.decision === 'block' ? 'block' : 'approve') : v.decision;
  return { ...v, tier: t, decision, why: [...v.why, why], crossCall: true };
}

export class TaintSession {
  constructor(policy = undefined) {
    this.policy = policy;
    this._egress = normalizePolicy(policy).egressAllow || [];
    this.taintedPaths = new Set(); // files that hold secret-derived bytes
    this.holdsSecret = false;      // a secret was read to stdout/memory this session
    this.calls = 0;
  }

  // Classify one call in the CONTEXT of the session so far. Returns decide()'s
  // verdict, possibly RAISED for a cross-call flow. Never throws, never lowers.
  // `skillText` is forwarded to decide() unchanged so callers that vet skill
  // text (the daemon's action-shape requests) keep that classification when they
  // route through a session.
  check(action, skillText = '') {
    this.calls++;
    let v;
    try { v = decide(action, this.policy, skillText); } catch { return { tool: action && action.tool, tier: TIER.RED, decision: 'approve', why: ['⚠ taint: guard error — fail-safe gate'], crossCall: true }; }
    let out = v;
    try {
      const cmd = cmdText(action);
      const sec = scanSecrets(action);
      const extern = (sec.hosts || []).filter((h) => isExternal(h, this._egress));

      // ── SINK: is this call shipping tainted data OUT? (evaluate before we
      //    re-taint on this same call) ──
      if (out.decision !== 'block' && extern.length) {
        const sentPath = [...this.taintedPaths].find((p) => p && cmd.includes(p));
        if (sentPath) {
          out = escalate(out, TIER.BLACK, `☠ CROSS-CALL EXFIL: ${sentPath} (derived from a secret read earlier this session) → external ${extern.join(',')}`);
        } else if (out.decision === 'allow' && this.holdsSecret && looksLikeSend(cmd, action)) {
          // weaker signal: a DATA-SEND (not a plain GET) to an external host
          // after a secret was read this session, with no tainted file named —
          // gate for review rather than block.
          out = escalate(out, TIER.RED, `⚠ cross-call: external data-send to ${extern.join(',')} after a secret was read this session`);
        }
      }

      // ── SOURCE + PROPAGATION: update taint AFTER classifying this call ──
      if (sec.hasSecret) {
        const dests = writeDests(cmd);
        if (dests.length) for (const d of dests) this.taintedPaths.add(d);
        else this.holdsSecret = true; // read to stdout/memory, no file target
      }
      for (const [src, dst] of copyPairs(cmd)) {
        if (this.taintedPaths.has(src) || SENSITIVE_PATH_RE.test(src)) this.taintedPaths.add(dst);
      }
    } catch { /* taint analysis is best-effort; the stateless verdict always stands */ }
    return out;
  }

  // Inspect / reset session state (for a new agent task).
  state() { return { calls: this.calls, holdsSecret: this.holdsSecret, taintedPaths: [...this.taintedPaths] }; }
  reset() { this.taintedPaths.clear(); this.holdsSecret = false; this.calls = 0; }
}

// Convenience: wrap a stream of actions, returning the per-call verdicts.
export function checkSequence(actions, policy) {
  const s = new TaintSession(policy);
  return (Array.isArray(actions) ? actions : []).map((a) => s.check(a));
}
