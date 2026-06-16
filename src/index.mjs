// warden — own your agent security. A guard between an agent and its tools.
import { TIER, ORDER, worst, classify, SHELL, NET, WRITE } from './classify.mjs';
import { scanSecrets, injectionHits, obfuscationHits, isExternal, ipScope, safeStringify, METADATA_RE, PERSISTENCE_PATH_RE } from './scan.mjs';
import { matchRule, DEFAULT_POLICY, loadPolicy } from './policy.mjs';
import { AuditLog } from './audit.mjs';

export { TIER, AuditLog, classify, loadPolicy, matchRule };

/** Deterministic verdict for an action. No I/O, no LLM — pure + offline. */
export function decide(action, policy = DEFAULT_POLICY, skillText = '') {
  // Fail safe on malformed input: a null/non-object action or a non-string tool
  // must yield a verdict, never throw into the host agent.
  action = action || {};
  const { allow = [], deny = [], egressAllow = [], writeRoots = null } = policy || {};
  const tool = String(action.tool || '').toLowerCase();
  const base = classify(action);
  // Bound the scanned text. Secrets / injection phrases / metadata hosts that
  // matter appear early, and the classifier already caps the command at 16KB —
  // so a giant input field can't turn each firewall call into a heavy (linear
  // but unbounded) scan (a DoS-amplification vector). 64KB is a generous window.
  const SCAN_CAP = 65536;
  const fullStr = safeStringify(action.input || {});
  const inputStr = fullStr.length > SCAN_CAP ? fullStr.slice(0, SCAN_CAP) : fullStr; // reused by scanSecrets + injection/SSRF below
  const secrets = scanSecrets(action, inputStr);
  let tier = base.tier;
  const why = [...base.why];

  const active = SHELL.includes(tool) || NET.includes(tool); // executes or sends — only here is data "in motion"
  const externalHosts = secrets.hosts.filter((h) => isExternal(h, egressAllow));

  // exfil = a secret + an external destination, but ONLY when the tool actually sends (shell/net).
  // A secret sitting in file content (write/read) is flagged red, not treated as exfiltration.
  if (secrets.hasSecret && externalHosts.length && active) {
    tier = TIER.BLACK;
    why.push('☠ EXFIL: ' + secrets.flags.join('; ') + ' → external ' + externalHosts.join(','));
  } else if (secrets.hasSecret) {
    tier = worst(tier, TIER.RED);
    why.push(...secrets.flags.map((f) => '⚠ ' + f));
  }
  // injection: a poisoned skill is always black; injection in an executable arg is black;
  // injection patterns in passive file content are flagged red (it's data, not execution).
  const injSkill = injectionHits(skillText || '');
  if (injSkill.length) { tier = TIER.BLACK; why.push(...injSkill.map((f) => '☠ poisoned-skill: ' + f)); }
  // Injection scanning targets DATA the agent consumes (skill text, file content,
  // request bodies) — NOT shell-command args. A human running `echo "ignore all
  // previous instructions"` or `grep "you are now in developer mode"` is benign;
  // shell threats are the classifier's job. Scanning command text for injection
  // English only false-blocks legitimate work, so skip it for shell tools.
  const injInput = SHELL.includes(tool) ? [] : injectionHits(inputStr);
  if (injInput.length) { const it = active ? TIER.BLACK : TIER.RED; tier = worst(tier, it); why.push(...injInput.map((f) => (active ? '☠' : '⚠') + ' injection: ' + f)); }
  // SSRF — only meaningful for tools that fetch/exec. Cloud-metadata hosts and
  // the link-local range (169.254/16) are credential-theft-grade (black); an
  // http(s) request to an RFC1918 internal address is gated (red). Loopback is
  // intentionally NOT flagged (dev-server requests would false-positive).
  if (active) {
    const scopes = secrets.hosts.map(ipScope);
    if (METADATA_RE.test(inputStr) || scopes.includes('linklocal')) {
      tier = TIER.BLACK; why.push('☠ cloud-metadata / link-local SSRF (credential theft)');
    } else if (scopes.includes('private')) {
      tier = worst(tier, TIER.RED); why.push('⚠ http request to an internal/RFC1918 address (SSRF risk)');
    }
  }
  // persistence/backdoor: writing into a known persistence location. Only a
  // string path is a real write target; a non-string (Symbol/array/object) path
  // fails safe to '' rather than throwing on coercion.
  const wpath = typeof action.input?.path === 'string' ? action.input.path : '';
  if (WRITE.includes(tool) && PERSISTENCE_PATH_RE.test(wpath)) { tier = TIER.BLACK; why.push('☠ persistence target: ' + wpath); }
  if (NET.includes(tool) && externalHosts.length && egressAllow.length) {
    tier = worst(tier, TIER.RED);
    why.push('⚠ egress to non-allowlisted host(s): ' + externalHosts.join(','));
  }
  if (writeRoots && WRITE.includes(tool)) {
    const p = wpath;
    if (p && !writeRoots.some((r) => p.startsWith(r))) {
      tier = worst(tier, TIER.RED);
      why.push('⚠ write outside allowed roots: ' + p);
    }
  }

  // obfuscation router: a command that *smells* evasive but classified clean is
  // routed to the judge (marked gray) WITHOUT changing the deterministic verdict
  // — so with no judge configured it still allows (no false block), and with a
  // judge it gets deobfuscated. This is how the evasion bucket reaches the judge.
  let smells = [];
  if (SHELL.includes(tool) && tier !== TIER.BLACK) {
    const c = action.input?.command ?? action.input?.cmd;
    const ctext = typeof c === 'string' ? c : inputStr;
    smells = obfuscationHits(ctext.length > SCAN_CAP ? ctext.slice(0, SCAN_CAP) : ctext);
    if (smells.length) why.push(...smells.map((f) => '· obfuscation smell → judge: ' + f));
  }

  const denied = deny.find((r) => matchRule(r, action));
  const allowed = allow.find((r) => matchRule(r, action));

  let decision;
  if (denied) { decision = 'block'; why.push('✗ denied by rule: ' + denied); }
  else if (tier === TIER.BLACK) decision = 'block';
  else if (allowed) { decision = 'allow'; why.push('✓ pre-approved by rule: ' + allowed); }
  else if (tier === TIER.RED) decision = 'approve';
  else decision = 'allow';

  return { tool: action.tool, tier, decision, why, externalHosts, gray: decision === 'approve' || tier === TIER.YELLOW || smells.length > 0 };
}

const recordVerdict = (audit, action, v) =>
  audit && audit.record({ ts: new Date().toISOString(), tool: action.tool, input: action.input, tier: v.tier, decision: v.decision, why: v.why });

/** Sync deterministic check (optionally records to an AuditLog). */
export function check(action, policy = DEFAULT_POLICY, { audit = null, skillText = '' } = {}) {
  const v = decide(action, policy, skillText);
  recordVerdict(audit, action, v);
  return v;
}

/**
 * Async check that consults an optional LLM judge for gray-zone actions.
 * The judge can only ESCALATE risk — a deterministic BLACK is final, and the
 * judge is never asked to bless something the rules already blocked.
 */
export async function checkAsync(action, policy = DEFAULT_POLICY, { audit = null, skillText = '', judge = null } = {}) {
  const v = decide(action, policy, skillText);
  if (judge && v.decision !== 'block' && v.gray) {
    try {
      const j = await judge(action, v);
      if (j && j.tier && ORDER[j.tier] > ORDER[v.tier]) {
        v.tier = j.tier;
        v.why.push(`🧠 judge escalated → ${j.tier}: ${j.reason || 'unspecified'}`);
        if (j.tier === TIER.BLACK) v.decision = 'block';
        else if (j.tier === TIER.RED && v.decision === 'allow') v.decision = 'approve';
      } else if (j && j.reason) {
        v.why.push(`🧠 judge: ${j.reason}`);
      }
    } catch (e) {
      v.why.push('🧠 judge unavailable (fail-safe: kept deterministic verdict)');
    }
  }
  recordVerdict(audit, action, v);
  return v;
}
