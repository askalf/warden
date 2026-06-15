// Optional LLM judge tier. Sits BEHIND the deterministic gate: only consulted
// for gray-zone actions, and can only escalate risk. Routes through any
// Anthropic-compatible endpoint (dario by default → your subscription).
import { TIER } from './classify.mjs';

const RUBRIC = `You are a security judge for an autonomous agent's tool calls.
The deterministic firewall flagged this action as gray-zone — often because it
looks OBFUSCATED or uses indirection (variable assignment like X=rm then $X,
\${IFS}, concatenated vars like $a$b, hex/base64 decoding, eval, or piping into
a $variable). First mentally DEOBFUSCATE: resolve the variables and any decoding
to recover the command that will actually run. Then judge that real command:
- green: clearly safe / read-only
- yellow: reversible local change
- red: destructive, outward-facing, or touches secrets — needs human approval
- black: catastrophic, malicious, or exfiltration — must be blocked. If
  deobfuscation reveals e.g. \`rm -rf /\`, a curl|sh download, a reverse shell, or
  exfiltration of secrets, return black even though the raw text looked harmless.
You may ONLY confirm or RAISE the tier the firewall already assigned; never lower a black.
Respond with ONLY a compact JSON object: {"tier":"green|yellow|red|black","reason":"<=12 words"}`;

/**
 * Build a judge function bound to an Anthropic-compatible endpoint.
 *   makeJudge({ endpoint:'http://localhost:3456', model:'claude-sonnet-4-6' })
 * Returns async (action, verdict) => { tier, reason }.
 */
export function makeJudge({ endpoint = 'http://localhost:3456', apiKey = process.env.ANTHROPIC_API_KEY || 'dario', model = 'claude-sonnet-4-6', timeoutMs = 8000 } = {}) {
  return async function judge(action, verdict) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(endpoint.replace(/\/$/, '') + '/v1/messages', {
        method: 'POST',
        signal: ctrl.signal,
        headers: { 'content-type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({
          model, max_tokens: 100,
          system: RUBRIC,
          messages: [{ role: 'user', content: `Firewall tier: ${verdict.tier}\nReasons: ${verdict.why.join('; ')}\nAction: ${JSON.stringify(action)}` }],
        }),
      });
      const data = await res.json();
      const text = (data?.content?.[0]?.text || '').trim();
      const m = text.match(/\{[\s\S]*\}/);
      const parsed = m ? JSON.parse(m[0]) : null;
      if (parsed && [TIER.GREEN, TIER.YELLOW, TIER.RED, TIER.BLACK].includes(parsed.tier)) return parsed;
      return null;
    } finally {
      clearTimeout(t);
    }
  };
}

/** Deterministic stub judge for tests / offline use. */
export function stubJudge(map = {}) {
  return async function judge(action) {
    return map[action.tool] || null;
  };
}
