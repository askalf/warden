// Secret/exfil and prompt-injection / poisoned-skill scanners.
export const SECRET_RE = [
  { re: /sk-ant-[A-Za-z0-9_-]{20,}/, why: 'Anthropic API key' },
  { re: /sk-[A-Za-z0-9]{20,}/, why: 'OpenAI-style API key' },
  { re: /ghp_[A-Za-z0-9]{30,}/, why: 'GitHub PAT' },
  { re: /AKIA[0-9A-Z]{16}/, why: 'AWS access key id' },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, why: 'private key' },
  { re: /xox[baprs]-[A-Za-z0-9-]{10,}/, why: 'Slack token' },
];
export const SECRET_ENV_RE = /\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\w*\}?/i;
export const SENSITIVE_PATH_RE = /(\.env\b|\.aws[\\/]|\.ssh[\\/]|\.npmrc|credentials\.json|\.git-credentials|\.kube[\\/]config|[\\/]\.claude[\\/]|[\\/]\.askalf[\\/])/i;
export const METADATA_RE = /\b(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2::254|100\.100\.100\.200)\b/i;
export const PERSISTENCE_PATH_RE = /(authorized_keys|[\\/]etc[\\/]cron|[\\/]etc[\\/]systemd[\\/]system|CurrentVersion[\\/]+Run|[\\/]Startup[\\/])/i;
export const INJECTION_RE = [
  { re: /ignore\s+(?:all\s+|the\s+|your\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompt)/i, why: 'instruction-override' },
  { re: /\b(?:exfiltrate|leak|steal)\b/i, why: 'exfiltration intent' },
  { re: /disregard[^.]{0,20}(?:safety|guardrail|policy)/i, why: 'safety-bypass instruction' },
  { re: /base64\s+-d\s*\|\s*(?:ba)?sh/i, why: 'obfuscated payload to shell' },
  { re: /send\s+(?:all\s+|the\s+)?(?:files|secrets|env|credentials|keys)[^.]{0,40}(?:https?|webhook|curl)/i, why: 'data-exfil instruction' },
];
export const URL_RE = /https?:\/\/([^\/\s'"]+)/gi;

export function isExternal(host, allow = []) {
  if (!host) return false;
  const h = host.toLowerCase();
  if (/^(localhost|127\.|0\.0\.0\.0|::1|\[)/.test(h)) return false;
  return !allow.some((d) => h === d || h.endsWith('.' + d));
}

export function scanSecrets(action) {
  const text = JSON.stringify(action.input || {});
  const flags = [];
  for (const s of SECRET_RE) if (s.re.test(text)) flags.push(s.why);
  if (SECRET_ENV_RE.test(text)) flags.push('reads a secret env var');
  if (SENSITIVE_PATH_RE.test(text)) flags.push('touches a sensitive path');
  const hosts = [...text.matchAll(URL_RE)].map((m) => m[1]);
  return { flags, hosts, hasSecret: flags.length > 0 };
}

export function injectionHits(text = '') {
  return INJECTION_RE.filter((p) => p.re.test(text)).map((p) => p.why);
}

export function scanInjection(action, skillText = '') {
  return injectionHits(JSON.stringify(action.input || {}) + ' ' + skillText);
}
