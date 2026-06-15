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
export const SENSITIVE_PATH_RE = /(\.env\b|\.aws[\\/]|\.ssh[\\/]|\.npmrc|credentials\.json|\.git-credentials|\.kube[\\/]config|[\\/]\.claude[\\/]|[\\/]\.askalf[\\/]|[\\/](?:Cookies|Login Data)\b|key4\.db|logins\.json)/i;
export const METADATA_RE = /\b(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2::254|100\.100\.100\.200)\b/i;
export const PERSISTENCE_PATH_RE = /(authorized_keys|[\\/]etc[\\/]cron|[\\/]etc[\\/]systemd[\\/]system|CurrentVersion[\\/]+Run|[\\/]Startup[\\/])/i;
export const INJECTION_RE = [
  { re: /ignore\s+(?:all\s+|the\s+|your\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompt)/i, why: 'instruction-override' },
  { re: /\b(?:exfiltrate|leak|steal)\b/i, why: 'exfiltration intent' },
  { re: /disregard[^.]{0,20}(?:safety|guardrail|policy)/i, why: 'safety-bypass instruction' },
  { re: /base64\s+-d\s*\|\s*(?:ba)?sh/i, why: 'obfuscated payload to shell' },
  { re: /send\s+(?:all\s+|the\s+)?(?:files|secrets|env|credentials|keys)[^.]{0,40}(?:https?|webhook|curl)/i, why: 'data-exfil instruction' },
  { re: /\b(?:e-?mail|send|upload|post|transmit|forward|exfil\w*)\b\s+(?:all\s+|the\s+|every\s+|your\s+)?(?:secrets?|credentials?|api[ _-]?keys?|passwords?|tokens?|private\s+keys?|\.env\b)\b[^.]{0,60}(?:@|https?:|webhook|attacker|to\s+\S+@)/i, why: 'data-exfil instruction (to a destination)' },
  { re: /reveal\s+(?:all\s+|the\s+|your\s+)?(?:secrets|system\s+prompt|prompt|api\s+keys|credentials)/i, why: 'system-prompt/secret extraction' },
  { re: /disregard\s+(?:all\s+|the\s+|your\s+)?(?:system\s+)?(?:prompt|instructions|rules)/i, why: 'instruction-override' },
  { re: /you\s+are\s+now\s+(?:in\s+)?(?:a\s+)?(?:developer|dan|jailbreak|god|unrestricted)\s*-?\s*mode/i, why: 'jailbreak persona' },
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

// Obfuscation / evasion *smells* — NOT detections. Regex can't safely decide
// whether `X=rm;$X -rf /` or `rm${IFS}-rf${IFS}/` is malicious (deobfuscating
// arbitrary shell is undecidable by pattern), so a command matching these is
// classified normally by the deterministic gate but flagged GRAY so the LLM
// judge (which CAN deobfuscate) gets a look. Liberal by design: a false smell
// costs one judge call that returns benign — never a false block.
export const OBFUSCATION_RE = [
  { re: /\$\{?IFS\}?/, why: 'IFS word-splitting (anti-detection)' },
  { re: /\$\w+\$\w+/, why: 'concatenated variables as a command' },
  { re: /\|\s*\$\{?\w+\}?(?:\s|$)/, why: 'pipes into a variable-named command' },
  { re: /\b\w{1,4}=[^;\s|]{1,16}\s*;[^;]{0,40}\$\{?\w/, why: 'assigns then invokes via a variable' },
  { re: /\bxxd\s+-r\b|\b(?:base32|openssl\s+enc)\b[^|]*\|\s*(?:ba)?sh\b/i, why: 'decodes then pipes to a shell' },
  { re: /\beval\b/i, why: 'eval of dynamic content' },
  { re: /(?:\\x[0-9a-f]{2}){3,}/i, why: 'hex-escaped payload' },
];

export function obfuscationHits(text = '') {
  return OBFUSCATION_RE.filter((p) => p.re.test(text)).map((p) => p.why);
}
