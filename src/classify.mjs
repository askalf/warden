// Risk classification for agent tool-calls. Deterministic, offline, fast.
export const TIER = { GREEN: 'green', YELLOW: 'yellow', RED: 'red', BLACK: 'black' };
export const ORDER = { green: 0, yellow: 1, red: 2, black: 3 };
export const worst = (a, b) => (ORDER[a] >= ORDER[b] ? a : b);

export const SHELL = ['shell', 'bash', 'exec', 'run', 'powershell', 'cmd', 'terminal'];
export const NET = ['fetch', 'http', 'request', 'webhook', 'post', 'curl'];
export const WRITE = ['write', 'edit', 'create', 'append', 'notebookedit'];
export const READONLY = ['read', 'get', 'list', 'ls', 'grep', 'glob', 'status', 'stat'];

export const BLACK_SHELL = [
  { re: /\brm\s+-[a-z]*r[a-z]*f?\b[^|]*(\s|\/|~|\$HOME|\*)/i, why: 'recursive force-delete' },
  { re: /\bmkfs(\.\w+)?\b/i, why: 'format filesystem' },
  { re: /\bdd\b[^|]*\bof=\/dev\/(sd|nvme|disk)/i, why: 'raw disk overwrite' },
  { re: /:\(\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:/, why: 'fork bomb' },
  { re: /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b/i, why: 'pipe remote script to shell (RCE)' },
  { re: /\bchmod\s+-R\s+0?777\s+\//i, why: 'world-writable root' },
  { re: /\bhistory\s+-c\b|\bunset\s+HISTFILE\b|rm\s+[^|]*\.bash_history/i, why: 'covering tracks (history wipe)' },
  { re: /\/dev\/tcp\//i, why: 'reverse shell (/dev/tcp)' },
  { re: /\bnc\b[^|]*\s-[a-z]*e\b/i, why: 'netcat exec (reverse shell)' },
  { re: /\beval\b[^|]*\$\(\s*(?:curl|wget)\b/i, why: 'eval of remote download (RCE)' },
  { re: /\bbase64\b[^|]*(?:-d|--decode)[^|]*\|\s*(?:ba)?sh\b/i, why: 'base64-decode piped to shell (obfuscated RCE)' },
  { re: /\b(?:python[0-9.]*|perl|ruby|php)\b\s+-[ce]\b(?=[^|]*\b(?:socket|fsockopen)\b)(?=[^|]*\b(?:connect|subprocess|exec|system|pty|\/bin\/(?:ba)?sh)\b)/i, why: 'interpreter reverse shell' },
  { re: /\b(?:iptables\s+-F|ufw\s+disable|setenforce\s+0)\b/i, why: 'disables host firewall/SELinux' },
  { re: /(?:Set|Add)-MpPreference[^|]*-(?:Disable\w+|ExclusionPath)/i, why: 'disables/evades Microsoft Defender' },
  { re: /\|\s*crontab\b/i, why: 'installs a crontab (persistence)' },
  { re: /(?:>>?|tee\b|\bcp\b|\bmv\b|\becho\b|install)[^|]*authorized_keys/i, why: 'writes an SSH backdoor (authorized_keys)' },
  { re: /(?:>>?|tee\b|\bcp\b|\bmv\b)[^|]*[\\/]etc[\\/](?:cron|systemd)/i, why: 'writes a persistence unit (cron/systemd)' },
  { re: /\b(?:tar|cat|cp|zip|gzip|dd)\b[^|]*(?:\.ssh|id_rsa|id_ed25519|\.aws|\.env\b|authorized_keys|credentials)[^|]*\|\s*(?:nc|ncat|curl|wget|socat)\b/i, why: 'pipe sensitive files to the network (exfil)' },
  { re: /\b(?:scp|rsync)\b(?:\s+-\w+\s+\S+|\s+-\w+)*\s+\S*(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|\.pem\b|\.ppk\b|\.aws[\\/]credentials|\.env\b)\S*\s+\S*@\S+:/i, why: 'exfiltrate a key/credential via scp/rsync' },
  { re: /\breg\s+add\b[^|]*(?:CurrentVersion[\\/]+Run|Image\s+File\s+Execution)/i, why: 'registry Run-key persistence' },
  { re: /\bpowershell(?:\.exe)?\b[^|]*\s-e(?:c|nc|ncodedcommand)?\b\s+[A-Za-z0-9+/=]{16,}/i, why: 'powershell encoded command (obfuscation)' },
  { re: /\b(?:IEX|Invoke-Expression|iwr|irm)\b[^|]*(?:DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|https?:)/i, why: 'powershell download-cradle (RCE)' },
  { re: /\bvssadmin\b[^|]*\bdelete\b[^|]*shadow/i, why: 'deletes volume shadow copies (ransomware)' },
  { re: /\bnet\s+localgroup\s+admin\w*\b[^|]*\/add/i, why: 'adds a backdoor admin account' },
  { re: /\bdocker\s+run\b[^|]*-v\s+\/:(?:\/|\s|$)/i, why: 'mounts host root into container (escape)' },
  { re: /\bnsenter\b[^|]*--target\s+1\b/i, why: 'namespace escape to host (nsenter)' },
  { re: /\b(?:env|printenv|set)\b\s*\|\s*(?:curl|wget|nc|ncat)\b/i, why: 'pipes environment to the network (exfil)' },
  { re: /\b(?:nslookup|dig|host)\b[^|]*\$\([^)]*(?:cat|base64|whoami|hostname|env|printenv)/i, why: 'DNS exfiltration' },
];
export const RED_SHELL = [
  { re: /\bsudo\b/i, why: 'privilege escalation' },
  { re: /(?<![-\w])rm\s+\S/i, why: 'file deletion' },
  { re: /\bgit\s+push\b/i, why: 'outward-facing: pushes code' },
  { re: /\b(npm|pnpm|yarn|pip|apt|brew|choco)\s+(i|install|add)\b/i, why: 'installs packages (supply-chain)' },
  { re: /\b(kill|pkill|taskkill)\b/i, why: 'kills processes' },
  { re: /\b(systemctl|service)\s+(stop|disable|mask)\b/i, why: 'disables services' },
  { re: /\b(?:kubectl\s+delete|terraform\s+destroy|aws\s+s3\s+rm\b[^|]*--recursive|docker\s+(?:rm|rmi)\s+-f|helm\s+(?:delete|uninstall))\b/i, why: 'destructive infrastructure operation' },
  { re: /\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b/i, why: 'destructive database operation' },
  { re: /\b(?:scp|rsync)\b[^|]*\S+@\S+:/i, why: 'remote file transfer' },
  { re: /\bdocker\s+run\b[^|]*--(?:privileged|pid[= ]host|net[= ]host|cap-add[= ]?SYS_ADMIN)/i, why: 'privileged / host-namespace container' },
  { re: /\bmount\b\s+\/dev\//i, why: 'mounts a block device' },
  { re: /\bnet\s+user\b[^|]*\/add/i, why: 'creates a user account' },
  { re: /\bwmic\b[^|]*process[^|]*call\s+create|\bInvoke-WmiMethod\b/i, why: 'WMI process creation' },
];
export const YELLOW_SHELL = [
  { re: /\b(mkdir|touch|mv|cp)\b/i, why: 'reversible filesystem change' },
  { re: /(^|\s)(echo|printf)\b[^|]*>{1,2}/i, why: 'writes to a file' },
];

/** Classify an action {tool, input} into a risk tier with reasons. */
export function classify(action) {
  const tool = (action.tool || '').toLowerCase();
  const input = action.input || {};
  const why = [];
  let tier = TIER.GREEN;

  if (SHELL.includes(tool)) {
    const cmd = input.command || input.cmd || JSON.stringify(input);
    for (const p of BLACK_SHELL) if (p.re.test(cmd)) { tier = worst(tier, TIER.BLACK); why.push('☠ ' + p.why); }
    for (const p of RED_SHELL) if (p.re.test(cmd)) { tier = worst(tier, TIER.RED); why.push('⚠ ' + p.why); }
    for (const p of YELLOW_SHELL) if (p.re.test(cmd)) { tier = worst(tier, TIER.YELLOW); why.push('· ' + p.why); }
    if (tier === TIER.GREEN) why.push('· read-only shell');
  } else if (WRITE.includes(tool)) {
    tier = TIER.YELLOW; why.push('· file write (reversible)');
  } else if (['delete', 'rm', 'unlink'].includes(tool)) {
    tier = TIER.RED; why.push('⚠ file deletion');
  } else if (NET.includes(tool)) {
    const m = (input.method || 'GET').toUpperCase();
    if (m !== 'GET' && m !== 'HEAD') { tier = TIER.RED; why.push('⚠ outbound ' + m); } else why.push('· outbound GET');
  } else if (READONLY.includes(tool)) {
    why.push('· read-only');
  } else {
    tier = TIER.YELLOW; why.push('· unknown tool — treat with care');
  }
  return { tier, why };
}
