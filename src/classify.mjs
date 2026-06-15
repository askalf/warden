// Risk classification for agent tool-calls. Deterministic, offline, fast.
import { safeStringify } from './scan.mjs';
export const TIER = { GREEN: 'green', YELLOW: 'yellow', RED: 'red', BLACK: 'black' };
export const ORDER = { green: 0, yellow: 1, red: 2, black: 3 };
export const worst = (a, b) => (ORDER[a] >= ORDER[b] ? a : b);

export const SHELL = ['shell', 'bash', 'exec', 'run', 'powershell', 'cmd', 'terminal'];
export const NET = ['fetch', 'http', 'request', 'webhook', 'post', 'curl'];
export const WRITE = ['write', 'edit', 'create', 'append', 'notebookedit'];
export const READONLY = ['read', 'get', 'list', 'ls', 'grep', 'glob', 'status', 'stat'];

export const BLACK_SHELL = [
  { re: /\brm\s+-[a-z]*r[a-z]*f?\b[^|]*?(?:--no-preserve-root|\s[/~]\s*$|\s~\/?\s*$|["'\s]\$\{?HOME\b|\s\/?\*|\s\/(?:etc|usr|var|bin|lib|boot|sys|root|home|opt)(?:\/?\s|\/?$))/i, why: 'recursive force-delete of root/home/system/glob' },
  { re: /\bmkfs(\.\w+)?\b/i, why: 'format filesystem' },
  { re: /\bdd\b[^|]*\bof=\/dev\/(sd|nvme|disk)/i, why: 'raw disk overwrite' },
  { re: /:\(\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:/, why: 'fork bomb' },
  { re: /\b(curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:(?:ba)?sh|zsh|python[0-9.]*|node|ruby|perl|php)\b/i, why: 'pipe remote download to an interpreter (RCE)' },
  { re: /\bchmod\s+-R\s+0?777\s+\//i, why: 'world-writable root' },
  { re: /\bhistory\s+-c\b|\bunset\s+HISTFILE\b|rm\s+[^|]*\.bash_history/i, why: 'covering tracks (history wipe)' },
  { re: /\/dev\/tcp\//i, why: 'reverse shell (/dev/tcp)' },
  { re: /\bn(?:c|cat)\b[^|]*\s-[a-z]*e\b/i, why: 'netcat exec (reverse shell)' },
  { re: /\beval\b[^|]*\$\(\s*(?:curl|wget)\b/i, why: 'eval of remote download (RCE)' },
  { re: /\bbase64\b[^|]*(?:-d|--decode)[^|]*\|\s*(?:ba)?sh\b/i, why: 'base64-decode piped to shell (obfuscated RCE)' },
  { re: /\b(?:python[0-9.]*|perl|ruby|php|node)\b(?=[^|]*\b(?:socket|fsockopen|IO::Socket|Socket::INET)\b)(?=[^|]*\b(?:connect|PeerAddr|exec|system|subprocess|popen|fdopen|spawn|\/bin\/(?:ba)?sh)\b)/i, why: 'interpreter reverse shell' },
  { re: /\b(?:iptables\s+-F|ufw\s+disable|setenforce\s+0)\b/i, why: 'disables host firewall/SELinux' },
  { re: /(?:Set|Add)-MpPreference[^|]*-(?:Disable\w+|ExclusionPath)/i, why: 'disables/evades Microsoft Defender' },
  { re: /\|\s*crontab\b/i, why: 'installs a crontab (persistence)' },
  { re: /(?:>>?|tee\b|\bcp\b|\bmv\b|\becho\b|install)[^|]*authorized_keys/i, why: 'writes an SSH backdoor (authorized_keys)' },
  { re: /(?:>>?|tee\b|\bcp\b|\bmv\b|\binstall\b|\becho\b)[^|]*[\\/]etc[\\/](?:cron|systemd|ld\.so\.preload|sudoers|rc\.local|init\.d|profile\.d)/i, why: 'writes a persistence/escalation file (cron/systemd/sudoers/ld.so.preload)' },
  { re: /(?:>>?|tee\b|\bcp\b|\bmv\b)[^|]*[\\/]\.(?:bashrc|bash_profile|bash_login|zshrc|zshenv|zprofile|profile|kshrc|cshrc)\b/i, why: 'writes a shell rc/profile (login persistence)' },
  { re: /\b(?:tar|cat|cp|zip|gzip|dd)\b[^|]*(?:\.ssh|id_rsa|id_ed25519|\.aws|\.env\b|authorized_keys|credentials)[^|]*\|\s*(?:nc|ncat|curl|wget|socat)\b/i, why: 'pipe sensitive files to the network (exfil)' },
  // linear (no nested quantifier → no ReDoS); [^|@]*? before the secret means no
  // earlier @host: dest, and the secret must sit immediately before the dest —
  // so `scp -i ~/.ssh/key dist.tar deploy@host:` (key is auth, not source) stays clean.
  { re: /\b(?:scp|rsync)\b[^|@]*?(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|\.pem\b|\.ppk\b|\.aws[\\/]credentials|\.env\b|[\\/]\.ssh\b|[\\/]\.gnupg\b)\S*\s+\S*@\S+:/i, why: 'exfiltrate a key/credential via scp/rsync' },
  { re: /\bcurl\b[^|]*\s-(?:F|T|d|-form|-upload-file|-data(?:-binary)?)\b[^|]*(?:@?\/etc\/(?:passwd|shadow)|id_rsa|id_ed25519|[\\/]\.ssh[\\/]|\.aws[\\/]credentials|\.env\b|\.pem\b)/i, why: 'uploads a sensitive file via curl (exfil)' },
  { re: /\bwget\b[^|]*--post-file=[^|]*(?:\/etc\/(?:passwd|shadow)|id_rsa|[\\/]\.ssh[\\/]|\.aws[\\/]credentials|\.env\b|credentials)/i, why: 'uploads a sensitive file via wget (exfil)' },
  { re: /\breg\s+add\b[^|]*(?:CurrentVersion[\\/]+Run|Image\s+File\s+Execution)/i, why: 'registry Run-key persistence' },
  { re: /\bpowershell(?:\.exe)?\b[^|]*\s-e(?:c|nc|ncodedcommand)?\b\s+[A-Za-z0-9+/=]{16,}/i, why: 'powershell encoded command (obfuscation)' },
  { re: /\b(?:IEX|Invoke-Expression|iwr|irm)\b[^|]*(?:DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|https?:)/i, why: 'powershell download-cradle (RCE)' },
  { re: /\bvssadmin\b[^|]*\bdelete\b[^|]*shadow/i, why: 'deletes volume shadow copies (ransomware)' },
  { re: /\bnet\s+localgroup\s+admin\w*\b[^|]*\/add/i, why: 'adds a backdoor admin account' },
  { re: /\bdocker\s+run\b[^|]*-v\s+\/:(?:\/|\s|$)/i, why: 'mounts host root into container (escape)' },
  { re: /\bnsenter\b[^|]*(?:--target|-t)\s*1\b/i, why: 'namespace escape to host (nsenter)' },
  { re: /\b(?:env|printenv|set)\b\s*\|\s*(?:curl|wget|nc|ncat)\b/i, why: 'pipes environment to the network (exfil)' },
  { re: /\b(?:nslookup|dig|host)\b[^|]*\$\([^)]*(?:cat|base64|whoami|hostname|env|printenv)/i, why: 'DNS exfiltration' },

  // --- download-and-execute LOLBins (Windows). Scoped so read-only uses
  //     (certutil -hashfile, reg query, sc query) do NOT match. ---
  { re: /\bcertutil(?:\.exe)?\b[^|]*(?:-urlcache|-urlfetch|https?:\/\/)/i, why: 'certutil remote download (LOLBin)' },
  { re: /\bbitsadmin(?:\.exe)?\b[^|]*\/transfer\b/i, why: 'bitsadmin download (LOLBin)' },
  { re: /\bmshta(?:\.exe)?\b[^|]*(?:https?:|javascript:|vbscript:)/i, why: 'mshta remote/script exec (LOLBin)' },
  { re: /\bregsvr32(?:\.exe)?\b[^|]*(?:\/i:\s*https?:|scrobj\.dll)/i, why: 'regsvr32 scriptlet exec (LOLBin)' },
  { re: /\bmsiexec(?:\.exe)?\b[^|]*\/i\b[^|]*https?:/i, why: 'msiexec remote package (LOLBin)' },
  { re: /\bwmic\b[^|]*\bprocess\b[^|]*\bcall\s+create\b/i, why: 'WMI process creation (exec)' },
  // --- download-and-execute (Unix). Process substitution / sh -c that a shell
  //     actually executes; `diff <(curl a) <(curl b)` (no sh/source) won't match. ---
  { re: /(?:\b(?:ba)?sh\b|\bsource\b|(?:^|[;&|])\s*\.)\s*[^|]*<\(\s*(?:curl|wget)\b/i, why: 'process-substitution remote exec (RCE)' },
  { re: /\b(?:ba)?sh\b\s+-c\b[^|]*\$\(\s*(?:curl|wget)\b/i, why: 'sh -c of remote download (RCE)' },
  { re: /\bpython[0-9.]*\b\s+-c\b(?=[^|]*\b(?:urlopen|urlretrieve|requests\.get)\b)(?=[^|]*\b(?:exec|eval|os\.system|subprocess|popen)\b)/i, why: 'python download-and-exec (RCE)' },
  // staged download-then-execute (two-step, not a single pipe)
  { re: /\b(?:curl|wget)\b[^|]*?\s-o\b[^|]*?[;&][^|]*?\b(?:bash|sh|zsh|source)\b/i, why: 'staged download-then-execute (RCE)' },
  { re: /\b(?:curl|wget)\b[^|]*?&&[^|]*?\bchmod\s+\+x\b/i, why: 'download + make-executable (staged RCE)' },
  // git config-override / transport RCE (sshCommand, fsmonitor, pager, ext::)
  { re: /\bgit\b[^|]*\s-c\s+(?:core\.(?:sshCommand|pager|fsmonitor|hooksPath)|gpg\.program)\s*=/i, why: 'git -c config-override RCE' },
  { re: /\bgit\s+config\b[^|]*\bcore\.(?:sshCommand|fsmonitor|pager|hooksPath)\b/i, why: 'git config core.* RCE override' },
  { re: /\bgit\b[^|]*\bext::/i, why: 'git ext:: transport RCE' },
  // --- reverse shells (more) ---
  { re: /\bsocat\b[^|]*\bEXEC:/i, why: 'socat reverse shell (EXEC)' },
  { re: /\bmkfifo\b[\s\S]*\|\s*n(?:c|cat)\b/i, why: 'named-pipe reverse shell (mkfifo|nc)' },
  // --- credential dumping (Windows) ---
  { re: /\breg(?:\.exe)?\s+save\b[^|]*\bHK(?:LM|EY_LOCAL_MACHINE)\\(?:SAM|SECURITY|SYSTEM)\b/i, why: 'dumps SAM/SECURITY hive (credential theft)' },
  { re: /\bcomsvcs\.dll\b.{0,40}\bMiniDump\b|\bprocdump(?:64|\.exe)?\b[^|]*\blsass\b|\bMiniDumpWriteDump\b/i, why: 'LSASS memory dump (credential theft)' },
  // --- Windows persistence (autorun). The shell-side of the Startup/Run gap;
  //     read-only forms (reg query Run, schtasks /query, Get-ScheduledTask,
  //     Copy-Item to non-Startup) are excluded by requiring a write verb + target. ---
  { re: /(?:New-ItemProperty|Set-ItemProperty)\b[^|]*CurrentVersion[\\/]+Run\b/i, why: 'registry Run-key persistence (cmdlet)' },
  { re: /(?:Copy-Item|Move-Item|Set-Content|Add-Content|Out-File|New-Item|Tee-Object|\bcp\b|\bmv\b|>>?)[^|]*(?:GetFolderPath\(\s*['"]?Startup|[\\/]Startup[\\/])/i, why: 'writes to the Startup folder (persistence)' },
  { re: /\bschtasks(?:\.exe)?\b[^|]*\/create\b/i, why: 'creates a scheduled task (persistence)' },
  { re: /\bRegister-ScheduledTask\b/i, why: 'registers a scheduled task (persistence)' },
  { re: /\bsc(?:\.exe)?\s+create\b|\bNew-Service\b/i, why: 'creates a service (persistence)' },
  // --- security disable (more) ---
  { re: /\bsc(?:\.exe)?\s+(?:stop|delete|config)\s+(?:WinDefend|Sense|MsMpSvc|WdNisSvc)\b/i, why: 'stops Microsoft Defender service' },
  { re: /\bwevtutil\s+(?:cl|clear-log)\b|\bClear-EventLog\b|\bRemove-EventLog\b/i, why: 'clears Windows event logs (anti-forensics)' },
  { re: /\bauditctl\s+-D\b|\bsystemctl\s+(?:stop|disable|mask)\s+(?:auditd|rsyslog|syslog)\b/i, why: 'disables host audit/logging' },
  { re: /\bbcdedit\b[^|]*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)/i, why: 'disables Windows recovery (ransomware)' },
  // --- obfuscated/hidden powershell (hidden window + bypass/encoded together) ---
  { re: /\bpowershell(?:\.exe)?\b(?=[^|]*-w(?:indowstyle)?\s+hidden\b)(?=[^|]*(?:-(?:ep|executionpolicy)\s+bypass\b|-e(?:c|nc|ncodedcommand)?\s))/i, why: 'hidden + bypass/encoded powershell (obfuscation)' },
  // --- container escape (more) ---
  { re: /\bdocker\s+run\b[^|]*-v\s+\/var\/run\/docker\.sock/i, why: 'mounts the docker socket (escape)' },
  { re: /\bdocker\s+run\b(?=[^|]*--pid[= ]host\b)(?=[^|]*--privileged\b)/i, why: 'privileged host-pid container (escape)' },
  // --- destructive (more). Drive-root / system targets only; `Remove-Item
  //     node_modules`, `find /tmp -delete`, `> /dev/null` stay clean. ---
  { re: /\brm\b(?=[^|]*--recursive\b)(?=[^|]*--force\b)[^|]*(?:\s[/~](?:\s|$)|--no-preserve-root|["'\s]\$\{?HOME\b)/i, why: 'recursive force-delete (long flags) of root/home' },
  { re: /\bfind\s+\/\s+[^|]*-delete\b/i, why: 'find / -delete (mass deletion)' },
  { re: />\s*\/dev\/(?:sd|nvme|hd|disk|vd)[a-z]*\d*\b/i, why: 'overwrites a raw block device' },
  { re: /\bshred\b\s+(?:-\S+\s+)*[\\/](?:etc|boot|dev|var|usr|home|root)\b/i, why: 'shreds a system file' },
  { re: /\bcipher\b[^|]*\/w:/i, why: 'cipher secure-wipe' },
  { re: /\bRemove-Item\b(?=[^|]*-Recurse\b)(?=[^|]*-Force\b)[^|]*[A-Za-z]:\\(?:[\s"']|$|Windows|Program|Users\b)/i, why: 'recursive force-delete of a Windows drive/system root' },
  { re: /\bFormat-Volume\b|\bformat\s+[A-Za-z]:\s/i, why: 'formats a volume' },
];
export const RED_SHELL = [
  { re: /\bsudo\b/i, why: 'privilege escalation' },
  { re: /(?<![-\w])rm\s+\S/i, why: 'file deletion' },
  { re: /\bgit\s+push\b/i, why: 'outward-facing: pushes code' },
  { re: /\b(npm|pnpm|yarn|pip|apt|brew|choco)\s+(i|install|add)\b/i, why: 'installs packages (supply-chain)' },
  { re: /\b(?:npx|pnpm\s+dlx|yarn\s+dlx|bunx|uvx|pipx\s+run)\b/i, why: 'runs an arbitrary remote package (npx/uvx)' },
  { re: /\b(kill|pkill|taskkill)\b/i, why: 'kills processes' },
  { re: /\b(systemctl|service)\s+(stop|disable|mask)\b/i, why: 'disables services' },
  { re: /\b(?:kubectl\s+delete|terraform\s+destroy|aws\s+s3\s+rm\b[^|]*--recursive|docker\s+(?:rm|rmi)\s+-f|helm\s+(?:delete|uninstall))\b/i, why: 'destructive infrastructure operation' },
  { re: /\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b/i, why: 'destructive database operation' },
  { re: /\b(?:scp|rsync)\b[^|]*\S+@\S+:/i, why: 'remote file transfer' },
  { re: /\bdocker\s+run\b[^|]*--(?:privileged|pid[= ]host|net[= ]host|cap-add[= ]?SYS_ADMIN)/i, why: 'privileged / host-namespace container' },
  { re: /\bmount\b\s+\/dev\//i, why: 'mounts a block device' },
  { re: /\bnet\s+user\b[^|]*\/add/i, why: 'creates a user account' },
  { re: /\bInvoke-WmiMethod\b/i, why: 'WMI method invocation' },
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

  // Run the shell ruleset for shell tools AND for any non-write tool that carries
  // a command/cmd field — so a poisoned tool that declares `read` but ships a
  // shell command can't slip past (tool-name spoofing). Write content is data,
  // handled separately, so it's excluded.
  const cmdField = input.command ?? input.cmd;
  if (SHELL.includes(tool) || (cmdField != null && !WRITE.includes(tool))) {
    // non-string command must NOT coerce to "[object Object]"/"rm,-rf,/" (silent
    // green bypass). Join argv arrays so a split command is visible; stringify
    // other shapes so nested dangerous strings stay visible.
    let cmd = typeof cmdField === 'string' ? cmdField
      : Array.isArray(cmdField) ? cmdField.map(String).join(' ')
      : safeStringify(input);
    // defeat fullwidth/homoglyph evasion (NFKC maps ＲＭ → RM, etc.)
    cmd = cmd.normalize('NFKC');
    if (cmd.length > 16384) { why.push('⚠ oversized command (' + cmd.length + 'B) — gated for review'); return { tier: TIER.RED, why }; }
    if (!SHELL.includes(tool)) why.push('⚠ shell-command field on a non-shell tool (' + (tool || 'unknown') + ')');
    for (const p of BLACK_SHELL) if (p.re.test(cmd)) { tier = worst(tier, TIER.BLACK); why.push('☠ ' + p.why); }
    for (const p of RED_SHELL) if (p.re.test(cmd)) { tier = worst(tier, TIER.RED); why.push('⚠ ' + p.why); }
    for (const p of YELLOW_SHELL) if (p.re.test(cmd)) { tier = worst(tier, TIER.YELLOW); why.push('· ' + p.why); }
    if (tier === TIER.GREEN) why.push(SHELL.includes(tool) ? '· read-only shell' : '· command field — read-only');
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
