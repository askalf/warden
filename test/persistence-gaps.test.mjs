// Persistence-evasion gap closure (2026-06-18). The scheduled-task / service /
// autorun rules were evadable by sibling techniques that don't use the caught
// verbs. Each test below FAILS against the pre-fix ruleset and blocks now. The
// last test guards against false positives on the read-only / edit siblings.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide } from '../src/index.mjs';

const blocks = (c) => assert.equal(decide({ tool: 'shell', input: { command: c } }).decision, 'block', `expected block: ${c}`);
const notBlack = (c) => assert.notEqual(decide({ tool: 'shell', input: { command: c } }).tier, 'black', `false positive (black): ${c}`);

test('scheduled task / job / service siblings block', () => {
  blocks('Register-ScheduledJob -Name memsync -ScriptBlock { sync }');           // PS scheduled job
  blocks('schtasks /create /tn memsync /tr c:\\x.cmd /sc minute /mo 5 /it /f');  // schtasks (existing)
  blocks('Register-ScheduledTask -TaskName memsync -Action $a -Trigger $t');     // cmdlet task (existing)
  blocks('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Evil" /v ImagePath /d c:\\m.exe /f');
  blocks('sc create Evil binPath= c:\\m.exe start= auto');                       // service (existing)
});

test('WMI permanent event-subscription persistence blocks', () => {
  blocks('Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{Name="f"}');
  blocks('New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property @{Name="c"}');
  blocks('Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{Filter=$f;Consumer=$c}');
  blocks('wmic /namespace:"\\\\root\\subscription" path __EventFilter create Name="f"');
});

test('registry autostart hijacks block', () => {
  blocks('reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Shell /d "explorer.exe,evil.exe" /f');
  blocks('Set-ItemProperty "HKLM:\\...\\Winlogon" -Name Userinit -Value "userinit.exe,evil.exe"');
  blocks('New-ItemProperty "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" -Name x -Value c:\\e.exe');
  blocks('reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" /v x /d c:\\e.exe /f');
  blocks('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" /v x /d c:\\e.exe /f');
});

test('unix cron / user-systemd siblings block', () => {
  blocks('crontab mycron.txt');
  blocks('crontab -u root /tmp/job');
  blocks('echo "* * * * * sync" | crontab -');                       // pipe form (existing)
  blocks('echo "[Service]" > ~/.config/systemd/user/eviltimer.service');
  blocks('cp evil.service ~/.config/systemd/user/');
});

test('read-only / edit siblings are NOT false-blocked', () => {
  for (const c of [
    'schtasks /query /tn memsync',
    'Get-ScheduledTask -TaskName memsync',
    'Get-ScheduledJob',
    'reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
    'Get-ItemProperty "HKLM:\\...\\Winlogon"',
    'crontab -l',
    'crontab -e',
    'crontab -r',
    'systemctl status memsync',
    'Get-WmiObject -Class __EventFilter',
  ]) notBlack(c);
});

// Persistence-path FALSE-POSITIVE fix (2026-06-22). The write-to-location rules
// (Startup / authorized_keys / .config/systemd/user / rc-profile / /etc) used
// `[^|]*` after the verb, which (1) treated an fd-redirect like `2>&1` /
// `2>/dev/null` as the write `>`, and (2) spanned `;`/`&&` so a `>` in one
// command associated with a persistence PATH merely READ in another. Now the
// gap is `[^;\n]*` (one command) and the redirect alt is `(?<![0-9&])>>?`.
test('reads that merely reference a persistence path are NOT false-blocked', () => {
  for (const c of [
    // fd-redirect (2>&1 / 2>/dev/null) is not a write verb
    'find / 2>/dev/null -path "*/Startup/*"',
    'ls -la "$HOME/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/" 2>&1',
    // a `>` in one command must not bind to a path read in the next command
    'ls -la /var/log 2>&1; ls -la "$HOME/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"',
    'echo done > /tmp/log.txt; ls "$HOME/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"',
    'systemctl status sshd 2>&1; cat ~/.ssh/authorized_keys',
    'tail -f /var/log/syslog 2>&1; source ~/.bashrc',
    'cat /etc/systemd/system/sshd.service 2>/dev/null; echo ok > /tmp/x',
  ]) notBlack(c);
});

test('genuine writes to a persistence location still block', () => {
  blocks('echo "evil" >> ~/.bashrc');                                                            // stdout append
  blocks('echo x > "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\run.bat"'); // genuine `>` into Startup
  blocks('Copy-Item evil.vbs "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\u.vbs"');
  blocks('cp backdoor.service ~/.config/systemd/user/x.service');
  blocks('tee -a ~/.bashrc');
  blocks('echo "ssh-rsa AAAA attacker" >> ~/.ssh/authorized_keys');
  blocks('install -m 644 evil /etc/cron.d/job');
});
