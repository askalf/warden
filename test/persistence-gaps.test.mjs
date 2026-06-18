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
