// Live verification of the daemon auth token + on-disk audit chain.
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { verifyAuditFile } from '../src/audit.mjs';

const HOME = process.env.USERPROFILE || os.homedir();
const info = JSON.parse(fs.readFileSync(path.join(HOME, '.warden', 'daemon.json'), 'utf8'));

function ask(payload) {
  return new Promise((res) => {
    const s = net.connect(info.port, '127.0.0.1'); let b = '';
    const to = setTimeout(() => { s.destroy(); res('<timeout>'); }, 3000);
    s.on('connect', () => s.write(JSON.stringify(payload) + '\n'));
    s.on('data', (d) => { b += d; const i = b.indexOf('\n'); if (i >= 0) { clearTimeout(to); s.destroy(); res(b.slice(0, i)); } });
    s.on('error', () => { clearTimeout(to); res('<error>'); });
  });
}

const benign = { tool: 'read', input: { path: 'package.json' } };

const noTok = await ask({ action: benign });
const wrongTok = await ask({ action: benign, token: 'not-the-real-token' });
const rightTok = await ask({ action: benign, token: info.token });

const parse = (s) => { try { return JSON.parse(s); } catch { return s; } };
console.log('no token      →', parse(noTok));
console.log('wrong token   →', parse(wrongTok));
console.log('correct token →', (parse(rightTok) || {}).decision, '(should be allow)');

const auditPath = path.join(HOME, '.warden', 'audit.jsonl');
const v = verifyAuditFile(auditPath);
console.log('\naudit chain   →', v, fs.existsSync(auditPath) ? '' : '(no file yet)');
