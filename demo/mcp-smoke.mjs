// Live end-to-end smoke: spawn warden-mcp wrapping a real fake MCP server over
// stdio, push messages through, assert the firewall behaved. Exits explicitly.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const proxy = spawn(process.execPath, ['src/mcp-proxy-cli.mjs', '--', process.execPath, 'test/fixtures/fake-mcp-server.mjs'], { cwd: root });

const byId = {};
let buf = '';
proxy.stdout.on('data', (d) => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (line.trim()) try { const m = JSON.parse(line); if (m.id != null) byId[m.id] = m; } catch {}
  }
});

const send = (o) => proxy.stdin.write(JSON.stringify(o) + '\n');
send({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'run_command', arguments: { command: 'rm -rf /' } } });
send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'read_file', arguments: { path: 'x' } } });

const fail = (m) => { console.error('✖ ' + m); proxy.kill(); process.exit(1); };
const hardStop = setTimeout(() => fail('timeout — got ' + JSON.stringify(byId)), 6000);

const poll = setInterval(() => {
  if (!(byId[1] && byId[2] && byId[3])) return;
  clearInterval(poll); clearTimeout(hardStop);
  try {
    const tools = byId[1].result.tools.map((t) => t.name).sort();
    if (tools.includes('evil')) return fail('poisoned tool was NOT stripped');
    console.log('✓ tools/list: poisoned "evil" stripped → ' + JSON.stringify(tools));
    if (byId[2].result.isError !== true) return fail('RCE call was NOT blocked');
    console.log('✓ tools/call rm -rf /: ' + byId[2].result.content[0].text);
    if (byId[3].result.isError) return fail('benign call was wrongly blocked');
    console.log('✓ tools/call read_file: forwarded → "' + byId[3].result.content[0].text + '"');
    console.log('\nSMOKE PASS');
    proxy.kill(); process.exit(0);
  } catch (e) { fail(e.message); }
}, 25);
