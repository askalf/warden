// MCP stdio proxy — sits transparently between an MCP client and a downstream
// MCP server. Firewalls every `tools/call`, and strips poisoned tools out of
// `tools/list` responses. JSON-RPC over newline-delimited stdio.
import { spawn } from 'node:child_process';
import readline from 'node:readline';
import { check } from './index.mjs';
import { mapMcpToAction, scanMcpTools } from './mcp.mjs';

const toolError = (id, text) =>
  JSON.stringify({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], isError: true } });

/** client → server. Returns { forwardLine } to pass on, or { replyLine } to short-circuit a block. */
export function inspectClientLine(line, state, policy, opts = {}) {
  let msg;
  try { msg = JSON.parse(line); } catch { return { forwardLine: line }; }
  if (msg && msg.method && msg.id != null) state.pending[msg.id] = msg.method;
  if (msg && msg.method === 'tools/call') {
    const name = msg.params?.name;
    const args = msg.params?.arguments || {};
    const action = mapMcpToAction(name, args, opts.nameMap || {});
    const v = check(action, policy, { audit: opts.audit });
    const blocked = v.decision === 'block' || (v.decision === 'approve' && !opts.allowApprove);
    if (blocked) {
      opts.onWarn?.(`blocked ${name} (${v.tier}): ${v.why.join('; ')}`);
      const hint = v.decision === 'approve' ? ' — add an allow rule to warden.config.json to permit it.' : '';
      return { replyLine: toolError(msg.id, `⛔ warden blocked this call (${v.tier}): ${v.why.join('; ')}${hint}`) };
    }
    if (v.decision === 'approve') opts.onWarn?.(`allowed (approve-tier, --allow-approve) ${name}`);
    return { forwardLine: line };
  }
  return { forwardLine: line };
}

/** server → client. Returns { forwardLine }, possibly rewritten to strip poisoned tools. */
export function inspectServerLine(line, state, opts = {}) {
  let msg;
  try { msg = JSON.parse(line); } catch { return { forwardLine: line }; }
  const method = msg && msg.id != null ? state.pending[msg.id] : undefined;
  if (method === 'tools/list' && msg.result?.tools) {
    delete state.pending[msg.id];
    const findings = scanMcpTools(msg.result.tools);
    if (findings.length) {
      for (const f of findings) opts.onWarn?.(`poisoned tool from server: ${f.tool} (${f.flags.join(', ')})`);
      if (opts.strip !== false) {
        const bad = new Set(findings.map((f) => f.tool));
        msg.result.tools = msg.result.tools.filter((t) => !bad.has(t.name));
        return { forwardLine: JSON.stringify(msg) };
      }
    }
  } else if (method && msg.id != null) {
    delete state.pending[msg.id];
  }
  return { forwardLine: line };
}

/** Spawn the downstream server and wire the two firewalled streams together. */
export function runProxy({ command, args = [], policy = {}, audit = null, auditPath = null, allowApprove = false, strip = true, nameMap = {} }) {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'inherit'] });
  const state = { pending: {} };
  const opts = { allowApprove, strip, nameMap, audit, onWarn: (m) => process.stderr.write('[warden] ' + m + '\n') };

  readline.createInterface({ input: process.stdin }).on('line', (line) => {
    if (!line.trim()) return;
    const r = inspectClientLine(line, state, policy, opts);
    if (r.replyLine) process.stdout.write(r.replyLine + '\n');
    if (r.forwardLine) child.stdin.write(r.forwardLine + '\n');
  });
  readline.createInterface({ input: child.stdout }).on('line', (line) => {
    if (!line.trim()) return;
    process.stdout.write(inspectServerLine(line, state, opts).forwardLine + '\n');
  });

  process.stdin.on('end', () => { try { child.stdin.end(); } catch {} });
  child.on('exit', (code) => { if (audit && auditPath) try { audit.flush(auditPath); } catch {} process.exit(code ?? 0); });
}
