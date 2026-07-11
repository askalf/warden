// Fuzz redstamp's deterministic classifier — the firewall that sits in the host
// agent's hot path on EVERY tool call. Its headline contract (src/index.mjs:
// "must yield a verdict, never throw into the host agent") is the invariant:
// arbitrary bytes as a tool command must never throw and must always return a
// well-formed verdict — a known tier and a known decision. A throw here crashes
// the agent; a malformed verdict breaks every integration downstream.
import { check } from '../src/index.mjs';

const TIERS = new Set(['green', 'yellow', 'red', 'black']);
const DECISIONS = new Set(['allow', 'approve', 'block']);
// A spread of tool names so the fuzzer reaches the shell, network, and
// file-write branches (RCE / destruction / exfil / SSRF regexes). Unknown tool
// names are valid too — they still must produce a well-formed verdict.
const TOOLS = ['shell', 'bash', 'exec', 'fetch', 'http', 'net', 'write', 'read', 'edit'];

export function fuzz(data) {
  const s = data.toString('utf8');
  const tool = TOOLS[data.length ? data[0] % TOOLS.length : 0];
  // Put the fuzzed bytes in every field the classifier stringifies + scans.
  const v = check({ tool, input: { command: s, url: s, path: s, content: s } });
  if (!v || !TIERS.has(v.tier) || !DECISIONS.has(v.decision) || !Array.isArray(v.why)) {
    throw new Error(`malformed verdict for tool=${tool} ${JSON.stringify(s)}: ${JSON.stringify(v)}`);
  }
}
