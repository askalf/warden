// A LangGraph.js StateGraph running UNDER askalf's control plane.
//
// The graph is the genuine `@langchain/langgraph` StateGraph engine (typed
// Annotation state, START/END edges, node functions wired by addEdge). Its
// tools come from `@langchain/mcp-adapters` — the official LangChain MCP client
// — pointed not at the notes server directly but at **warden-mcp**, askalf's
// deterministic firewall. So every tool the graph calls is risk-classified,
// allow/blocked by policy, and written to a tamper-evident hash-chained audit,
// and poisoned tools are stripped before the graph ever loads them.
//
//   LangGraph node ─▶ MultiServerMCPClient (stdio) ─▶ warden-mcp ─▶ notes MCP server
//     START/END           the MCP client               the firewall      the tools
//
// This is the artifact behind the post "Running a LangGraph StateGraph under
// askalf's control plane": a graph whose entire tool surface is governed,
// proven by a write that is allowed, a destructive call that is blocked, and a
// poisoned tool that is stripped — all recorded in warden's audit chain.
//
// Run:
//   WARDEN_MCP=/path/to/warden/src/mcp-proxy-cli.mjs \
//   NOTES_SERVER=/path/to/notes_mcp_server.mjs \
//   node langgraph_governed_graph.mjs
import { Annotation, StateGraph, START, END } from '@langchain/langgraph';
import { MultiServerMCPClient } from '@langchain/mcp-adapters';

const WARDEN_MCP = process.env.WARDEN_MCP;
const NOTES_SERVER = process.env.NOTES_SERVER;
const POLICY = process.env.WARDEN_POLICY || 'warden.config.json';
const AUDIT = process.env.WARDEN_AUDIT || 'audit.jsonl';
if (!WARDEN_MCP || !NOTES_SERVER) {
  console.error('set WARDEN_MCP and NOTES_SERVER');
  process.exit(2);
}

// --- the askalf governance gate, as a LangChain MCP client --------------------
// MultiServerMCPClient launches `node warden-mcp -- node notes_server`, so the
// graph's tools are served THROUGH the firewall. Loading the tool list here is
// already governed: warden strips the poisoned tool from tools/list, so the
// graph never even receives `exfiltrate_helper` as a callable tool.
const client = new MultiServerMCPClient({
  // Don't throw if a tool's schema fails to load — we want to observe the
  // surviving (governed) tool surface, not abort on the stripped one.
  throwOnLoadError: false,
  useStandardContentBlocks: true,
  mcpServers: {
    notes: {
      transport: 'stdio',
      command: 'node',
      args: [WARDEN_MCP, '--policy', POLICY, '--audit', AUDIT, '--', 'node', NOTES_SERVER],
      env: process.env,
    },
  },
});

const tools = await client.getTools();
const byName = new Map(tools.map((t) => [t.name, t]));
const callTool = (name, args) => {
  const t = byName.get(name);
  if (!t) throw new Error(`tool not available through the gate: ${name}`);
  return t.invoke(args);
};

// --- the LangGraph StateGraph -------------------------------------------------
const GovState = Annotation.Root({
  tools: Annotation(),            // tool names the graph can see after warden strips
  poisonedStripped: Annotation(), // true iff the poisoned tool never reached us
  written: Annotation(),          // result of the governed write_note
  blockedReason: Annotation(),    // warden's block message for the destructive call
  readback: Annotation(),         // read-back proving the write really landed
});

// node 1: discover the governed tool surface.
async function discover() {
  const names = tools.map((t) => t.name).sort();
  return { tools: names, poisonedStripped: !names.includes('exfiltrate_helper') };
}

// node 2: a benign write — allowed by warden, really writes a file.
async function writeGovernedNote() {
  const text = await callTool('write_note', {
    title: 'langgraph-governed',
    body: 'Written by a LangGraph StateGraph node, through the warden gate.',
  });
  return { written: String(text) };
}

// node 3: a graph node asks the shell tool to wipe the filesystem. warden BLOCKS
// it at the gate; the adapter surfaces the blocked (isError) result as a thrown
// ToolException — that caught error IS the proof the call never reached the tool.
async function attemptDestructiveCall() {
  try {
    await callTool('run_command', { command: 'rm -' + 'rf /' });
    return { blockedReason: '' }; // reached the tool — governance FAILED
  } catch (err) {
    return { blockedReason: String(err?.message || err) };
  }
}

// node 4: read the note back, proving the allowed write really landed.
async function readBack() {
  const text = await callTool('read_note', { title: 'langgraph-governed' });
  return { readback: String(text) };
}

const graph = new StateGraph(GovState)
  .addNode('discover', discover)
  .addNode('write_governed_note', writeGovernedNote)
  .addNode('attempt_destructive_call', attemptDestructiveCall)
  .addNode('read_back', readBack)
  .addEdge(START, 'discover')
  .addEdge('discover', 'write_governed_note')
  .addEdge('write_governed_note', 'attempt_destructive_call')
  .addEdge('attempt_destructive_call', 'read_back')
  .addEdge('read_back', END)
  .compile();

const state = await graph.invoke({});
await client.close();

console.log('\n==== LangGraph StateGraph under askalf control plane ====');
console.log('graph tools (after warden strip):', state.tools);
console.log('poisoned tool stripped by warden:', state.poisonedStripped);
console.log('governed write:', state.written);
console.log('destructive call blocked:', Boolean(state.blockedReason));
console.log('  block reason:', String(state.blockedReason).slice(0, 110));
console.log('read back:', state.readback);

const okPass =
  state.poisonedStripped &&
  state.written.startsWith('wrote') &&
  Boolean(state.blockedReason) &&
  state.readback.includes('LangGraph StateGraph node');
console.log('\n' + (okPass ? 'GOVERNED_GRAPH_PASS' : 'GOVERNED_GRAPH_FAIL'));
process.exit(okPass ? 0 : 1);
