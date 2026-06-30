# Example: governing a LangGraph.js StateGraph with warden

Put a real **LangGraph `StateGraph`** (the `@langchain/langgraph` engine — typed
`Annotation` state, `START`/`END` edges, node functions) under warden's firewall
by routing its MCP tool calls through **`warden-mcp`**. Every tool the graph
calls is risk-classified, policy-checked, injection/exfil-screened, and written
to a tamper-evident audit — and poisoned tools are stripped before the graph
ever loads them. No changes to LangGraph; no changes to the tool server.

```
LangGraph node ──▶ MultiServerMCPClient (stdio) ──▶ warden-mcp ──▶ your MCP server
  START/END            the MCP client                the firewall      the tools
```

LangGraph.js speaks MCP through the official **`@langchain/mcp-adapters`**
client, and `warden-mcp` wraps any MCP server transparently — so the only change
versus an ungoverned setup is pointing the client's `command` at
`node warden-mcp -- <server>` instead of `<server>`. The gate is deterministic
(no LLM, no network), so this whole example runs offline with no API key.

## Files

| File | What it is |
|------|------------|
| `langgraph_governed_graph.mjs` | the LangGraph StateGraph; its 4 nodes call tools through the warden gate |
| `notes_mcp_server.mjs` | a small downstream MCP server: real note tools + a shell tool + **one poisoned tool** |
| `warden.config.json` | the policy warden enforces at the gate |
| `verify_audit.mjs` | verifies warden's audit chain and proves it's tamper-evident |
| `_plumbing_test.mjs` | the same gate exercised with a raw MCP client, no LangGraph (layer test) |
| `evidence/` | captured stdout, `audit.jsonl`, verify output, and exact version provenance from a real run |
| `package.json` | pinned LangGraph + MCP adapter + MCP SDK versions |

## Run

```bash
npm install
# from the warden repo root, src/mcp-proxy-cli.mjs is the warden-mcp entrypoint.

export WARDEN_MCP="$(git rev-parse --show-toplevel)/src/mcp-proxy-cli.mjs"
export NOTES_SERVER="$PWD/notes_mcp_server.mjs"
export NOTES_WORKSPACE="$PWD/notes_workspace"
export WARDEN_POLICY="$PWD/warden.config.json"
export WARDEN_AUDIT="$PWD/audit.jsonl"          # fresh file per run (see note)

node langgraph_governed_graph.mjs        # -> GOVERNED_GRAPH_PASS
node verify_audit.mjs audit.jsonl        # -> AUDIT_TAMPER_EVIDENT_PASS
node _plumbing_test.mjs                   # -> PLUMBING_PASS (gate only, no LangGraph)
```

### What you should see

- the graph's tool list is `['list_notes','read_note','run_command','write_note']`
  — the poisoned `exfiltrate_helper` is **stripped** by warden (`[warden] poisoned
  tool from server: exfiltrate_helper …` on stderr), so the graph never loads it.
- the benign `write_note` is **allowed** and really writes a file.
- the destructive `run_command` is **blocked**: the adapter surfaces warden's
  `⛔ warden blocked this call (black): ☠ recursive force-delete …` as a thrown
  `ToolException`, so the node catches it — the server never runs the command.
- `audit.jsonl` is a hash-chained audit of all three verdicts; `verify_audit.mjs`
  shows it verifies, and that altering the blocked verdict breaks the chain.

The captured output of a real run is checked in under `evidence/` (with exact
framework/adapter/SDK versions in `evidence/PROVENANCE.txt`) so you can see the
result without running it.

## Notes

- **Fresh audit file per run.** `warden-mcp`'s buffered audit re-roots at GENESIS
  each process; appending multiple runs to one file concatenates independent
  chains. Use a new `WARDEN_AUDIT` path per run (or the streaming
  `ChainedFileAudit` for a long-lived gate).
- **Deterministic, offline.** This example governs the graph's *tool surface*
  with fixed nodes — no model call, so it needs no API key and the evidence is
  reproducible. To govern an LLM's *tool choices*, bind these same MCP-loaded
  tools to a chat model in a graph node (e.g. `model.bindTools(await
  client.getTools())`) — same gate, now in front of the model's decisions.
- **Node-only, no Python.** This is the JS sibling of the `crewai-flowdef`
  example. It was built and its `evidence/` captured on an Alpine/musl host
  (Node 24) with no Python toolchain, which is why the framework here is
  LangGraph.js and the downstream server is `notes_mcp_server.mjs` rather than
  the CrewAI example's `.py`. Everything is pure JS — `npm install` is the only
  setup, and the gate (`warden-mcp`) is the same one the CrewAI example uses.
