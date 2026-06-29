# Example: governing a CrewAI v1.15 Flow with warden

Put a real **CrewAI `Flow`** (the FlowDefinition engine — `@start`/`@listen`
steps, typed state) under warden's firewall by routing its MCP tool calls through
**`warden-mcp`**. Every tool the Flow calls is risk-classified, policy-checked,
injection/exfil-screened, and written to a tamper-evident audit — and poisoned
tools are stripped before the Flow ever sees them. No changes to CrewAI; no
changes to the tool server.

```
CrewAI Flow ──▶ mcp.ClientSession (stdio) ──▶ warden-mcp ──▶ your MCP server
 @start/@listen        the MCP client          the firewall     the tools
```

CrewAI v1.15 speaks MCP natively (`mcp` is a core dependency), and `warden-mcp`
wraps any MCP server transparently — so the only change versus an ungoverned
setup is pointing the Flow's MCP client at `warden-mcp -- <server>` instead of
`<server>`.

## Files

| File | What it is |
|------|------------|
| `crewai_governed_flow.py` | the CrewAI Flow; its 4 steps call tools through the warden gate |
| `notes_mcp_server.py` | a small downstream MCP server: real note tools + a shell tool + **one poisoned tool** |
| `warden.config.json` | the policy warden enforces at the gate |
| `dump_flow_definition.py` | prints the serializable `FlowDefinition` contract for the Flow |
| `verify_audit.mjs` | verifies warden's audit chain and proves it's tamper-evident |
| `_plumbing_test.py` | the same gate exercised without CrewAI (layer test) |
| `_musl_rag_shim.py` | optional; only needed on Alpine/musl (no-op on glibc) |
| `requirements.txt` | `crewai==1.15.1` |

## Run

```bash
pip install -r requirements.txt           # glibc: done. (musl: see the note below)
# from the warden repo root, build/link warden so src/mcp-proxy-cli.mjs is present.

export WARDEN_MCP="$(git rev-parse --show-toplevel)/src/mcp-proxy-cli.mjs"
export NOTES_SERVER="$PWD/notes_mcp_server.py"
export NOTES_WORKSPACE="$PWD/notes_workspace"
export WARDEN_POLICY="$PWD/warden.config.json"
export WARDEN_AUDIT="$PWD/flow_audit.jsonl"      # fresh file per run (see note)

python crewai_governed_flow.py            # -> GOVERNED_FLOW_PASS
node verify_audit.mjs flow_audit.jsonl    # -> AUDIT_TAMPER_EVIDENT_PASS
python dump_flow_definition.py            # -> the FlowDefinition (schema_: crewai.flow/v1)
```

### What you should see

- `discover` lists `['list_notes','read_note','run_command','write_note']` — the
  poisoned `exfiltrate_helper` is **stripped** by warden (`[warden] poisoned tool
  from server: exfiltrate_helper …` on stderr).
- the benign `write_note` is **allowed** and really writes a file.
- the destructive `run_command` is **blocked**: `⛔ warden blocked this call
  (black): ☠ recursive force-delete …` — the server never runs it.
- `flow_audit.jsonl` is a hash-chained audit of all three verdicts;
  `verify_audit.mjs` shows it verifies, and that altering the blocked verdict
  breaks the chain.

## Notes

- **Fresh audit file per run.** `warden-mcp`'s buffered audit re-roots at GENESIS
  each process; appending multiple runs to one file concatenates independent
  chains. Use a new `WARDEN_AUDIT` path per run (or the streaming
  `ChainedFileAudit` for a long-lived gate).
- **musl hosts (Alpine).** `pip install crewai` is blocked because `lancedb`/
  `chromadb` (CrewAI's vector-memory RAG deps, which a Flow doesn't use) ship no
  musllinux wheels. `_musl_rag_shim.py` stubs only that unused subtree so the
  genuine Flow engine imports. On glibc the shim is a no-op — delete it.
- **Next step (LLM-driven).** This example governs a Flow's tool surface with
  deterministic steps. To govern an LLM's *tool choices*, put a CrewAI `Agent`
  in a Flow step and supply its tools via `crewai-tools`' `MCPServerAdapter`
  pointed at `warden-mcp` — same gate, now in front of the model.
