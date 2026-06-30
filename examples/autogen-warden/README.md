# Example: governing a Microsoft AutoGen agent with warden

Put a real **Microsoft AutoGen** agent (the `autogen_agentchat.AssistantAgent`
v0.4+ runtime — the genuine agent loop that executes a model's tool calls) under
warden's firewall by routing its MCP tool calls through **`warden-mcp`**. Every
tool the agent calls is risk-classified, policy-checked, injection/exfil-
screened, and written to a tamper-evident audit — and poisoned tools are
stripped before the agent ever loads them. No changes to AutoGen; no changes to
the tool server.

```
AutoGen AssistantAgent ──▶ McpWorkbench (stdio) ──▶ warden-mcp ──▶ your MCP server
     the agent loop          AutoGen's MCP client      the firewall      the tools
```

AutoGen speaks MCP natively through its first-party `McpWorkbench` /
`StdioServerParams` (`autogen_ext.tools.mcp`), and `warden-mcp` wraps any MCP
server transparently — so the only change versus an ungoverned setup is pointing
the workbench's command at `node warden-mcp -- <server>` instead of `<server>`.
The gate is deterministic (no LLM, no network), so this whole example runs
**offline with no model API key**: AutoGen requires a `model_client`, so the
model is a small scripted `ChatCompletionClient` stub, and the genuine AutoGen
agent loop executes its tool calls through the warden gate. The thing under test
is warden's governance of the agent's tool calls, not LLM inference.

## Files

| File | What it is |
|------|------------|
| `autogen_governed_agent.py` | the AutoGen `AssistantAgent`; its tool calls go through the warden gate |
| `notes_mcp_server.py` | a small downstream MCP server: real note tools + a shell tool + **one poisoned tool** |
| `warden.config.json` | the policy warden enforces at the gate (shipped in this dir) |
| `verify_audit.mjs` | verifies warden's audit chain and proves it's tamper-evident |
| `_plumbing_check.py` | the same gate exercised with a raw MCP client, no AutoGen (layer test) |
| `evidence/` | captured stdout, `audit.jsonl`, verify output, and exact version provenance from a real run |
| `requirements.txt` | pinned `autogen-agentchat` + `autogen-ext[mcp]` versions |

## Run

```bash
pip install -r requirements.txt
# from the warden repo root, src/mcp-proxy-cli.mjs is the warden-mcp entrypoint.

export WARDEN_MCP="$(git rev-parse --show-toplevel)/src/mcp-proxy-cli.mjs"
export NOTES_SERVER="$PWD/notes_mcp_server.py"
export NOTES_WORKSPACE="$PWD/notes_workspace"
export WARDEN_POLICY="$PWD/warden.config.json"
export WARDEN_AUDIT="$PWD/audit.jsonl"          # fresh file per run (see note)

python autogen_governed_agent.py     # -> GOVERNED_AGENT_PASS
node verify_audit.mjs audit.jsonl    # -> AUDIT_TAMPER_EVIDENT_PASS
python _plumbing_check.py            # -> PLUMBING_PASS (gate only, no AutoGen)
```

### What you should see

- the agent's tool list is `['list_notes','read_note','run_command','write_note']`
  — the poisoned `exfiltrate_helper` is **stripped** by warden (`[warden] poisoned
  tool from server: exfiltrate_helper …` on stderr), so the agent never loads it.
- the benign `write_note` is **allowed** and really writes a file.
- the destructive `run_command` is **blocked**: warden returns
  `⛔ warden blocked this call (black): ☠ recursive force-delete …` as the tool's
  result, so the agent loop sees the refusal — the server never runs the command.
- `audit.jsonl` is a hash-chained audit of all three verdicts; `verify_audit.mjs`
  shows it verifies, and that altering the blocked verdict breaks the chain.

The captured output of a real run is checked in under `evidence/` (with exact
framework/library versions in `evidence/PROVENANCE.txt`) so you can see the
result without running it.

## Notes

- **Fresh audit file per run.** `warden-mcp`'s buffered audit re-roots at GENESIS
  each process; appending multiple runs to one file concatenates independent
  chains. Use a new `WARDEN_AUDIT` path per run (or the streaming
  `ChainedFileAudit` for a long-lived gate).
- **Deterministic, offline.** The model is a scripted `ChatCompletionClient`, so
  the example needs no API key and the evidence is reproducible. To govern a
  *live* model's tool choices, swap the scripted client for a real one (e.g.
  `autogen_ext.models.openai.OpenAIChatCompletionClient` with `OPENAI_API_KEY`) —
  the `AssistantAgent`, the `McpWorkbench`, and the warden gate are all
  unchanged; only the token source differs.
- **`_plumbing_check.py`, not `_plumbing_test.py`.** The `_check` suffix keeps the
  layer test out of pytest's default discovery glob, so it never runs as an
  unconfigured "test". (The repo's Node CI — `node --test` — ignores `.py` files
  entirely, so the Python files here, like the `crewai-flowdef` example, are not
  executed by CI; the checked-in `evidence/` is the proof of a real run.)
- **Cleaner on musl than CrewAI.** Unlike CrewAI (whose RAG deps `lancedb`/
  `chromadb` ship no musllinux wheels), AutoGen has no native vector-DB
  dependency, so `pip install -r requirements.txt` works on Alpine/musl with no
  shim. The downstream `notes_mcp_server.py` and the gate (`warden-mcp`) are the
  same ones the other examples use.
