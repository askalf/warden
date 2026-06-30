# Example: governing an OpenAI Agents SDK agent with warden

Put a real **OpenAI Agents SDK** agent (the `@openai/agents` runtime — an
`Agent` run by the SDK's `Runner`, the genuine tool-execution loop) under
warden's firewall by routing its MCP tool calls through **`warden-mcp`**. Every
tool the agent calls is risk-classified, policy-checked, injection/exfil-
screened, and written to a tamper-evident audit — and poisoned tools are
stripped before the agent ever loads them. No changes to the Agents SDK; no
changes to the tool server.

```
Agents SDK Runner ──▶ MCPServerStdio (stdio) ──▶ warden-mcp ──▶ your MCP server
   the tool loop          the SDK's MCP client       the firewall      the tools
```

The OpenAI Agents SDK speaks MCP natively through its built-in `MCPServerStdio`,
and `warden-mcp` wraps any MCP server transparently — so the only change versus
an ungoverned setup is pointing the server's `fullCommand` at
`node warden-mcp -- <server>` instead of `<server>`. The gate is deterministic
(no LLM, no network), so this whole example runs **offline with no OpenAI API
key**: the model is a small scripted stub injected via a custom `ModelProvider`,
and the genuine Agents-SDK `Runner` executes its tool calls through the warden
gate. The thing under test is warden's governance of the agent's tool calls, not
OpenAI inference.

## Files

| File | What it is |
|------|------------|
| `agent_governed_flow.mjs` | the OpenAI Agents SDK agent; its tool calls go through the warden gate |
| `notes_mcp_server.mjs` | a small downstream MCP server: real note tools + a shell tool + **one poisoned tool** |
| `warden.config.json` | the policy warden enforces at the gate (shipped in this dir) |
| `verify_audit.mjs` | verifies warden's audit chain and proves it's tamper-evident |
| `_plumbing_check.mjs` | the same gate exercised with a raw MCP client, no Agents SDK (layer test) |
| `evidence/` | captured stdout, `audit.jsonl`, verify output, and exact version provenance from a real run |
| `package.json` | pinned Agents SDK + MCP SDK + zod versions |

## Run

```bash
npm install
# from the warden repo root, src/mcp-proxy-cli.mjs is the warden-mcp entrypoint.

export WARDEN_MCP="$(git rev-parse --show-toplevel)/src/mcp-proxy-cli.mjs"
export NOTES_SERVER="$PWD/notes_mcp_server.mjs"
export NOTES_WORKSPACE="$PWD/notes_workspace"
export WARDEN_POLICY="$PWD/warden.config.json"
export WARDEN_AUDIT="$PWD/audit.jsonl"          # fresh file per run (see note)

node agent_governed_flow.mjs        # -> GOVERNED_AGENT_PASS
node verify_audit.mjs audit.jsonl   # -> AUDIT_TAMPER_EVIDENT_PASS
node _plumbing_check.mjs            # -> PLUMBING_PASS (gate only, no Agents SDK)
```

### What you should see

- the agent's tool list is `['list_notes','read_note','run_command','write_note']`
  — the poisoned `exfiltrate_helper` is **stripped** by warden (`[warden] poisoned
  tool from server: exfiltrate_helper …` on stderr), so the agent never loads it.
- the benign `write_note` is **allowed** and really writes a file.
- the destructive `run_command` is **blocked**: warden returns
  `⛔ warden blocked this call (black): ☠ recursive force-delete …` as the tool's
  result, so the agent's Runner sees the refusal — the server never runs the
  command.
- `audit.jsonl` is a hash-chained audit of all three verdicts; `verify_audit.mjs`
  shows it verifies, and that altering the blocked verdict breaks the chain.

The captured output of a real run is checked in under `evidence/` (with exact
framework/SDK versions in `evidence/PROVENANCE.txt`) so you can see the result
without running it.

## Notes

- **Fresh audit file per run.** `warden-mcp`'s buffered audit re-roots at GENESIS
  each process; appending multiple runs to one file concatenates independent
  chains. Use a new `WARDEN_AUDIT` path per run (or the streaming
  `ChainedFileAudit` for a long-lived gate).
- **Deterministic, offline.** The model is a scripted stub, so the example needs
  no API key and the evidence is reproducible. To govern a *live* model's tool
  choices, drop the stub `modelProvider` and let the SDK use a real OpenAI model
  (`OPENAI_API_KEY` in the environment) — the agent, the `MCPServerStdio`, and
  the warden gate are all unchanged; only the token source differs.
- **`_plumbing_check.mjs`, not `_plumbing_test.mjs`.** The repo's root
  `npm test` runs `node --test`, which auto-discovers any `*_test.mjs` /
  `*.test.mjs` file and would try to run it at the repo root — where this
  example's deps aren't installed. The `_check` suffix keeps the layer test out
  of that glob, so the root test suite stays green.
- **Node-only, no Python.** This is a JS sibling of the `crewai-flowdef` example.
  The downstream server is the same `notes_mcp_server.mjs` the LangGraph example
  uses, and the gate (`warden-mcp`) is the same one all the examples use.
