# Integrating redstamp into a fleet

Three surfaces, depending on how an agent runs. Until `@askalf/redstamp` is published, depend on it with a path: `"@askalf/redstamp": "file:../redstamp"` (swap to a version on publish).

## 1. Claude Code (operator sessions, hands in Claude-Login mode, dock) — DONE
Register the PreToolUse hook in `~/.claude/settings.json` (a new group beside any existing hooks):
```json
{ "matcher": "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read|WebFetch|WebSearch|Grep|Glob",
  "hooks": [ { "type": "command", "command": "node /path/to/redstamp/src/cc-hook.mjs", "timeout": 15 } ] }
```
Policy: `~/.redstamp/config.json`. Audit: `~/.redstamp/audit.jsonl`. Posture: deny-black / defer-rest / ask-red-if-`strict`. Fail-open.

## 2. Any executor (agent's task runner, custom loops) — `guardExecutor`
Wrap the native executor in one line:
```js
import { guardExecutor, WardenBlocked } from '@askalf/redstamp/wrap';
import { loadPolicy, AuditLog } from '@askalf/redstamp';

const audit = new AuditLog();
const safeShell = guardExecutor(runShellCommand, {
  toAction: (cmd) => ({ tool: 'shell', input: { command: cmd } }),
  policy: loadPolicy('redstamp.config.json'),
  audit,
  onApprove: async (action, v) => askOperator(action, v), // omit -> fail-closed
});
await safeShell('rm -rf /');   // throws WardenBlocked (black)
```
**`agent` specifically:** it exports `validateInput` from `security.js`. Either wrap the exec path with `guardExecutor`, or call `check(action, policy)` inside `validateInput` and reject on `decision === 'block'`.

## 3. Anthropic-SDK tool loops (hands SDK mode, the platform forge) — `guardToolUse`
Before dispatching each `tool_use` block from the model:
```js
import { guardToolUse } from '@askalf/redstamp/wrap';

for (const block of response.content) {
  if (block.type !== 'tool_use') continue;
  const v = guardToolUse(block, policy, { audit });
  if (v.decision === 'block') { toolResults.push({ type: 'tool_result', tool_use_id: block.id, is_error: true, content: v.why.join('; ') }); continue; }
  if (v.decision === 'approve' && !(await askOperator(block, v))) { /* held */ continue; }
  // ...execute the tool normally...
}
```

## 4. MCP servers (any MCP-based agent) — the stdio proxy
No code change — wrap the server:
```bash
redstamp-mcp --policy redstamp.config.json -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

---
Part of **[Own Your Stack](https://github.com/askalf)**.
