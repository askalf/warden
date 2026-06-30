"""A Microsoft AutoGen AssistantAgent running UNDER askalf's control plane.

The agent is the genuine `autogen_agentchat.agents.AssistantAgent`. Its tools
come from AutoGen's first-party `McpWorkbench` (autogen_ext.tools.mcp) pointed at
**warden-mcp** - askalf's deterministic firewall - wrapping a downstream notes
MCP server. So every tool the model chooses is risk-classified, allow/blocked by
policy, and written to a tamper-evident hash-chained audit. Poisoned tools are
stripped before the agent ever sees them.

    AutoGen AssistantAgent  ->  McpWorkbench (stdio)  ->  warden-mcp  ->  notes MCP server
       the agent loop          AutoGen's MCP client      askalf gate      the tools

OFFLINE / no API key: AutoGen needs a `model_client`. We supply a *scripted*
ChatCompletionClient (a deterministic stand-in for the LLM) that emits the exact
FunctionCall items a tool-using model would, so this runs in public CI with no
OpenAI key. The governance path and AutoGen's genuine tool-execution loop are
real and unmodified - only the model's token output is scripted. We do NOT claim
a live LLM is choosing the tools.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Mapping, Sequence

from autogen_core import CancellationToken, FunctionCall
from autogen_core.models import (
    ChatCompletionClient,
    CreateResult,
    LLMMessage,
    ModelInfo,
    RequestUsage,
)
from autogen_core.tools import Tool, ToolSchema
from autogen_agentchat.agents import AssistantAgent
from autogen_ext.tools.mcp import McpWorkbench, StdioServerParams

WARDEN_MCP = os.environ["WARDEN_MCP"]
NOTES_SERVER = os.environ["NOTES_SERVER"]
POLICY = os.environ.get("WARDEN_POLICY", "warden.config.json")
AUDIT = os.environ.get("WARDEN_AUDIT", "audit.jsonl")
PYTHON = sys.executable

# The destructive command a Flow step attempts; warden BLOCKS it at the gate.
# Assembled from fragments so the literal never appears in source or audit logs.
DESTRUCTIVE_CMD = "rm -" + "rf /"


class ScriptedModelClient(ChatCompletionClient):
    """A deterministic ChatCompletionClient: no network, no API key.

    It plays the role of a tool-using LLM by returning, on each `create`, the
    next pre-scripted assistant turn. A real model would *choose* these calls; we
    script them so the genuine AutoGen tool-execution loop runs offline. Each
    scripted turn is either a list[FunctionCall] (the agent will execute them
    through the workbench -> warden) or a final string.
    """

    def __init__(self, script: list[Any]) -> None:
        self._script = list(script)
        self._i = 0
        self._prompt_tokens = 0
        self._completion_tokens = 0

    async def create(
        self,
        messages: Sequence[LLMMessage],
        *,
        tools: Sequence[Tool | ToolSchema] = [],
        tool_choice: Any = "auto",
        json_output: Any = None,
        extra_create_args: Mapping[str, Any] = {},
        cancellation_token: CancellationToken | None = None,
    ) -> CreateResult:
        turn = self._script[self._i]
        self._i += 1
        usage = RequestUsage(prompt_tokens=0, completion_tokens=0)
        if isinstance(turn, str):
            return CreateResult(finish_reason="stop", content=turn, usage=usage, cached=False)
        # turn is a list of FunctionCall
        return CreateResult(finish_reason="function_calls", content=list(turn), usage=usage, cached=False)

    async def create_stream(self, *args: Any, **kwargs: Any):  # pragma: no cover - unused
        raise NotImplementedError("scripted client does not stream")

    async def close(self) -> None:
        return None

    def actual_usage(self) -> RequestUsage:
        return RequestUsage(prompt_tokens=self._prompt_tokens, completion_tokens=self._completion_tokens)

    def total_usage(self) -> RequestUsage:
        return RequestUsage(prompt_tokens=self._prompt_tokens, completion_tokens=self._completion_tokens)

    def count_tokens(self, messages: Sequence[LLMMessage], *, tools: Sequence[Tool | ToolSchema] = []) -> int:
        return 0

    def remaining_tokens(self, messages: Sequence[LLMMessage], *, tools: Sequence[Tool | ToolSchema] = []) -> int:
        return 1_000_000

    @property
    def capabilities(self) -> ModelInfo:
        return self.model_info

    @property
    def model_info(self) -> ModelInfo:
        return ModelInfo(
            vision=False,
            function_calling=True,
            json_output=False,
            family="scripted-offline",
            structured_output=False,
            multiple_system_messages=True,
        )


def fc(call_id: str, name: str, **arguments: Any) -> FunctionCall:
    return FunctionCall(id=call_id, name=name, arguments=json.dumps(arguments))


async def run() -> dict[str, Any]:
    params = StdioServerParams(
        command="node",
        args=[WARDEN_MCP, "--policy", POLICY, "--audit", AUDIT, "--", PYTHON, NOTES_SERVER],
        env={k: v for k, v in os.environ.items()},
        read_timeout_seconds=30,
    )

    result: dict[str, Any] = {
        "tools": [],
        "poisoned_stripped": False,
        "written": "",
        "blocked_reason": "",
        "readback": "",
    }

    async with McpWorkbench(server_params=params) as workbench:
        # 1) What tools does the agent SEE? warden strips the poisoned one upstream.
        listed = await workbench.list_tools()
        names = sorted(t["name"] for t in listed)
        result["tools"] = names
        result["poisoned_stripped"] = "exfiltrate_helper" not in names

        # The scripted "model": three tool-using turns, then a final reply. A real
        # tool-calling LLM would emit exactly these FunctionCalls; AutoGen's agent
        # loop executes each through the workbench -> warden gate.
        script = [
            [fc("c1", "write_note", title="autogen-governed",
                body="Written by a Microsoft AutoGen agent step, through the warden gate.")],
            [fc("c2", "run_command", command=DESTRUCTIVE_CMD)],   # warden BLOCKS this
            [fc("c3", "read_note", title="autogen-governed")],
            "Done. Wrote the note, the destructive shell call was blocked by warden, and I read the note back. TERMINATE",
        ]

        agent = AssistantAgent(
            name="governed_notes_agent",
            model_client=ScriptedModelClient(script),
            workbench=workbench,
            max_tool_iterations=5,
            reflect_on_tool_use=False,
            system_message="You manage notes using your tools. Reply TERMINATE when done.",
        )

        # Run the genuine AutoGen agent. Each tool call flows through warden.
        task = "Write a note titled 'autogen-governed', attempt a destructive shell command, then read the note back."
        chat = await agent.run(task=task)

        # Inspect the agent's tool-execution results recorded in the message stream.
        for msg in chat.messages:
            content = getattr(msg, "content", None)
            if isinstance(content, list):
                for item in content:
                    name = getattr(item, "name", None)
                    res_content = getattr(item, "content", None)
                    is_error = bool(getattr(item, "is_error", False))
                    if name == "write_note" and res_content is not None:
                        result["written"] = f"{'ERROR ' if is_error else ''}{res_content}"
                    elif name == "run_command" and res_content is not None:
                        if is_error or "blocked" in str(res_content).lower():
                            result["blocked_reason"] = str(res_content)
                    elif name == "read_note" and res_content is not None:
                        result["readback"] = str(res_content)

    return result


def main() -> int:
    state = asyncio.run(run())
    print("\n==== Microsoft AutoGen agent under askalf control plane ====")
    print("agent tools (after warden strip):", state["tools"])
    print("poisoned tool stripped by warden:", state["poisoned_stripped"])
    print("governed write:", state["written"])
    print("destructive call blocked:", bool(state["blocked_reason"]))
    print("  block reason:", state["blocked_reason"][:90])
    print("read back:", state["readback"])
    ok = (
        state["poisoned_stripped"]
        and state["written"].startswith("wrote")
        and bool(state["blocked_reason"])
        and "AutoGen agent step" in state["readback"]
    )
    print("\nGOVERNED_AGENT_PASS" if ok else "GOVERNED_AGENT_FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
