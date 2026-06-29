"""A CrewAI v1.15.1 FlowDefinition flow running UNDER askalf's control plane.

The Flow is the genuine `crewai.flow.flow.Flow` engine (event-driven @start /
@listen steps, typed FlowState, FlowDefinition export). Every tool it calls goes
over MCP through **warden-mcp** - askalf's deterministic firewall - so each call
is risk-classified, allow/blocked by policy, and written to a tamper-evident
hash-chained audit. Poisoned tools are stripped before the Flow ever sees them.

    CrewAI Flow  ->  mcp.ClientSession (stdio)  ->  warden-mcp (askalf gate)  ->  notes MCP server

This is the artifact behind the post "Running CrewAI FlowDefinition under
askalf's control plane": a Flow whose entire tool surface is governed, proven by
a write that is allowed, a destructive call that is blocked, and a poisoned tool
that is stripped - all recorded in warden's audit chain.

Run:
    HOME=... CREWAI_STORAGE_DIR=... \
    WARDEN_MCP=/path/to/warden/src/mcp-proxy-cli.mjs \
    NOTES_SERVER=/path/to/notes_mcp_server.py \
    python crewai_governed_flow.py
"""
from __future__ import annotations

import asyncio
import os
import sys

# Sandbox-only: let crewai 1.15.1 import on Alpine/musl (see _musl_rag_shim.py).
# No-op / unnecessary on a normal glibc host.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _musl_rag_shim  # noqa: E402
_musl_rag_shim.install()

from pydantic import BaseModel, PrivateAttr  # noqa: E402

from crewai.flow.flow import Flow, listen, start  # noqa: E402
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

WARDEN_MCP = os.environ["WARDEN_MCP"]
NOTES_SERVER = os.environ["NOTES_SERVER"]
POLICY = os.environ.get("WARDEN_POLICY", "warden.config.json")
AUDIT = os.environ.get("WARDEN_AUDIT", "audit.jsonl")
PYTHON = sys.executable


# --- the askalf governance gate, as an async context the Flow steps share ------
class GovernedTools:
    """An MCP client session pointed at warden-mcp wrapping the notes server.

    Opening this is opening the askalf control plane: every call() below is
    firewalled by warden before it reaches the downstream tool server.
    """

    def __init__(self) -> None:
        self._params = StdioServerParameters(
            command="node",
            args=[WARDEN_MCP, "--policy", POLICY, "--audit", AUDIT, "--", PYTHON, NOTES_SERVER],
            env=os.environ.copy(),
        )
        self.session: ClientSession | None = None

    async def __aenter__(self) -> "GovernedTools":
        self._client = stdio_client(self._params)
        read, write = await self._client.__aenter__()
        self.session = ClientSession(read, write)
        await self.session.__aenter__()
        await self.session.initialize()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.session.__aexit__(*exc)
        await self._client.__aexit__(*exc)

    async def list_tools(self) -> list[str]:
        res = await self.session.list_tools()
        return sorted(t.name for t in res.tools)

    async def call(self, name: str, args: dict) -> tuple[str, bool]:
        res = await self.session.call_tool(name, args)
        text = res.content[0].text if res.content else ""
        return text, bool(res.isError)


# --- the CrewAI FlowDefinition flow -------------------------------------------
class GovernanceState(BaseModel):
    tools: list[str] = []
    written: str = ""
    readback: str = ""
    blocked_reason: str = ""
    poisoned_stripped: bool = False


class GovernedNotesFlow(Flow[GovernanceState]):
    """Event-driven Flow whose every tool call is governed by warden.

    The shared GovernedTools is held in a pydantic PrivateAttr (not a model
    field) so it can be injected before kickoff without becoming required input.
    Steps are async; CrewAI's runtime awaits coroutine steps natively, so each
    @listen fires when its predecessor completes - the real CrewAI event graph.
    """

    _gov: GovernedTools = PrivateAttr()

    @start()
    async def discover(self):
        names = await self._gov.list_tools()
        self.state.tools = names
        # warden strips the poisoned exfiltrate_helper from tools/list upstream
        self.state.poisoned_stripped = "exfiltrate_helper" not in names
        return names

    @listen(discover)
    async def write_governed_note(self, _tools):
        text, is_err = await self._gov.call(
            "write_note",
            {"title": "crewai-governed", "body": "Written by a CrewAI Flow step, through the warden gate."},
        )
        self.state.written = f"{'ERROR ' if is_err else ''}{text}"
        return text

    @listen(write_governed_note)
    async def attempt_destructive_call(self, _w):
        # A Flow step asks the dangerous shell tool to wipe the filesystem.
        # warden BLOCKS it at the gate; the tool server never sees it.
        text, is_err = await self._gov.call("run_command", {"command": "rm -" + "rf /"})
        self.state.blocked_reason = text if is_err else ""
        return is_err

    @listen(attempt_destructive_call)
    async def read_back(self, _b):
        text, _ = await self._gov.call("read_note", {"title": "crewai-governed"})
        self.state.readback = text
        return text


async def run() -> GovernanceState:
    async with GovernedTools() as gov:
        flow = GovernedNotesFlow()
        flow._gov = gov
        await flow.kickoff_async()
        return flow.state


def main() -> int:
    state = asyncio.run(run())
    print("\n==== CrewAI FlowDefinition under askalf control plane ====")
    print("flow tools (after warden strip):", state.tools)
    print("poisoned tool stripped by warden:", state.poisoned_stripped)
    print("governed write:", state.written)
    print("destructive call blocked:", bool(state.blocked_reason))
    print("  block reason:", state.blocked_reason[:90])
    print("read back:", state.readback)
    ok = (
        state.poisoned_stripped
        and state.written.startswith("wrote")
        and bool(state.blocked_reason)
        and "CrewAI Flow step" in state.readback
    )
    print("\nGOVERNED_FLOW_PASS" if ok else "GOVERNED_FLOW_FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
