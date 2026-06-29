"""Layer test: MCP client -> warden-mcp (the gate) -> notes MCP server.

No CrewAI yet - this proves the governance plumbing on its own:
  1. tools/list comes back with the poisoned `exfiltrate_helper` STRIPPED.
  2. a benign write_note call is FORWARDED and really writes a file.
  3. a malicious run_command (filesystem destruction) is BLOCKED by warden.
"""
import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

WARDEN_MCP = os.environ["WARDEN_MCP"]          # path to warden src/mcp-proxy-cli.mjs
SERVER = os.environ["NOTES_SERVER"]            # path to notes_mcp_server.py
PYTHON = sys.executable
POLICY = os.environ.get("WARDEN_POLICY", "warden.config.json")
AUDIT = os.environ.get("WARDEN_AUDIT", "audit.jsonl")


async def main() -> int:
    params = StdioServerParameters(
        command="node",
        args=[WARDEN_MCP, "--policy", POLICY, "--audit", AUDIT, "--", PYTHON, SERVER],
        env=os.environ.copy(),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            print("tools/list (via gate):", names)
            assert "exfiltrate_helper" not in names, "poisoned tool was NOT stripped!"
            print("  -> poisoned tool stripped:", "exfiltrate_helper" not in names)

            r = await session.call_tool("write_note", {"title": "governed", "body": "hello from a governed CrewAI tool call"})
            print("write_note ->", r.content[0].text, "| isError:", r.isError)
            assert not r.isError, "benign write was wrongly blocked"

            bad = await session.call_tool("run_command", {"command": "rm -" + "rf /"})
            print("run_command(destroy) ->", bad.content[0].text[:80], "| isError:", bad.isError)
            assert bad.isError, "malicious command was NOT blocked"

            print("PLUMBING_PASS")
            return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
