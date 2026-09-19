#!/usr/bin/env python3
"""Smoke-test an installed Cait Local Bridge wheel over MCP stdio."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def probe(command: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="clb-stdio-state-") as state, tempfile.TemporaryDirectory(
        prefix="clb-stdio-workspace-"
    ) as workspace:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", str(Path.home())),
            "LANG": os.environ.get("LANG", "en_US.UTF-8"),
            "CLB_STATE_DIR": state,
            "CLB_WORKSPACE_ROOT": workspace,
            "CLB_USER_SUBJECT": "smoke-operator",
        }
        params = StdioServerParameters(command=command, env=env)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = [tool.name for tool in tools.tools]
                if "bridge_info" not in names:
                    raise RuntimeError("bridge_info is missing from the installed stdio server")
                result = await session.call_tool("bridge_info", {})
                if result.is_error:
                    raise RuntimeError("bridge_info returned an MCP error")
                return {"ok": True, "tool_count": len(names), "bridge_info": True}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--command",
        default=shutil.which("cait-local-bridge-stdio"),
        help="installed cait-local-bridge-stdio executable",
    )
    args = parser.parse_args()
    if not args.command:
        raise SystemExit("cait-local-bridge-stdio is not on PATH; pass --command")
    print(json.dumps(asyncio.run(probe(args.command)), sort_keys=True))


if __name__ == "__main__":
    main()
