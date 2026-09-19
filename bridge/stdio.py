"""Local stdio entry point for MCP clients and package registries.

Remote HTTP deployments use bridge.__main__ and OAuth.  This module deliberately
switches the guard into local-stdio mode only in this process.
"""
from __future__ import annotations

import os
from pathlib import Path


def _bootstrap_workspace() -> None:
    root = os.environ.get("SCOPERAIL_WORKSPACE_ROOT") or os.environ.get("CLB_WORKSPACE_ROOT")
    if not root:
        return
    from . import policy

    path = Path(root).expanduser().resolve()
    name = os.environ.get("SCOPERAIL_WORKSPACE_NAME") or os.environ.get("CLB_WORKSPACE_NAME") or path.name or "workspace"
    # The registry bootstrap is intentionally least-privilege: sandboxed, network off.
    # trusted-host and desktop capabilities require an explicit local CLI action.
    policy.workspace_add(str(path), name, ["sandboxed"], network="off", days=None, notes="stdio bootstrap")


def main() -> None:
    _bootstrap_workspace()
    from . import server as server_module

    server_module.LOCAL_STDIO = True
    server_module.server.run("stdio")


if __name__ == "__main__":
    main()
