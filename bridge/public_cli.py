"""Installable command line interface for the public package."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__


def _workspace(args: argparse.Namespace) -> None:
    from . import policy

    root = Path(args.path).expanduser().resolve()
    profiles = ["sandboxed", "trusted-host"] if args.trusted_host else ["sandboxed"]
    w = policy.workspace_add(str(root), args.name or root.name, profiles, network=args.network, days=None, notes="public CLI")
    if args.desktop:
        policy.grant_add(w["id"], "desktop", {"screen": "*"}, hours=None, max_uses=None)
    print(json.dumps({"workspace_id": w["id"], "root": w["root"], "profiles": w["profiles"], "network": w["network"],
                      "desktop_granted": bool(args.desktop)}, indent=2))


def _grant(args: argparse.Namespace) -> None:
    from . import policy

    params = {}
    for item in args.param:
        if "=" not in item:
            raise SystemExit(f"grant parameter must be key=value: {item}")
        key, value = item.split("=", 1)
        params[key] = value
    g = policy.grant_add(args.workspace_id, args.kind, params, hours=args.hours, max_uses=args.max_uses)
    print(json.dumps({"grant_id": g["id"], "workspace_id": g["workspace_id"], "kind": g["kind"],
                      "params": g["params"], "expires_at": g["expires_at"], "max_uses": g["max_uses"]}, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cait-local-bridge",
        description="Local-first MCP execution bridge for files, processes, browsers and native macOS UI.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    stdio = sub.add_parser("stdio", help="run the MCP server over local stdio")
    stdio.set_defaults(func=lambda _a: __import__("bridge.stdio", fromlist=["main"]).main())

    serve = sub.add_parser("serve", help="run the OAuth HTTP service and loopback admin service")
    serve.set_defaults(func=lambda _a: __import__("bridge.__main__", fromlist=["main"]).main())

    init = sub.add_parser("init", help="register a local workspace")
    init.add_argument("path")
    init.add_argument("--name")
    init.add_argument("--network", choices=["off", "public"], default="off")
    init.add_argument("--trusted-host", action="store_true",
                      help="also allow commands with the logged-in user's full host authority")
    init.add_argument("--desktop", action="store_true",
                      help="create a persistent desktop-control grant for this workspace")
    init.set_defaults(func=_workspace)

    grant = sub.add_parser("grant", help="create an explicit local capability grant")
    grant.add_argument("workspace_id")
    grant.add_argument("kind")
    grant.add_argument("param", nargs="*", help="key=value pairs bound to the grant")
    grant.add_argument("--hours", type=float, default=24)
    grant.add_argument("--max-uses", type=int)
    grant.set_defaults(func=_grant)

    args = parser.parse_args()
    if not getattr(args, "command", None):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
