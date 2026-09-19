"""Installable command line interface for the public package."""
from __future__ import annotations

import argparse
import json
import time
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


def _workspace_doctor(args: argparse.Namespace) -> None:
    from . import policy

    try:
        result = policy.workspace_doctor(args.workspace, args.path)
    except policy.BridgeError as exc:
        if args.json:
            print(json.dumps(exc.payload(), indent=2))
        else:
            print(f"{exc.code}: {exc.message}")
        raise SystemExit(2) from None
    if args.json:
        print(json.dumps(result, indent=2))
        return

    w = result["workspace"]
    expires = "never" if w["expires_at"] is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(w["expires_at"]))
    print(f"workspace {w['id']} ({w['name']})")
    print(f"  state: {w['state']}  active={'yes' if w['active'] else 'no'}  root_available={'yes' if w['root_available'] else 'no'}")
    print(f"  root: {w['root']}")
    print(f"  profiles: {', '.join(w['profiles']) or '(none)'}")
    print(f"  network: {w['network']}  expires: {expires}")
    if "path" in result:
        p = result["path"]
        if p["allowed"]:
            suffix = "exists" if p["exists"] else "new path"
            print(f"  path: allowed ({suffix}) -> {p['resolved']}")
        else:
            print(f"  path: rejected [{p['error']}] {p['message']}")


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
        prog="scoperail",
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

    workspace = sub.add_parser("workspace", help="workspace diagnostics")
    workspace_sub = workspace.add_subparsers(dest="workspace_command", required=True)
    doctor = workspace_sub.add_parser("doctor", help="diagnose a registered workspace and optional path")
    doctor.add_argument("workspace", help="workspace ID or registered root path")
    doctor.add_argument("--path", help="workspace-relative path to check without mutating it")
    doctor.add_argument("--json", action="store_true", help="print the stable machine-readable result")
    doctor.set_defaults(func=_workspace_doctor)

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
