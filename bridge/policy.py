"""Workspaces, grants, profiles and path safety. Every tool goes through here before touching data."""
from __future__ import annotations
import hashlib, ipaddress, json, os, socket, time, uuid
from pathlib import Path
from typing import Any
from . import db
from .config import STATE_DIR, INSTALL_DIR

PROFILES = ("sandboxed", "trusted-host")
NETWORKS = ("off", "public")


class BridgeError(Exception):
    """Stable error codes surfaced to the client as isError results."""
    def __init__(self, code: str, message: str, **extra: Any):
        super().__init__(message)
        self.code, self.message, self.extra = code, message, extra

    def payload(self) -> dict:
        return {"ok": False, "error": self.code, "message": self.message, **self.extra}


# ---------- workspaces ----------
def workspace_add(root: str, name: str, profiles: list[str], network: str = "off", days: float | None = 30, notes: str = "") -> dict:
    p = Path(root).expanduser().resolve()
    if not p.is_dir():
        raise BridgeError("invalid_argument", f"workspace root is not a directory: {p}")
    if p == Path.home().resolve() or p == Path("/"):
        raise BridgeError("permission_denied", "refusing to register the home directory or / as a workspace")
    for forbidden in (STATE_DIR, INSTALL_DIR):
        f = forbidden.resolve()
        if p == f or f in p.parents:
            raise BridgeError("permission_denied", f"refusing to register {p}: inside the bridge control plane or install dir")
    for pr in profiles:
        if pr not in PROFILES:
            raise BridgeError("invalid_argument", f"unknown profile {pr}")
    if network not in NETWORKS:
        raise BridgeError("invalid_argument", f"network must be one of {NETWORKS}")
    wid = "ws_" + hashlib.sha256(str(p).encode()).hexdigest()[:10]
    exp = time.time() + days * 86400 if days else None
    db.q("INSERT OR REPLACE INTO workspaces(id,name,root,profiles,network,expires_at,revoked,created_at,notes) VALUES(?,?,?,?,?,?,0,?,?)",
         wid, name, str(p), json.dumps(profiles), network, exp, time.time(), notes)
    return workspace_get(wid)


def workspace_get(wid: str, check: bool = True) -> dict:
    r = db.one("SELECT * FROM workspaces WHERE id=?", wid)
    if not r:
        raise BridgeError("not_found", f"unknown workspace {wid}")
    w = dict(r); w["profiles"] = json.loads(w["profiles"])
    if check:
        if w["revoked"]:
            raise BridgeError("permission_denied", f"workspace {wid} is revoked")
        if w["expires_at"] and w["expires_at"] < time.time():
            raise BridgeError("permission_denied", f"workspace {wid} grant expired; renew with scoperailctl")
        if not Path(w["root"]).is_dir():
            raise BridgeError("offline", f"workspace root missing: {w['root']}")
    return w


def workspace_list(include_revoked: bool = False) -> list[dict]:
    rows = db.all_("SELECT * FROM workspaces ORDER BY created_at")
    out = []
    for r in rows:
        w = dict(r); w["profiles"] = json.loads(w["profiles"])
        if w["revoked"] and not include_revoked:
            continue
        w["active"] = not w["revoked"] and (not w["expires_at"] or w["expires_at"] > time.time())
        out.append(w)
    return out


def workspace_find(identifier: str) -> dict:
    """Find a registered workspace by opaque ID or canonical/root path without enforcing liveness."""
    if not identifier:
        raise BridgeError("invalid_argument", "workspace identifier is required")
    if identifier.startswith("ws_"):
        r = db.one("SELECT * FROM workspaces WHERE id=?", identifier)
    else:
        root = str(Path(identifier).expanduser().resolve(strict=False))
        r = db.one("SELECT * FROM workspaces WHERE root=?", root)
    if not r:
        raise BridgeError("not_found", f"unknown workspace {identifier}")
    w = dict(r)
    w["profiles"] = json.loads(w["profiles"])
    return w


def workspace_doctor(identifier: str, path: str | None = None) -> dict:
    """Return a stable, read-only diagnostic view of a registered workspace and optional path."""
    w = workspace_find(identifier)
    now = time.time()
    root = Path(w["root"])
    revoked = bool(w["revoked"])
    expired = bool(w["expires_at"] and w["expires_at"] < now)
    root_available = root.is_dir()
    active = not revoked and not expired and root_available
    state = "revoked" if revoked else "expired" if expired else "offline" if not root_available else "active"

    result = {
        "workspace": {
            "id": w["id"],
            "name": w["name"],
            "root": w["root"],
            "profiles": list(w["profiles"]),
            "network": w["network"],
            "expires_at": w["expires_at"],
            "revoked": revoked,
            "expired": expired,
            "root_available": root_available,
            "active": active,
            "state": state,
        }
    }

    if path is not None:
        if not root_available:
            result["path"] = {
                "input": path,
                "allowed": False,
                "error": "offline",
                "message": "workspace root is unavailable",
            }
        else:
            try:
                resolved = resolve_in_workspace(w, path, must_exist=False)
                result["path"] = {
                    "input": path,
                    "allowed": True,
                    "resolved": str(resolved),
                    "exists": resolved.exists() or resolved.is_symlink(),
                }
            except BridgeError as exc:
                safe_message = {
                    "permission_denied": "path rejected by workspace boundary",
                    "invalid_argument": "path is invalid for this operation",
                    "not_found": "path not found in workspace",
                }.get(exc.code, "path check failed")
                result["path"] = {
                    "input": path,
                    "allowed": False,
                    "error": exc.code,
                    "message": safe_message,
                }
    return result


def workspace_revoke(wid: str) -> None:
    db.q("UPDATE workspaces SET revoked=1 WHERE id=?", wid)


def require_profile(w: dict, profile: str) -> None:
    if profile not in PROFILES:
        raise BridgeError("invalid_argument", f"unknown profile {profile}")
    if profile not in w["profiles"]:
        raise BridgeError("permission_denied",
                          f"profile '{profile}' is not granted for workspace {w['id']}; granted: {w['profiles']}. "
                          f"The user can grant it locally with: scoperailctl workspace profiles {w['id']} --add {profile}")


# ---------- grants (publish / trusted operations) ----------
def grant_add(workspace_id: str, kind: str, params: dict, hours: float | None = 24, max_uses: int | None = None) -> dict:
    workspace_get(workspace_id, check=False)
    gid = "grant_" + uuid.uuid4().hex[:10]
    exp = time.time() + hours * 3600 if hours else None
    db.q("INSERT INTO grants(id,workspace_id,kind,params,expires_at,revoked,created_at,used,max_uses) VALUES(?,?,?,?,?,0,?,0,?)",
         gid, workspace_id, kind, json.dumps(params), exp, time.time(), max_uses)
    return grant_get(gid)


def grant_get(gid: str) -> dict:
    r = db.one("SELECT * FROM grants WHERE id=?", gid)
    if not r:
        raise BridgeError("not_found", f"unknown grant {gid}")
    g = dict(r); g["params"] = json.loads(g["params"]); return g


def grant_list(workspace_id: str | None = None) -> list[dict]:
    rows = db.all_("SELECT * FROM grants WHERE (?1 IS NULL OR workspace_id=?1) ORDER BY created_at", workspace_id)
    out = []
    for r in rows:
        g = dict(r); g["params"] = json.loads(g["params"])
        g["active"] = not g["revoked"] and (not g["expires_at"] or g["expires_at"] > time.time()) and (g["max_uses"] is None or g["used"] < g["max_uses"])
        out.append(g)
    return out


def grant_revoke(gid: str) -> None:
    db.q("UPDATE grants SET revoked=1 WHERE id=?", gid)


def grant_find(workspace_id: str, kind: str, match: dict) -> dict:
    """Return an active grant of `kind` whose params match every key in `match` (exact), else raise needs_user_action."""
    for g in grant_list(workspace_id):
        if g["kind"] != kind or not g["active"]:
            continue
        if all(g["params"].get(k) in (v, "*") for k, v in match.items()):
            return g
    raise BridgeError("needs_user_action",
                      f"no active '{kind}' grant for workspace {workspace_id} matching {match}. "
                      f"The user must approve it locally: scoperailctl grant add {workspace_id} {kind} " +
                      " ".join(f"{k}={v}" for k, v in match.items()))


def grant_use(gid: str) -> None:
    db.q("UPDATE grants SET used=used+1 WHERE id=?", gid)


# ---------- paths ----------
def resolve_in_workspace(w: dict, rel: str, must_exist: bool = True, allow_root: bool = True) -> Path:
    """Canonicalise `rel` inside the workspace root.

    This is a user-space policy check, not a kernel transaction: it rejects lexical
    traversal, ASCII/C1 control characters and symlink escapes at check time, but a
    same-user process can still race a later filesystem operation by swapping a path
    component after validation. Execution confinement is handled separately.
    """
    if rel is None:
        rel = "."
    if any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in rel):
        raise BridgeError("invalid_argument", "path contains control characters")
    root = Path(w["root"]).resolve()
    cand = (root / rel).absolute() if not os.path.isabs(rel) else Path(rel)

    # Lexical checks happen before filesystem resolution.
    try:
        cand.relative_to(root) if not os.path.isabs(rel) else None
    except ValueError:
        raise BridgeError("permission_denied", f"path escapes workspace: {rel}")
    if os.path.isabs(rel):
        try:
            Path(rel).relative_to(root)
        except ValueError:
            raise BridgeError("permission_denied", f"absolute path outside workspace: {rel}")
    if ".." in Path(rel).parts:
        raise BridgeError("permission_denied", f"'..' not allowed: {rel}")

    if must_exist and not cand.exists() and not cand.is_symlink():
        raise BridgeError("not_found", f"no such path in workspace: {rel}")

    # Resolve the deepest existing *or symlink* ancestor. Path.exists() is false for
    # broken symlinks, so stopping on is_symlink() is required to reject a proposed
    # child write through a broken link that points outside the workspace.
    probe = cand
    while not (probe.exists() or probe.is_symlink()) and probe != probe.parent:
        probe = probe.parent
    real = probe.resolve(strict=False)
    try:
        real.relative_to(root)
    except ValueError:
        raise BridgeError("permission_denied", f"path resolves outside workspace via symlink: {rel} -> {real}")
    # allow_root concerns the requested target, not the deepest existing ancestor.
    # A proposed root-level child has probe==root and must remain creatable.
    target_real = cand.resolve(strict=False)
    if not allow_root and target_real == root:
        raise BridgeError("invalid_argument", "operation not allowed on workspace root")
    return cand


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------- network policy for browser / downloads ----------
PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
    "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10", "fd7a:115c:a1e0::/48")]


def host_is_private(host: str) -> bool:
    h = host.strip("[]").lower()
    if h in ("localhost",) or h.endswith(".local") or h.endswith(".ts.net") or h.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return any(ip in n for n in PRIVATE_NETS) or ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return True  # unresolvable: treat as blocked
    for fam, _, _, _, sa in infos:
        ip = ipaddress.ip_address(sa[0])
        if any(ip in n for n in PRIVATE_NETS) or ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
    return False


def dev_port_allowed(workspace_id: str, port: int) -> bool:
    r = db.one("SELECT 1 FROM dev_ports WHERE workspace_id=? AND port=? AND (expires_at IS NULL OR expires_at>?)", workspace_id, port, time.time())
    return bool(r)
