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
    """Canonicalise `rel` inside the workspace root. Rejects .., symlink escapes and control characters."""
    if rel is None:
        rel = "."
    if "\x00" in rel:
        raise BridgeError("invalid_argument", "path contains NUL")
    root = Path(w["root"]).resolve()
    cand = (root / rel).absolute() if not os.path.isabs(rel) else Path(rel)
    # lexical check first (before touching the filesystem), then realpath check
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
    # symlink escape: resolve the deepest existing ancestor
    probe = cand
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    real = probe.resolve()
    try:
        real.relative_to(root)
    except ValueError:
        raise BridgeError("permission_denied", f"path resolves outside workspace via symlink: {rel} -> {real}")
    if not allow_root and real == root:
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
