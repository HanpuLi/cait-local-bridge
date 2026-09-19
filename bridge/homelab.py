"""Optional named, read-only HomeLab adapters.

Service endpoints are operator configuration, never source defaults.  Credentials are
read from local credential stores / bridge secrets only and are never returned.
"""
from __future__ import annotations
import json, time, uuid, urllib.parse
from pathlib import Path
import httpx
from .config import SECRETS_DIR, load_config
from .policy import BridgeError

CFG = load_config()


def _spec(name: str) -> dict:
    raw = (CFG.get("homelab") or {}).get(name) or {}
    return raw if isinstance(raw, dict) else {}


def _url(name: str, *, required: bool = True) -> str | None:
    value = _spec(name).get("url")
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        return value.rstrip("/")
    if required:
        raise BridgeError(
            "needs_user_action",
            f"HomeLab service {name!r} is not configured; add homelab.{name}.url to the bridge config",
        )
    return None


def _forgejo_token() -> str | None:
    url = _url("forgejo", required=False)
    if not url:
        return None
    host = _spec("forgejo").get("credential_host") or urllib.parse.urlsplit(url).hostname
    if not host:
        return None
    p = Path.home() / ".git-credentials"
    if not p.exists():
        return None
    for line in p.read_text(errors="replace").splitlines():
        if host in line and "://" in line:
            cred = line.split("://", 1)[1].split("@", 1)[0]
            return cred.split(":", 1)[1] if ":" in cred else cred
    return None


def _paperless_auth() -> tuple[str, str] | None:
    p = SECRETS_DIR / "homelab.json"
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text()).get("paperless") or {}
    except Exception:
        return None
    if d.get("token"):
        return ("__token__", d["token"])
    return (d["user"], d["password"]) if d.get("user") and d.get("password") else None


def _wrap(service: str, r: httpx.Response, rid: str, started: float) -> dict:
    try:
        body = r.json()
    except ValueError:
        body = r.text[:4000]
    ok = 200 <= r.status_code < 300
    return {
        "ok": ok, "source": "live", "service": service, "request_id": rid,
        "http_status": r.status_code, "url": str(r.request.url),
        "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_ms": int((time.time() - started) * 1000),
        "data": body if ok else None,
        "error": None if ok else (body if isinstance(body, str) else json.dumps(body)[:2000]),
    }


def forgejo_query(path: str, params: dict | None = None) -> dict:
    """GET only against the configured Forgejo API."""
    if not path.startswith("/api/v1/") or ".." in path:
        raise BridgeError("invalid_argument", "path must start with /api/v1/")
    base = _url("forgejo")
    tok = _forgejo_token()
    if not tok:
        raise BridgeError("needs_user_action", "no Forgejo credential available for the configured host")
    rid, t0 = uuid.uuid4().hex[:12], time.time()
    try:
        r = httpx.get(
            base + path, params=params,
            headers={"Authorization": f"token {tok}", "Accept": "application/json"},
            timeout=20,
        )
    except httpx.HTTPError as e:
        return {"ok": False, "source": "live", "service": "forgejo", "request_id": rid, "error": f"offline: {e}", "url": base + path}
    return _wrap("forgejo", r, rid, t0)


def paperless_query(path: str, params: dict | None = None) -> dict:
    """GET only against the configured Paperless-ngx API."""
    if not path.startswith("/api/") or ".." in path:
        raise BridgeError("invalid_argument", "path must start with /api/")
    base = _url("paperless")
    auth = _paperless_auth()
    if not auth:
        raise BridgeError("needs_user_action", "Paperless credentials are not configured in the bridge secret store")
    rid, t0 = uuid.uuid4().hex[:12], time.time()
    try:
        hdr = {"Accept": "application/json"}
        request_auth = auth
        if auth[0] == "__token__":
            hdr["Authorization"] = f"Token {auth[1]}"
            request_auth = None
        r = httpx.get(base + path, params=params, auth=request_auth, headers=hdr, timeout=20)
    except httpx.HTTPError as e:
        return {"ok": False, "source": "live", "service": "paperless", "request_id": rid, "error": f"offline: {e}", "url": base + path}
    return _wrap("paperless", r, rid, t0)


def status() -> dict:
    forgejo_url = _url("forgejo", required=False)
    paperless_url = _url("paperless", required=False)
    return {
        "forgejo": {
            "url": forgejo_url, "configured": bool(forgejo_url),
            "credential_present": bool(_forgejo_token()) if forgejo_url else False,
        },
        "paperless": {
            "url": paperless_url, "configured": bool(paperless_url),
            "credential_present": bool(_paperless_auth()) if paperless_url else False,
        },
    }
