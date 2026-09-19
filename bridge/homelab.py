"""Optional named, read-only HomeLab adapters.

Service endpoints are operator configuration, never source defaults. Credentials are
resolved through credential helpers / macOS Keychain and are never returned by tools.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path

import httpx

from .config import SECRETS_DIR, load_config
from .policy import BridgeError

CFG = load_config()
PAPERLESS_KEYCHAIN_SERVICE = "io.github.hanpuli.scoperail.homelab.paperless"
_PAPERLESS_META = SECRETS_DIR / "paperless.json"
_LEGACY_HOMELAB = SECRETS_DIR / "homelab.json"
_SECURITY = "/usr/bin/security"


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
    """Ask Git's configured credential helpers instead of parsing ~/.git-credentials."""
    url = _url("forgejo", required=False)
    if not url:
        return None
    parsed = urllib.parse.urlsplit(url)
    host = _spec("forgejo").get("credential_host") or parsed.netloc
    if not host:
        return None
    query = f"protocol={parsed.scheme or 'https'}\nhost={host}\n\n"
    try:
        env = dict(os.environ)
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GCM_INTERACTIVE"] = "Never"
        result = subprocess.run(
            ["git", "credential", "fill"],
            input=query,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    fields = dict(
        line.split("=", 1)
        for line in result.stdout.splitlines()
        if "=" in line
    )
    return fields.get("password") or None


def _paperless_metadata() -> dict:
    if not _PAPERLESS_META.exists():
        return {}
    try:
        raw = json.loads(_PAPERLESS_META.read_text())
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def _legacy_paperless_metadata() -> dict:
    if not _LEGACY_HOMELAB.exists():
        return {}
    try:
        raw = json.loads(_LEGACY_HOMELAB.read_text())
        value = raw.get("paperless") or {}
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def paperless_credential_metadata() -> dict:
    """Non-secret Keychain lookup metadata for the local management CLI."""
    meta = _paperless_metadata()
    return {k: meta[k] for k in ("mode", "account") if k in meta}


def write_paperless_metadata(mode: str, account: str) -> None:
    """Persist only non-secret Keychain lookup metadata, never the credential itself."""
    if mode not in {"token", "password"} or not account:
        raise ValueError("mode must be token/password and account must be non-empty")
    metadata = {"mode": mode, "account": account}

    _PAPERLESS_META.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=_PAPERLESS_META.name + ".", dir=str(_PAPERLESS_META.parent))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(metadata, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, _PAPERLESS_META)
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def remove_paperless_metadata() -> None:
    _PAPERLESS_META.unlink(missing_ok=True)


def _keychain_password(service: str, account: str) -> str | None:
    try:
        result = subprocess.run(
            [_SECURITY, "find-generic-password", "-a", account, "-s", service, "-w"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.rstrip("\r\n")
    return value or None


def _paperless_auth() -> tuple[str, str] | None:
    meta = _paperless_metadata()
    mode = meta.get("mode")
    account = meta.get("account")
    if mode in {"token", "password"} and isinstance(account, str) and account:
        secret = _keychain_password(PAPERLESS_KEYCHAIN_SERVICE, account)
        if secret:
            return ("__token__", secret) if mode == "token" else (account, secret)

    # Read-only compatibility for legacy operator state. New writes never use this form.
    legacy = _legacy_paperless_metadata()
    if legacy.get("token"):
        return ("__token__", legacy["token"])
    if legacy.get("user") and legacy.get("password"):
        return (legacy["user"], legacy["password"])
    return None


def _paperless_storage() -> str | None:
    meta = _paperless_metadata()
    if meta.get("mode") in {"token", "password"} and meta.get("account"):
        return "macOS Keychain"
    legacy = _legacy_paperless_metadata()
    if legacy.get("token") or legacy.get("password"):
        return "legacy clear-text file (migrate with scoperailctl homelab set-paperless)"
    return None


def _wrap(service: str, r: httpx.Response, rid: str, started: float) -> dict:
    try:
        body = r.json()
    except ValueError:
        body = r.text[:4000]
    ok = 200 <= r.status_code < 300
    return {
        "ok": ok,
        "source": "live",
        "service": service,
        "request_id": rid,
        "http_status": r.status_code,
        "url": str(r.request.url),
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
        raise BridgeError("needs_user_action", "no Forgejo credential available through the configured Git credential helper")
    rid, t0 = uuid.uuid4().hex[:12], time.time()
    try:
        r = httpx.get(
            base + path,
            params=params,
            headers={"Authorization": f"token {tok}", "Accept": "application/json"},
            timeout=20,
        )
    except httpx.HTTPError as e:
        return {
            "ok": False,
            "source": "live",
            "service": "forgejo",
            "request_id": rid,
            "error": f"offline: {e}",
            "url": base + path,
        }
    return _wrap("forgejo", r, rid, t0)


def paperless_query(path: str, params: dict | None = None) -> dict:
    """GET only against the configured Paperless-ngx API."""
    if not path.startswith("/api/") or ".." in path:
        raise BridgeError("invalid_argument", "path must start with /api/")
    base = _url("paperless")
    auth = _paperless_auth()
    if not auth:
        raise BridgeError(
            "needs_user_action",
            "Paperless credentials are not configured; run scoperailctl homelab set-paperless",
        )
    rid, t0 = uuid.uuid4().hex[:12], time.time()
    try:
        hdr = {"Accept": "application/json"}
        request_auth = auth
        if auth[0] == "__token__":
            hdr["Authorization"] = f"Token {auth[1]}"
            request_auth = None
        r = httpx.get(base + path, params=params, auth=request_auth, headers=hdr, timeout=20)
    except httpx.HTTPError as e:
        return {
            "ok": False,
            "source": "live",
            "service": "paperless",
            "request_id": rid,
            "error": f"offline: {e}",
            "url": base + path,
        }
    return _wrap("paperless", r, rid, t0)


def status() -> dict:
    forgejo_url = _url("forgejo", required=False)
    paperless_url = _url("paperless", required=False)
    return {
        "forgejo": {
            "url": forgejo_url,
            "configured": bool(forgejo_url),
            "credential_present": bool(_forgejo_token()) if forgejo_url else False,
            "credential_source": "Git credential helper" if forgejo_url else None,
        },
        "paperless": {
            "url": paperless_url,
            "configured": bool(paperless_url),
            "credential_present": bool(_paperless_auth()) if paperless_url else False,
            "credential_source": _paperless_storage(),
        },
    }
