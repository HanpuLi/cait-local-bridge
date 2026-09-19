"""OAuth 2.1 authorization server (authorization code + PKCE S256, DCR, refresh, revocation) built on the
official MCP SDK's auth routes. User authentication is a local single-operator login: the passphrase set with
`scoperailctl passphrase set` (scrypt-hashed under ~/.scoperail/secrets). Tokens are opaque and stored hashed.
No third party can obtain a token without that passphrase; Funnel reachability alone never authenticates anyone."""
from __future__ import annotations
import base64, hashlib, hmac, html, json, os, secrets, time, urllib.parse
from pathlib import Path
from typing import Any
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from mcp.server.auth.provider import (AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
                                      OAuthAuthorizationServerProvider, RefreshToken, RegistrationError, TokenError)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from . import db
from .config import SECRETS_DIR, load_config

SCOPE = "bridge:tools"
USER_FILE = SECRETS_DIR / "user.json"
ALLOWED_REDIRECT_HOSTS = {"chatgpt.com", "chat.openai.com", "platform.openai.com", "openai.com", "localhost", "127.0.0.1"}


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------- operator passphrase ----------
def set_passphrase(passphrase: str, subject: str | None = None) -> None:
    cfg = load_config()
    if len(passphrase) < 12:
        raise ValueError("passphrase must be at least 12 characters")
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(passphrase.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32, maxmem=128 * 1024 * 1024)
    USER_FILE.write_text(json.dumps({"subject": subject or cfg["user_subject"], "salt": base64.b64encode(salt).decode(),
                                     "hash": base64.b64encode(dk).decode(), "n": 2**14, "r": 8, "p": 1, "set_at": time.time()}))
    os.chmod(USER_FILE, 0o600)


def passphrase_configured() -> bool:
    return USER_FILE.exists()


def verify_passphrase(passphrase: str) -> str | None:
    if not USER_FILE.exists():
        return None
    u = json.loads(USER_FILE.read_text())
    dk = hashlib.scrypt(passphrase.encode(), salt=base64.b64decode(u["salt"]), n=u["n"], r=u["r"], p=u["p"], dklen=32, maxmem=128 * 1024 * 1024)
    return u["subject"] if hmac.compare_digest(dk, base64.b64decode(u["hash"])) else None


# ---------- provider ----------
class BridgeAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, public_url: str, mcp_path: str = "/mcp"):
        self.cfg = load_config()
        self.public_url = public_url.rstrip("/")
        self.resource_url = self.public_url + mcp_path

    # --- clients (Dynamic Client Registration, RFC 7591) ---
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        r = db.one("SELECT data FROM oauth_clients WHERE client_id=?", client_id)
        return OAuthClientInformationFull.model_validate_json(r["data"]) if r else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        _prune(self.cfg)
        for uri in client_info.redirect_uris or []:
            u = urllib.parse.urlparse(str(uri))
            host = (u.hostname or "").lower()
            ok_host = host in ALLOWED_REDIRECT_HOSTS or any(host.endswith("." + h) for h in ALLOWED_REDIRECT_HOSTS)
            if u.scheme != "https" and host not in ("localhost", "127.0.0.1"):
                raise RegistrationError("invalid_redirect_uri", f"redirect_uri must be https: {uri}")
            if not ok_host:
                raise RegistrationError("invalid_redirect_uri", f"redirect host not allowed by this bridge: {host}")
        if not client_info.redirect_uris:
            raise RegistrationError("invalid_client_metadata", "redirect_uris required")
        db.q("INSERT OR REPLACE INTO oauth_clients(client_id,data,created_at) VALUES(?,?,?)",
             client_info.client_id, client_info.model_dump_json(), time.time())
        db.audit("oauth.register_client", f"client_id={client_info.client_id} name={client_info.client_name!r} redirect={[str(u) for u in client_info.redirect_uris]}")

    # --- authorization request: park it and send the user to the local login page ---
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if not passphrase_configured():
            raise AuthorizeError("server_error", "operator passphrase not configured; run `scoperailctl passphrase set` on the Mac")
        _prune(self.cfg)
        if params.resource and params.resource.rstrip("/") != self.resource_url:
            raise AuthorizeError("invalid_target", f"resource must be {self.resource_url}")
        pid = secrets.token_urlsafe(24)
        data = {"client_id": client.client_id, "client_name": client.client_name, "state": params.state,
                "scopes": params.scopes or [SCOPE], "code_challenge": params.code_challenge,
                "redirect_uri": str(params.redirect_uri), "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                "resource": params.resource, "csrf": secrets.token_urlsafe(16), "approve": None}
        db.q("INSERT INTO pending_auth(id,data,expires_at) VALUES(?,?,?)", pid, json.dumps(data), time.time() + 600)
        return f"{self.public_url}/login?p={urllib.parse.quote(pid)}"

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> AuthorizationCode | None:
        r = db.one("SELECT data, expires_at FROM auth_codes WHERE code=?", _h(authorization_code))
        if not r or r["expires_at"] < time.time():
            return None
        d = json.loads(r["data"])
        if d["client_id"] != client.client_id:
            return None
        return AuthorizationCode(code=authorization_code, **{k: v for k, v in d.items() if k != "client_id"}, client_id=client.client_id)

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        db.q("DELETE FROM auth_codes WHERE code=?", _h(authorization_code.code))  # single use
        return self._issue(client.client_id, authorization_code.subject or self.cfg["user_subject"], authorization_code.scopes,
                           authorization_code.resource or self.resource_url, family=secrets.token_hex(8))

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        r = db.one("SELECT * FROM tokens WHERE token_hash=? AND kind='refresh'", _h(refresh_token))
        if not r:
            return None
        if r["revoked"]:
            # OAuth 2.1 refresh-token rotation: a rotated token presented again means it leaked (or a retry lost the
            # response). Outside a short grace window revoke the whole family so thief and legitimate client both
            # have to log in again. Rows revoked before revoked_at existed (NULL) are left alone.
            grace = self.cfg.get("refresh_reuse_grace_seconds", 30)
            if r["family"] and r["revoked_at"] and time.time() - r["revoked_at"] >= grace:
                db.q("UPDATE tokens SET revoked=1, revoked_at=COALESCE(revoked_at, ?) WHERE family=?", time.time(), r["family"])
                db.audit("oauth.refresh_reuse", f"rotated refresh token replayed; family {r['family']} revoked client={r['client_id']}")
            return None
        if r["client_id"] != client.client_id or (r["expires_at"] and r["expires_at"] < time.time()):
            return None
        return RefreshToken(token=refresh_token, client_id=r["client_id"], scopes=json.loads(r["scopes"]),
                            expires_at=int(r["expires_at"]) if r["expires_at"] else None, resource=r["resource"], subject=r["subject"])

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        r = db.one("SELECT family FROM tokens WHERE token_hash=?", _h(refresh_token.token))
        family = r["family"] if r else secrets.token_hex(8)
        db.q("UPDATE tokens SET revoked=1, revoked_at=? WHERE token_hash=?", time.time(), _h(refresh_token.token))  # rotation
        return self._issue(client.client_id, refresh_token.subject or self.cfg["user_subject"], scopes or refresh_token.scopes,
                           refresh_token.resource or self.resource_url, family=family)

    async def load_access_token(self, token: str) -> AccessToken | None:
        r = db.one("SELECT * FROM tokens WHERE token_hash=? AND kind='access'", _h(token))
        if not r or r["revoked"] or (r["expires_at"] and r["expires_at"] < time.time()):
            return None
        return AccessToken(token=token, client_id=r["client_id"], scopes=json.loads(r["scopes"]),
                           expires_at=int(r["expires_at"]) if r["expires_at"] else None, resource=r["resource"], subject=r["subject"])

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        r = db.one("SELECT family, kind FROM tokens WHERE token_hash=?", _h(token.token))
        if r and r["family"]:
            db.q("UPDATE tokens SET revoked=1, revoked_at=COALESCE(revoked_at, ?) WHERE family=?", time.time(), r["family"])  # revoke the whole family
        else:
            db.q("UPDATE tokens SET revoked=1, revoked_at=COALESCE(revoked_at, ?) WHERE token_hash=?", time.time(), _h(token.token))
        db.audit("oauth.revoke", f"client={token.client_id}")

    async def exchange_identity_assertion(self, *a, **k):  # not enabled
        raise TokenError("unsupported_grant_type", "identity assertion not supported")

    def _issue(self, client_id: str, subject: str, scopes: list[str], resource: str, family: str) -> OAuthToken:
        now = time.time()
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        db.q("INSERT INTO tokens(token_hash,kind,client_id,subject,scopes,resource,expires_at,revoked,created_at,family) VALUES(?,?,?,?,?,?,?,0,?,?)",
             _h(access), "access", client_id, subject, json.dumps(scopes), resource, now + self.cfg["access_token_ttl"], now, family)
        db.q("INSERT INTO tokens(token_hash,kind,client_id,subject,scopes,resource,expires_at,revoked,created_at,family) VALUES(?,?,?,?,?,?,?,0,?,?)",
             _h(refresh), "refresh", client_id, subject, json.dumps(scopes), resource, now + self.cfg["refresh_token_ttl"], now, family)
        db.audit("oauth.issue", f"client={client_id} subject={subject} scopes={scopes}", subject=subject)
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=self.cfg["access_token_ttl"],
                          scope=" ".join(scopes), refresh_token=refresh)


# ---------- login / consent pages (custom routes on the same app) ----------
_PAGE = """<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ScopeRail</title><style>body{{font:16px -apple-system,system-ui,sans-serif;max-width:32em;margin:3em auto;padding:0 1em;color:#1a1a1a}}
input{{font:inherit;width:100%;padding:.5em;margin:.4em 0 1em;box-sizing:border-box}}button{{font:inherit;padding:.5em 1.2em}}
.box{{border:1px solid #ccc;padding:1em;border-radius:6px;margin:1em 0;background:#fafafa}}.err{{color:#8a2f1d}}small{{color:#666}}</style>
<h1>ScopeRail</h1>{body}"""
# The login/consent pages are the only HTML this server ever renders and they take the operator passphrase:
# never framable (clickjacking of "Allow"), never cached, no referrer leakage, inline style only.
_PAGE_HEADERS = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
                 "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


def _page(body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(_PAGE.format(body=body), status, headers=_PAGE_HEADERS)


def _client_ip(request: Request) -> str:
    """uvicorn runs with proxy_headers=True / forwarded_allow_ips=127.0.0.1, so request.client.host is already the
    right-most *untrusted* X-Forwarded-For entry as appended by tailscaled (the only proxy in front of us). Never parse
    the raw header here: a client-supplied left-most value would let an attacker choose the IP the lockout is keyed on.
    (Verified 2026-09-17 that tailscaled strips inbound X-Forwarded-For, so this is defence in depth, not a live hole.)"""
    return request.client.host if request.client else "?"


def _locked(ip: str, cfg: dict) -> bool:
    since = time.time() - cfg["login_lockout_seconds"]
    r = db.one("SELECT COUNT(*) c FROM login_attempts WHERE ip=? AND ok=0 AND ts>?", ip, since)
    if r["c"] >= cfg["login_max_attempts"]:
        return True
    # Single operator: a burst of failures spread over many source IPs is a distributed guess, not the user. Lock
    # everyone for the window (the user waits 15 min; a botnet gets nothing).
    g = db.one("SELECT COUNT(*) c FROM login_attempts WHERE ok=0 AND ts>?", since)
    return g["c"] >= cfg.get("login_global_max_attempts", 20)


def _prune(cfg: dict) -> None:
    """Unauthenticated endpoints (DCR, authorize, login) must not grow the control-plane DB without bound."""
    now = time.time()
    db.q("DELETE FROM pending_auth WHERE expires_at<?", now)
    db.q("DELETE FROM auth_codes WHERE expires_at<?", now)
    db.q("DELETE FROM login_attempts WHERE ts<?", now - max(cfg["login_lockout_seconds"], 86400))
    # A registration that never completed a login within a week was a probe or an abandoned connector.
    db.q("DELETE FROM oauth_clients WHERE created_at<? AND client_id NOT IN (SELECT DISTINCT client_id FROM tokens)", now - 7 * 86400)


def _pending(pid: str) -> dict | None:
    r = db.one("SELECT data FROM pending_auth WHERE id=? AND expires_at>?", pid, time.time())
    return json.loads(r["data"]) if r else None


def _save_pending(pid: str, d: dict) -> None:
    db.q("UPDATE pending_auth SET data=? WHERE id=?", json.dumps(d), pid)


def make_login_routes(provider: BridgeAuthProvider):
    cfg = provider.cfg

    async def login(request: Request) -> Response:
        pid = request.query_params.get("p", "")
        d = _pending(pid)
        if not d:
            return _page("<p class=err>This login link is invalid or expired. Start the connection again from ChatGPT.</p>", 400)
        ip = _client_ip(request)
        err = ""
        if request.method == "POST":
            form = await request.form()
            if _locked(ip, cfg):
                return _page("<p class=err>Too many failed attempts. Try again later.</p>", 429)
            if not hmac.compare_digest(str(form.get("csrf", "")), d["csrf"]):
                return _page("<p class=err>Form expired. Reload the page.</p>", 400)
            subject = verify_passphrase(str(form.get("passphrase", "")))
            db.q("INSERT INTO login_attempts(ts,ip,ok) VALUES(?,?,?)", time.time(), ip, 1 if subject else 0)
            if subject:
                d["approve"] = secrets.token_urlsafe(16); d["subject"] = subject
                _save_pending(pid, d)
                body = f"""<div class=box><p><b>{html.escape(d.get('client_name') or d['client_id'])}</b> asks to use this bridge as <b>{html.escape(subject)}</b>.</p>
<p>Scope: <code>{html.escape(' '.join(d['scopes']))}</code><br><small>Redirect: {html.escape(d['redirect_uri'])}</small></p>
<form method=post action="consent"><input type=hidden name=p value="{html.escape(pid)}"><input type=hidden name=approve value="{html.escape(d['approve'])}">
<button name=decision value=allow>Allow</button> <button name=decision value=deny>Deny</button></form></div>"""
                return _page(body)
            err = "<p class=err>Wrong passphrase.</p>"
        body = f"""{err}<div class=box><p><b>{html.escape(d.get('client_name') or d['client_id'])}</b> wants to connect. Enter the bridge passphrase you set on your Mac.</p>
<form method=post><input type=hidden name=csrf value="{html.escape(d['csrf'])}"><label>Passphrase<input type=password name=passphrase autofocus autocomplete=current-password></label>
<button>Sign in</button></form><p><small>Signing in issues a token only to this client. Revoke any time with <code>scoperailctl tokens revoke-all</code>.</small></p></div>"""
        return _page(body)

    async def consent(request: Request) -> Response:
        form = await request.form()
        pid = str(form.get("p", "")); d = _pending(pid)
        if not d or not d.get("approve") or not hmac.compare_digest(str(form.get("approve", "")), d["approve"]):
            return _page("<p class=err>Consent request invalid or expired.</p>", 400)
        db.q("DELETE FROM pending_auth WHERE id=?", pid)
        sep = "&" if urllib.parse.urlparse(d["redirect_uri"]).query else "?"
        if form.get("decision") != "allow":
            db.audit("oauth.consent", f"denied client={d['client_id']}", subject=d.get("subject"))
            q = urllib.parse.urlencode({"error": "access_denied", **({"state": d["state"]} if d.get("state") else {})})
            return RedirectResponse(d["redirect_uri"] + sep + q, status_code=302)
        code = secrets.token_urlsafe(32)
        rec = {"client_id": d["client_id"], "scopes": d["scopes"], "expires_at": time.time() + cfg["auth_code_ttl"],
               "code_challenge": d["code_challenge"], "redirect_uri": d["redirect_uri"],
               "redirect_uri_provided_explicitly": d["redirect_uri_provided_explicitly"],
               "resource": d.get("resource") or provider.resource_url, "subject": d.get("subject")}
        db.q("INSERT INTO auth_codes(code,data,expires_at) VALUES(?,?,?)", _h(code), json.dumps(rec), rec["expires_at"])
        db.audit("oauth.consent", f"allowed client={d['client_id']}", subject=d.get("subject"))
        q = urllib.parse.urlencode({"code": code, **({"state": d["state"]} if d.get("state") else {})})
        return RedirectResponse(d["redirect_uri"] + sep + q, status_code=302)

    return login, consent


def revoke_all_tokens() -> int:
    n = db.one("SELECT COUNT(*) c FROM tokens WHERE revoked=0")["c"]
    db.q("UPDATE tokens SET revoked=1, revoked_at=COALESCE(revoked_at, ?)", time.time())
    db.q("DELETE FROM pending_auth"); db.q("DELETE FROM auth_codes")
    db.audit("oauth.revoke_all", f"revoked {n} tokens")
    return n
