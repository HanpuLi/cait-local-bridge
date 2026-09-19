"""Network-facing auth hardening (2026-09-17): lockout keyed on the proxy-resolved client IP, global lockout, refresh-token
reuse detection with grace, pruning of unauthenticated-endpoint rows, and security headers on the login pages."""
from __future__ import annotations
import asyncio, os, tempfile, time, unittest
os.environ.setdefault("CLB_STATE_DIR", tempfile.mkdtemp(prefix="clb-auth-test-"))
from pydantic import AnyHttpUrl
from starlette.requests import Request
from mcp.server.auth.provider import RefreshToken
from mcp.shared.auth import OAuthClientInformationFull
from bridge import auth, db
from bridge.config import load_config

unittest.addModuleCleanup(db.close_thread_connection)

CFG = load_config()
CLIENT = OAuthClientInformationFull(client_id="c-test", redirect_uris=[AnyHttpUrl("http://localhost:9/cb")])


def _req(client_host: str, xff: str | None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request({"type": "http", "method": "GET", "path": "/login", "headers": headers, "client": (client_host, 1), "query_string": b""})


class ClientIp(unittest.TestCase):
    def test_raw_xff_header_is_ignored(self):
        # uvicorn already resolved the trusted-proxy chain into request.client; a spoofed header must not win
        self.assertEqual(auth._client_ip(_req("143.58.139.93", "203.0.113.7, 10.0.0.1")), "143.58.139.93")
        self.assertEqual(auth._client_ip(_req("127.0.0.1", None)), "127.0.0.1")


class Lockout(unittest.TestCase):
    def setUp(self):
        db.q("DELETE FROM login_attempts")

    def test_per_ip_lockout(self):
        for _ in range(CFG["login_max_attempts"]):
            db.q("INSERT INTO login_attempts(ts,ip,ok) VALUES(?,?,0)", time.time(), "1.1.1.1")
        self.assertTrue(auth._locked("1.1.1.1", CFG))
        self.assertFalse(auth._locked("2.2.2.2", CFG))

    def test_global_lockout_across_many_ips(self):
        for i in range(CFG["login_global_max_attempts"]):
            db.q("INSERT INTO login_attempts(ts,ip,ok) VALUES(?,?,0)", time.time(), f"203.0.113.{i}")
        self.assertTrue(auth._locked("198.51.100.9", CFG), "a fresh IP must be locked once the global budget is spent")
        db.q("DELETE FROM login_attempts")
        for i in range(3):
            db.q("INSERT INTO login_attempts(ts,ip,ok) VALUES(?,?,0)", time.time(), f"203.0.113.{i}")
        self.assertFalse(auth._locked("198.51.100.9", CFG))

    def test_old_failures_expire(self):
        for i in range(CFG["login_global_max_attempts"] + 5):
            db.q("INSERT INTO login_attempts(ts,ip,ok) VALUES(?,?,0)", time.time() - CFG["login_lockout_seconds"] - 5, f"203.0.113.{i}")
        self.assertFalse(auth._locked("203.0.113.1", CFG))


class RefreshReuse(unittest.TestCase):
    def setUp(self):
        db.q("DELETE FROM tokens"); db.q("DELETE FROM oauth_clients")
        self.p = auth.BridgeAuthProvider("https://example.test/gw")
        asyncio.run(self.p.register_client(CLIENT))

    def _rotate(self, refresh: str):
        rt = asyncio.run(self.p.load_refresh_token(CLIENT, refresh))
        self.assertIsNotNone(rt)
        return asyncio.run(self.p.exchange_refresh_token(CLIENT, rt, rt.scopes))

    def test_replay_within_grace_is_rejected_but_family_survives(self):
        t1 = self.p._issue("c-test", "cait", [auth.SCOPE], self.p.resource_url, family="fam1")
        t2 = self._rotate(t1.refresh_token)
        self.assertIsNone(asyncio.run(self.p.load_refresh_token(CLIENT, t1.refresh_token)))       # old one is dead
        self.assertIsNotNone(asyncio.run(self.p.load_access_token(t2.access_token)))               # new pair still fine
        self.assertIsNotNone(asyncio.run(self.p.load_refresh_token(CLIENT, t2.refresh_token)))

    def test_replay_after_grace_revokes_whole_family(self):
        t1 = self.p._issue("c-test", "cait", [auth.SCOPE], self.p.resource_url, family="fam2")
        t2 = self._rotate(t1.refresh_token)
        db.q("UPDATE tokens SET revoked_at=? WHERE token_hash=?", time.time() - CFG["refresh_reuse_grace_seconds"] - 1, auth._h(t1.refresh_token))
        self.assertIsNone(asyncio.run(self.p.load_refresh_token(CLIENT, t1.refresh_token)))       # replay
        self.assertIsNone(asyncio.run(self.p.load_access_token(t2.access_token)), "thief's replay must kill the live pair")
        self.assertIsNone(asyncio.run(self.p.load_refresh_token(CLIENT, t2.refresh_token)))
        self.assertTrue(db.one("SELECT 1 FROM audit WHERE tool='oauth.refresh_reuse'"))

    def test_legacy_rows_without_revoked_at_are_left_alone(self):
        t1 = self.p._issue("c-test", "cait", [auth.SCOPE], self.p.resource_url, family="fam3")
        t2 = self._rotate(t1.refresh_token)
        db.q("UPDATE tokens SET revoked_at=NULL WHERE token_hash=?", auth._h(t1.refresh_token))
        self.assertIsNone(asyncio.run(self.p.load_refresh_token(CLIENT, t1.refresh_token)))
        self.assertIsNotNone(asyncio.run(self.p.load_access_token(t2.access_token)))

    def test_revoke_all_sets_revoked_at(self):
        self.p._issue("c-test", "cait", [auth.SCOPE], self.p.resource_url, family="fam4")
        auth.revoke_all_tokens()
        self.assertEqual(db.one("SELECT COUNT(*) c FROM tokens WHERE revoked=0 OR revoked_at IS NULL")["c"], 0)


class Prune(unittest.TestCase):
    def test_expired_rows_and_orphan_clients_go(self):
        now = time.time()
        db.q("DELETE FROM pending_auth"); db.q("DELETE FROM auth_codes"); db.q("DELETE FROM oauth_clients"); db.q("DELETE FROM tokens"); db.q("DELETE FROM login_attempts")
        db.q("INSERT INTO pending_auth(id,data,expires_at) VALUES('old','{}',?)", now - 1)
        db.q("INSERT INTO pending_auth(id,data,expires_at) VALUES('new','{}',?)", now + 600)
        db.q("INSERT INTO auth_codes(code,data,expires_at) VALUES('old','{}',?)", now - 1)
        db.q("INSERT INTO login_attempts(ts,ip,ok) VALUES(?,?,0)", now - 2 * 86400, "9.9.9.9")
        db.q("INSERT INTO oauth_clients(client_id,data,created_at) VALUES('probe','{}',?)", now - 8 * 86400)
        db.q("INSERT INTO oauth_clients(client_id,data,created_at) VALUES('fresh','{}',?)", now - 60)
        db.q("INSERT INTO oauth_clients(client_id,data,created_at) VALUES('real','{}',?)", now - 30 * 86400)
        db.q("INSERT INTO tokens(token_hash,kind,client_id,subject,scopes,resource,expires_at,revoked,created_at,family) VALUES('h','refresh','real','cait','[]','r',?,0,?,'f')", now + 100, now)
        auth._prune(CFG)
        self.assertEqual({r["id"] for r in db.all_("SELECT id FROM pending_auth")}, {"new"})
        self.assertEqual(db.one("SELECT COUNT(*) c FROM auth_codes")["c"], 0)
        self.assertEqual(db.one("SELECT COUNT(*) c FROM login_attempts")["c"], 0)
        self.assertEqual({r["client_id"] for r in db.all_("SELECT client_id FROM oauth_clients")}, {"fresh", "real"})


class PageHeaders(unittest.TestCase):
    def test_login_page_headers(self):
        r = auth._page("<p>x</p>", 400)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.headers["x-frame-options"], "DENY")
        self.assertIn("frame-ancestors 'none'", r.headers["content-security-policy"])
        self.assertEqual(r.headers["cache-control"], "no-store")
        self.assertEqual(r.headers["referrer-policy"], "no-referrer")


if __name__ == "__main__":
    unittest.main()
