"""Server-side end-to-end test client (NOT the ChatGPT client). Runs the real OAuth 2.1 flow (DCR, PKCE S256, login,
consent, code exchange, refresh) against a running bridge, then exercises tools over Streamable HTTP with the official
MCP Python client. Prints a JSON evidence record. Usage:
  .venv/bin/python tests/e2e_client.py --base http://127.0.0.1:8795 --passphrase-env CLB_TEST_PASSPHRASE [--public https://bridge.example.com/gw]
"""
from __future__ import annotations
import argparse, asyncio, base64, hashlib, json, os, re, secrets, shlex, sys, time, urllib.parse
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import httpx


def pkce():
    v = secrets.token_urlsafe(48)
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")
    return v, c


def oauth_flow(base: str, passphrase: str, public: str | None, redirect="http://localhost:9/cb", wrong_passphrase_first=False) -> dict:
    ev = {}
    c = httpx.Client(base_url=base, follow_redirects=False, timeout=30, headers={"Host": urllib.parse.urlsplit(public or base).netloc})
    meta = c.get("/.well-known/oauth-authorization-server").json(); ev["metadata"] = meta
    prm = c.get("/.well-known/oauth-protected-resource/mcp").json(); ev["protected_resource"] = prm
    reg = c.post("/register", json={"client_name": "bridge e2e test client", "redirect_uris": [redirect], "grant_types": ["authorization_code", "refresh_token"],
                                    "response_types": ["code"], "token_endpoint_auth_method": "none"})
    assert reg.status_code in (200, 201), reg.text
    client = reg.json(); ev["client_id"] = client["client_id"]
    verifier, challenge = pkce(); state = secrets.token_hex(8)
    r = c.get("/authorize", params={"client_id": client["client_id"], "response_type": "code", "redirect_uri": redirect, "code_challenge": challenge,
                                   "code_challenge_method": "S256", "state": state, "scope": "bridge:tools", "resource": prm["resource"]})
    assert r.status_code in (302, 303), (r.status_code, r.text[:300])
    loc = r.headers["location"]; ev["authorize_redirect"] = loc
    login_path = "/login?" + urllib.parse.urlsplit(loc).query
    page = c.get(login_path); assert page.status_code == 200 and "Passphrase" in page.text
    csrf = re.search(r'name=csrf value="([^"]+)"', page.text).group(1)
    if wrong_passphrase_first:
        bad = c.post(login_path, data={"csrf": csrf, "passphrase": "definitely-wrong-passphrase"})
        ev["wrong_passphrase_rejected"] = "Wrong passphrase" in bad.text and "Allow" not in bad.text
    ok = c.post(login_path, data={"csrf": csrf, "passphrase": passphrase})
    assert "Allow" in ok.text, ok.text[:400]
    approve = re.search(r'name=approve value="([^"]+)"', ok.text).group(1); pid = re.search(r'name=p value="([^"]+)"', ok.text).group(1)
    cons = c.post("/consent", data={"p": pid, "approve": approve, "decision": "allow"})
    assert cons.status_code == 302, cons.text[:300]
    cb = urllib.parse.urlsplit(cons.headers["location"]); qs = dict(urllib.parse.parse_qsl(cb.query))
    assert qs.get("state") == state and "code" in qs, qs
    tok = c.post("/token", data={"grant_type": "authorization_code", "code": qs["code"], "code_verifier": verifier, "client_id": client["client_id"],
                                 "redirect_uri": redirect, "resource": prm["resource"]})
    assert tok.status_code == 200, tok.text
    t = tok.json(); ev["token_type"] = t["token_type"]; ev["expires_in"] = t["expires_in"]; ev["scope"] = t.get("scope")
    # code is single use
    again = c.post("/token", data={"grant_type": "authorization_code", "code": qs["code"], "code_verifier": verifier, "client_id": client["client_id"], "redirect_uri": redirect})
    ev["code_reuse_rejected"] = again.status_code == 400
    # wrong verifier on a fresh code is covered by the SDK; refresh rotation:
    rf = c.post("/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"], "client_id": client["client_id"]})
    ev["refresh_ok"] = rf.status_code == 200
    rf2 = c.post("/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"], "client_id": client["client_id"]})
    ev["old_refresh_rejected_after_rotation"] = rf2.status_code == 400
    t2 = rf.json() if rf.status_code == 200 else t
    ev["access_token"] = t2["access_token"]; ev["refresh_token"] = t2.get("refresh_token")
    # revocation: a second, independent login (token family B) is revoked; family A stays valid for the tool calls
    tb = _second_login(c, client, passphrase, redirect)
    rv = c.post("/revoke", data={"token": tb["access_token"], "client_id": client["client_id"], "client_secret": ""})
    ev["revoke_status"] = rv.status_code
    ev["old_access_token"] = tb["access_token"]   # must be rejected afterwards (family revoked)
    return ev


def _second_login(c, client, passphrase, redirect):
    verifier, challenge = pkce()
    r = c.get("/authorize", params={"client_id": client["client_id"], "response_type": "code", "redirect_uri": redirect, "code_challenge": challenge, "code_challenge_method": "S256", "state": "b"})
    login_path = "/login?" + urllib.parse.urlsplit(r.headers["location"]).query
    page = c.get(login_path); csrf = re.search(r'name=csrf value="([^"]+)"', page.text).group(1)
    ok = c.post(login_path, data={"csrf": csrf, "passphrase": passphrase})
    approve = re.search(r'name=approve value="([^"]+)"', ok.text).group(1); pid = re.search(r'name=p value="([^"]+)"', ok.text).group(1)
    cons = c.post("/consent", data={"p": pid, "approve": approve, "decision": "allow"})
    qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(cons.headers["location"]).query))
    return c.post("/token", data={"grant_type": "authorization_code", "code": qs["code"], "code_verifier": verifier, "client_id": client["client_id"], "redirect_uri": redirect}).json()


async def mcp_calls(base: str, token: str, public: str | None, ws_root: str, extra: dict | None = None) -> dict:
    from mcp.client.streamable_http import streamable_http_client
    from mcp import ClientSession
    headers = {"Authorization": f"Bearer {token}"}
    if public:
        headers["Host"] = urllib.parse.urlsplit(public).netloc
    ev = {"calls": []}
    async with streamable_http_client(base + "/mcp", http_client=__import__("httpx2").AsyncClient(headers=headers, timeout=120)) as streams:
        async with ClientSession(*streams[:2]) as s:
            init = await s.initialize(); ev["server"] = init.server_info.name; ev["protocol"] = init.protocol_version
            ev["instructions_head"] = (init.instructions or "")[:80]
            tools = await s.list_tools(); ev["tool_count"] = len(tools.tools); ev["tools"] = sorted(t.name for t in tools.tools)
            async def call(name, **args):
                res = await s.call_tool(name, args)
                sc = res.structured_content or json.loads(res.content[-1].text)
                ev["calls"].append({"tool": name, "ok": not res.is_error, "error": sc.get("error"), "request_id": sc.get("request_id")})
                return res, sc
            _, info = await call("bridge_info")
            ev["host_id"] = info["provenance"]["host_id"]; ev["workspaces"] = [w["id"] for w in info["data"]["workspaces"]]
            ws = next((w["id"] for w in info["data"]["workspaces"] if w["root"] == ws_root), None)
            ev["workspace_id"] = ws
            if ws:
                _, sc = await call("file_search", workspace_id=ws, pattern="def add")
                ev["search_hits"] = sc["data"]["hits"]
                _, sc = await call("file_read", workspace_id=ws, path="calc.py")
                ev["calc_sha"] = sc["data"]["sha256"]
                _, sc = await call("exec_start", workspace_id=ws, command=["python3", "-m", "unittest", "-v", "test_calc"], profile="sandboxed", timeout_seconds=120)
                job = sc["data"]["job_id"]
                for _ in range(60):
                    _, p = await call("exec_poll", job_id=job)
                    if p["data"]["status"] not in ("queued", "running"): break
                    await asyncio.sleep(0.5)
                ev["test_before"] = {"status": p["data"]["status"], "exit_code": p["data"]["exit_code"]}
                _, lg = await call("exec_logs", job_id=job, stream="stdout")
                ev["test_before_log_tail"] = lg["data"]["text"][-400:]
                # caller-provided fix (fixed patch for the mechanism test; ChatGPT writes its own in the client acceptance)
                patch = "--- a/calc.py\n+++ b/calc.py\n@@ -1,2 +1,2 @@\n def add(a, b):\n-    return a - b\n+    return a + b\n"
                _, pt = await call("file_patch", workspace_id=ws, unified_diff=patch, expected_sha256={"calc.py": ev["calc_sha"]})
                ev["patch"] = pt["data"]
                _, sc = await call("exec_start", workspace_id=ws, command="python3 -m unittest -v test_calc", profile="sandboxed", timeout_seconds=120)
                job2 = sc["data"]["job_id"]
                for _ in range(60):
                    _, p = await call("exec_poll", job_id=job2)
                    if p["data"]["status"] not in ("queued", "running"): break
                    await asyncio.sleep(0.5)
                ev["test_after"] = {"status": p["data"]["status"], "exit_code": p["data"]["exit_code"]}
                _, lg = await call("exec_logs", job_id=job2, stream="stdout"); ev["test_after_log_tail"] = lg["data"]["text"][-300:]
                _, ex = await call("artifact_export", workspace_id=ws, path="calc.py"); ev["export_sha"] = ex["data"]["sha256"]
                _, st = await call("state_write", workspace_id=ws, key="e2e", content={"job_before": job, "job_after": job2, "calc_sha": ex["data"]["sha256"]})
                ev["state_rev"] = st["data"]["revision"]
                # PTY + input + cancel
                _, sc = await call("exec_start", workspace_id=ws, command=["python3", "-c", "import sys; print('name?', flush=True); n=sys.stdin.readline().strip(); print('hello', n, flush=True); import time; time.sleep(60)"], use_pty=True, timeout_seconds=90)
                j3 = sc["data"]["job_id"]; await asyncio.sleep(1)
                await call("exec_input", job_id=j3, text="bridge-test", keys=["enter"]); await asyncio.sleep(1)
                _, lg = await call("exec_logs", job_id=j3); ev["pty_output"] = lg["data"]["text"][-120:]
                _, cn = await call("exec_cancel", job_id=j3); ev["cancel"] = {"status": cn.get("data", {}).get("status"), "survivors": cn.get("data", {}).get("surviving_pids", []), "error": cn.get("error")}
                # sandbox boundaries from inside a job. Build real-home probes dynamically so
                # this test suite is portable and does not publish an operator's absolute path.
                real_home = Path.home()
                real_docs = shlex.quote(str(real_home / "Documents"))
                control_token = shlex.quote(str(real_home / ".scoperail" / "secrets" / "admin.token"))
                escape_probe = shlex.quote(str(real_home / "Desktop" / "clb-escape-probe"))
                probes = {"home_read": f"cat ~/.ssh/config 2>&1 | head -1; ls {real_docs} 2>&1 | head -1",
                          "control_plane": f"cat {control_token} 2>&1 | head -c 60",
                          "write_outside": f"touch {escape_probe} 2>&1; ls {escape_probe} 2>&1",
                          "network": "curl -s -m 5 -o /dev/null -w '%{http_code}' https://example.com; echo",
                          "no_model_env": "env | grep -i -E 'anthropic|openai|claude|codex' ; echo env-scan-done; which claude codex 2>&1"}
                for name, sh in probes.items():
                    _, sc = await call("exec_start", workspace_id=ws, command=sh, profile="sandboxed", timeout_seconds=30)
                    jid = sc["data"]["job_id"]
                    for _ in range(40):
                        _, p = await call("exec_poll", job_id=jid)
                        if p["data"]["status"] not in ("queued", "running"): break
                        await asyncio.sleep(0.3)
                    _, lg = await call("exec_logs", job_id=jid); _, le = await call("exec_logs", job_id=jid, stream="stderr")
                    ev.setdefault("sandbox_probes", {})[name] = {"exit": p["data"]["exit_code"], "stdout": lg["data"]["text"][-200:], "stderr": le["data"]["text"][-200:]}
                # path escape via tool args
                _, esc = await call("file_read", workspace_id=ws, path="../../.scoperail/config.json"); ev["path_escape"] = esc.get("error")
                _, esc2 = await call("file_read", workspace_id=ws, path="/etc/passwd"); ev["abs_escape"] = esc2.get("error")
                if extra and extra.get("browser_url"):
                    _, bo = await call("browser_open", workspace_id=ws, url=extra["browser_url"], width=390, height=844)
                    ev["browser_open"] = bo.get("data"); pid = (bo.get("data") or {}).get("page_id")
                    if pid:
                        _, sn = await call("browser_snapshot", page_id=pid, mode="text", max_chars=200); ev["browser_text"] = sn["data"]["content"][:120]
                        res, sh = await call("browser_screenshot", page_id=pid)
                        ev["screenshot"] = {"bytes": sh["data"]["bytes"], "image_block": any(c.type == "image" for c in res.content), "path": sh["data"]["path"]}
                        _, bl = await call("browser_navigate", page_id=pid, url="http://127.0.0.1:8796/admin/status"); ev["browser_admin_blocked"] = not bl["data"].get("ok")
                        _, bl2 = await call("browser_navigate", page_id=pid, url="http://100.64.0.1/"); ev["browser_private_network_blocked"] = not bl2["data"].get("ok")
                        await call("browser_close", page_id=pid)
                if extra and extra.get("git_remote"):
                    await call("git_write", workspace_id=ws, subcommand="add", args=["-A"])
                    _, cm = await call("git_write", workspace_id=ws, subcommand="commit", args=["-m", "fix add() via bridge e2e"]); ev["commit"] = cm.get("ok")
                    _, pd = await call("git_push", workspace_id=ws, remote="origin", branch="main"); ev["push_without_grant"] = pd.get("error")
                    from bridge.config import admin_token, load_config
                    g = httpx.post(f"http://127.0.0.1:{load_config()['admin_port']}/admin/grant_add", json={"workspace_id": ws, "kind": "git_push", "params": {"remote": "origin", "branch": "main"}, "hours": 1, "max_uses": 1},
                                   headers={"Authorization": f"Bearer {admin_token()}"}).json()
                    _, pg = await call("git_push", workspace_id=ws, remote="origin", branch="main")
                    ev["push_with_grant"] = {k: pg.get("data", {}).get(k) for k in ("ok", "published", "local_head", "remote_head", "grant_id")}
                    _, pg2 = await call("git_push", workspace_id=ws, remote="origin", branch="main"); ev["push_after_grant_used_up"] = pg2.get("error")
            _, den = await call("file_read", workspace_id="ws_doesnotexist", path="x"); ev["unknown_workspace"] = den.get("error")
    return ev


async def bad_token_probe(base: str, token: str, public: str | None) -> dict:
    out = {}
    headers = {"Host": urllib.parse.urlsplit(public or base).netloc}
    async with httpx.AsyncClient(base_url=base, timeout=15) as c:
        body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "x", "version": "0"}}}
        r = await c.post("/mcp", json=body, headers={**headers, "Accept": "application/json, text/event-stream"}); out["anonymous"] = r.status_code
        out["www_authenticate"] = r.headers.get("www-authenticate", "")[:200]
        r = await c.post("/mcp", json=body, headers={**headers, "Authorization": "Bearer nope", "Accept": "application/json, text/event-stream"}); out["garbage_token"] = r.status_code
        r = await c.post("/mcp", json=body, headers={**headers, "Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream"}); out["revoked_token"] = r.status_code
        r = await c.post("/mcp", json=body, headers={"Host": "evil.example", "Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream"}); out["bad_host"] = r.status_code
        r = await c.post("/mcp?access_token=" + token, json=body, headers={**headers, "Accept": "application/json, text/event-stream"}); out["query_token"] = r.status_code
    return out


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--base", default="http://127.0.0.1:8795"); ap.add_argument("--public", default=None)
    ap.add_argument("--passphrase-env", default="CLB_TEST_PASSPHRASE"); ap.add_argument("--ws-root", required=True); ap.add_argument("--browser-url", default=None)
    ap.add_argument("--git-remote", action="store_true"); ap.add_argument("--out", default=None)
    a = ap.parse_args()
    pw = os.environ.get(a.passphrase_env) or sys.exit("passphrase env missing")
    ev = {"started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "base": a.base, "public": a.public}
    ev["oauth"] = oauth_flow(a.base, pw, a.public, wrong_passphrase_first=True)
    tok = ev["oauth"].pop("access_token"); old = ev["oauth"].pop("old_access_token"); ev["oauth"].pop("refresh_token", None)
    ev["mcp"] = asyncio.run(mcp_calls(a.base, tok, a.public, a.ws_root, {"browser_url": a.browser_url, "git_remote": a.git_remote}))
    ev["rejections"] = asyncio.run(bad_token_probe(a.base, old, a.public))
    ev["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    s = json.dumps(ev, indent=1, ensure_ascii=False, default=str)
    if a.out:
        open(a.out, "w").write(s)
    print(s)


if __name__ == "__main__":
    main()
