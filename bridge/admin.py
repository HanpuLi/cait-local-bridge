"""Loopback-only admin channel (127.0.0.1:<admin_port>, bearer = ~/.cait-local-bridge/secrets/admin.token, mode 0600).
It is never proxied by Funnel and is blocked from the managed browser. Everything here is a user decision made on the Mac:
workspaces, grants, token revocation, job control, kill switch. Remote (OAuth) identities cannot reach it."""
from __future__ import annotations
import hmac, json, os, shutil, subprocess, time
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from . import db, policy, jobs, auth, browser, agents, pipelines, coding, shells
from .config import admin_token, load_config, STATE_DIR

CFG = load_config()
TS = next((
    p for p in (
        shutil.which("tailscale"),
        "/usr/local/bin/tailscale",
        "/opt/homebrew/bin/tailscale",
    ) if p and os.path.exists(p)
), None)


def _authed(request: Request) -> bool:
    h = request.headers.get("authorization", "")
    return h.startswith("Bearer ") and hmac.compare_digest(h[7:], admin_token())


def _funnel_mounts() -> list[str]:
    return [CFG["funnel_path"], *CFG.get("funnel_wellknown_paths", [])]


def _funnel(action: str) -> dict:
    """Manage only the bridge's configured Funnel path mounts; unrelated mounts are untouched."""
    if not TS:
        return {"error": "tailscale executable not found", "rc": 127, "mounts": _funnel_mounts()}
    port = str(CFG["funnel_port"])
    if action == "status":
        r = subprocess.run([TS, "funnel", "status", "--json"], capture_output=True, text=True, timeout=20)
        return {"raw": r.stdout[:4000], "rc": r.returncode, "mounts": _funnel_mounts()}
    if action not in ("on", "off"):
        return {"error": "bad action"}
    results = []
    for mount in _funnel_mounts():
        target = f"http://127.0.0.1:{CFG['listen_port']}" if action == "on" else "off"
        r = subprocess.run([TS, "funnel", "--bg", "--yes", f"--https={port}", f"--set-path={mount}", target],
                           capture_output=True, text=True, timeout=30)
        results.append({"mount": mount, "rc": r.returncode, "stdout": r.stdout[-500:], "stderr": r.stderr[-500:]})
    return {"rc": max(x["rc"] for x in results), "mounts": results}


async def handle(request: Request):
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, 401)
    op = request.path_params["op"]
    body = {}
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
    try:
        if op == "status":
            active = [j for j in jobs.list_jobs(limit=500) if j["status"] in jobs.STATUS_ACTIVE]
            tokens = db.one("SELECT COUNT(*) c FROM tokens WHERE revoked=0 AND kind='access' AND expires_at>?", time.time())["c"]
            clients = db.one("SELECT COUNT(*) c FROM oauth_clients")["c"]
            return JSONResponse({"ok": True, "pid": os.getpid(), "state_dir": str(STATE_DIR), "workspaces": policy.workspace_list(True),
                                 "active_jobs": active, "active_agents": [a for a in agents.list_runs(limit=100) if a["status"] in agents.STATUS_ACTIVE], "live_access_tokens": tokens, "oauth_clients": clients,
                                 "passphrase_configured": auth.passphrase_configured(), "browser_pages": browser.list_pages(), "public_url": CFG["public_url"]})
        if op == "workspace_add":
            return JSONResponse({"ok": True, "workspace": policy.workspace_add(body["root"], body.get("name") or os.path.basename(body["root"]),
                                                                              body.get("profiles") or ["sandboxed"], body.get("network", "off"), body.get("days", 30), body.get("notes", ""))})
        if op == "workspace_revoke":
            policy.workspace_revoke(body["id"]); return JSONResponse({"ok": True})
        if op == "workspace_profiles":
            w = policy.workspace_get(body["id"], check=False)
            profs = set(w["profiles"]) | set(body.get("add", [])); profs -= set(body.get("remove", []))
            db.q("UPDATE workspaces SET profiles=?, network=COALESCE(?, network), revoked=0 WHERE id=?", json.dumps(sorted(profs)), body.get("network"), body["id"])
            return JSONResponse({"ok": True, "workspace": policy.workspace_get(body["id"], check=False)})
        if op == "grant_add":
            return JSONResponse({"ok": True, "grant": policy.grant_add(body["workspace_id"], body["kind"], body.get("params", {}), body.get("hours", 24), body.get("max_uses"))})
        if op == "grant_list":
            return JSONResponse({"ok": True, "grants": policy.grant_list(body.get("workspace_id"))})
        if op == "grant_revoke":
            policy.grant_revoke(body["id"]); return JSONResponse({"ok": True})
        if op == "tokens_revoke_all":
            return JSONResponse({"ok": True, "revoked": auth.revoke_all_tokens()})
        if op == "tokens_list":
            rows = db.all_("SELECT client_id, subject, kind, expires_at, revoked, created_at FROM tokens ORDER BY created_at DESC LIMIT 50")
            return JSONResponse({"ok": True, "tokens": [dict(r) for r in rows]})
        if op == "clients_list":
            rows = db.all_("SELECT client_id, data, created_at FROM oauth_clients")
            return JSONResponse({"ok": True, "clients": [{"client_id": r["client_id"], "name": json.loads(r["data"]).get("client_name"), "redirect_uris": json.loads(r["data"]).get("redirect_uris"), "created_at": r["created_at"]} for r in rows]})
        if op == "jobs":
            return JSONResponse({"ok": True, "jobs": jobs.list_jobs(body.get("workspace_id"), body.get("limit", 50))})
        if op == "job_cancel":
            return JSONResponse({"ok": True, "job": jobs.cancel(body["id"], "admin")})
        if op == "desktop_permissions":
            from . import desktop
            return JSONResponse({"ok": True, **(desktop.request_permissions() if body.get("request") else desktop.permissions())})
        if op == "agents":
            return JSONResponse({"ok": True, "runs": agents.list_runs(body.get("workspace_id"), body.get("limit", 50))})
        if op == "pipelines":
            return JSONResponse({"ok": True, "pipelines": pipelines.list_pipelines(body.get("workspace_id"), body.get("limit", 20))})
        if op == "coding_tasks":
            return JSONResponse({"ok": True, "tasks": coding.list_tasks(body.get("workspace_id"), body.get("limit", 20))})
        if op == "coding_task":
            return JSONResponse({"ok": True, "task": coding.info(body["id"])})
        if op == "coding_task_start":
            t = coding.start(body["workspace_id"], body["task"], body.get("repo_path", "."), body.get("test_command"), body.get("max_rounds", 3), body.get("effort", "extra_high"),
                             body.get("agent"), body.get("profile"), body.get("agent_timeout_seconds"), body.get("test_timeout_seconds", 900), body.get("baseline", True),
                             body.get("branch"), body.get("browser_sites"), body.get("notes"), body.get("protected_paths"), "admin")
            return JSONResponse({"ok": True, "task": t})
        if op == "coding_task_cancel":
            return JSONResponse({"ok": True, "task": await coding.cancel(body["id"], "admin")})
        if op == "pipeline_cancel":
            return JSONResponse({"ok": True, "pipeline": await pipelines.cancel(body["id"], "admin")})
        if op == "agent_cancel":
            return JSONResponse({"ok": True, "run": await agents.cancel(body["id"], "admin")})
        if op == "jobs_cancel_all":
            return JSONResponse({"ok": True, "cancelled": jobs.cancel_all("admin")})
        if op == "funnel":
            return JSONResponse({"ok": True, **_funnel(body.get("action", "status"))})
        if op == "killswitch":
            closed_shells = shells.close_all("killswitch")
            out = {"funnel": _funnel("off"), "tokens_revoked": auth.revoke_all_tokens(),
                   "shells_closed": closed_shells, "jobs_cancelled": jobs.cancel_all("killswitch")}
            try:
                for p in pipelines.list_pipelines(limit=100):
                    if p["status"] in pipelines.STATUS_ACTIVE:
                        await pipelines.cancel(p["pipeline_id"], "killswitch")
                for t in coding.list_tasks(limit=100):
                    if t["status"] in coding.STATUS_ACTIVE:
                        await coding.cancel(t["task_id"], "killswitch")
                out["agents_cancelled"] = await agents.cancel_all("killswitch")
            except Exception as e:
                out["agents_cancelled"] = str(e)
            try:
                out["browser"] = await browser.close()
            except Exception as e:
                out["browser"] = str(e)
            db.audit("killswitch", json.dumps(out)[:1000])
            return JSONResponse({"ok": True, **out})
        if op == "audit":
            rows = db.all_("SELECT ts, subject, tool, workspace_id, summary FROM audit ORDER BY id DESC LIMIT ?", body.get("limit", 100))
            return JSONResponse({"ok": True, "audit": [dict(r) for r in rows]})
        if op == "devports":
            return JSONResponse({"ok": True, "ports": [dict(r) for r in db.all_("SELECT * FROM dev_ports")]})
        return JSONResponse({"error": "unknown op"}, 404)
    except policy.BridgeError as e:
        return JSONResponse(e.payload(), 400)
    except KeyError as e:
        return JSONResponse({"error": "invalid_argument", "message": f"missing {e}"}, 400)


def build_admin_app() -> Starlette:
    return Starlette(routes=[Route("/admin/{op}", handle, methods=["GET", "POST"])])
