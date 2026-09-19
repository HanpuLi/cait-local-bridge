"""Deterministic multi-stage sub-agent pipelines (agent_pipeline): a DAG of agent_start calls run by the bridge.

There is no model in here. The bridge only substitutes placeholders, starts stages whose dependencies finished, and records
what happened — the same shape as a Claude Code workflow script (agent() / parallel() / pipeline()), except every "agent" is a
conversation in the user's own chatgpt.com session (agents.start). Stage outputs travel as FILES in the workspace, never as
text pasted into the next prompt: `{{<stage>.output}}` expands to the workspace-relative path of that stage's output file and
the next sub-agent reads it with file_read (a call that has never been dropped by OpenAI's safety check, unlike prompts that
quote tool output). When the main ChatGPT session needs to judge an intermediate result, it submits the next pipeline itself.
"""
from __future__ import annotations
import asyncio, json, re, time, uuid
from pathlib import Path
from . import db, agents
from .config import load_config
from .policy import BridgeError, workspace_get, resolve_in_workspace

CFG = load_config()
MAX_STAGES = int(CFG.get("max_pipeline_stages", 12))
POLL_S = float(CFG.get("pipeline_poll_seconds", 10))
DEFAULT_STOP_ON = ["blocked", "failed", "needs_user_action"]
STATUS_ACTIVE = ("queued", "running")
_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_PLACEHOLDER = re.compile(r"\{\{\s*([a-z][a-z0-9_]*)\.(output|run_id|dir)\s*\}\}")

db.conn().executescript("""
CREATE TABLE IF NOT EXISTS agent_pipelines(id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, status TEXT NOT NULL,
  created_at REAL NOT NULL, start_ts REAL, end_ts REAL, spec TEXT NOT NULL, state TEXT NOT NULL DEFAULT '{}', summary TEXT);
""")

_tasks: dict[str, asyncio.Task] = {}


# ---------- validation ----------
def validate(workspace_id: str, spec: dict) -> dict:
    """Return a normalised spec or raise invalid_argument. Checks ids, dependencies (present, acyclic), personas, efforts, placeholders."""
    if not isinstance(spec, dict) or not isinstance(spec.get("stages"), list) or not spec["stages"]:
        raise BridgeError("invalid_argument", "spec.stages must be a non-empty list")
    stages = spec["stages"]
    if len(stages) > MAX_STAGES:
        raise BridgeError("invalid_argument", f"at most {MAX_STAGES} stages per pipeline")
    ids = [s.get("id") for s in stages if isinstance(s, dict)]
    if len(ids) != len(stages) or any(not isinstance(i, str) or not _ID.match(i) for i in ids):
        raise BridgeError("invalid_argument", "every stage needs an id matching ^[a-z][a-z0-9_]{0,31}$")
    if len(set(ids)) != len(ids):
        raise BridgeError("invalid_argument", "stage ids must be unique")
    if "pipeline" in ids:
        raise BridgeError("invalid_argument", "'pipeline' is a reserved stage id")
    default_effort = spec.get("default_effort", "extra_high")
    if default_effort not in agents.EFFORTS + ["auto"]:
        raise BridgeError("invalid_argument", f"default_effort must be one of {agents.EFFORTS} or auto")
    max_parallel = int(spec.get("max_parallel", agents.MAX_AGENTS))
    if not 1 <= max_parallel <= agents.MAX_AGENTS:
        raise BridgeError("invalid_argument", f"max_parallel must be 1..{agents.MAX_AGENTS}")
    stop_on = spec.get("stop_on", DEFAULT_STOP_ON)
    if not isinstance(stop_on, list) or any(x not in ("blocked", "failed", "needs_user_action", "unverified", "needs_review") for x in stop_on):
        raise BridgeError("invalid_argument", "stop_on must be a list drawn from blocked|failed|needs_user_action|unverified|needs_review")
    out_dir = spec.get("output_dir") or f"_pipeline/{{pipeline_id}}"
    norm = []
    for s in stages:
        after = s.get("after") or []
        if not isinstance(after, list) or any(a not in ids for a in after) or s["id"] in after:
            raise BridgeError("invalid_argument", f"stage {s['id']}: 'after' must list other existing stage ids")
        prompt = s.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            raise BridgeError("invalid_argument", f"stage {s['id']}: prompt is empty")
        for ref, _field in _PLACEHOLDER.findall(prompt):
            if ref != "pipeline" and ref not in ids:
                raise BridgeError("invalid_argument", f"stage {s['id']}: placeholder refers to unknown stage '{ref}'")
            if ref != "pipeline" and ref not in after:
                raise BridgeError("invalid_argument", f"stage {s['id']}: uses {{{{{ref}.…}}}} but does not list '{ref}' in after")
        if s.get("agent"):
            agents.persona(s["agent"])
        effort = s.get("effort", default_effort)
        if effort not in agents.EFFORTS + ["auto"]:
            raise BridgeError("invalid_argument", f"stage {s['id']}: bad effort {effort!r}")
        sites = s.get("browser_sites") or []
        if not isinstance(sites, list) or any(not isinstance(x, str) for x in sites):
            raise BridgeError("invalid_argument", f"stage {s['id']}: browser_sites must be a list of hostnames")
        norm.append({"id": s["id"], "prompt": prompt.strip(), "agent": s.get("agent"), "effort": effort, "after": list(after),
                     "browser_sites": sites, "timeout_seconds": s.get("timeout_seconds"), "title": s.get("title")})
    # cycle check (Kahn)
    indeg = {s["id"]: len(s["after"]) for s in norm}
    order, ready = [], [i for i, d in indeg.items() if d == 0]
    while ready:
        n = ready.pop(); order.append(n)
        for s in norm:
            if n in s["after"]:
                indeg[s["id"]] -= 1
                if indeg[s["id"]] == 0:
                    ready.append(s["id"])
    if len(order) != len(norm):
        raise BridgeError("invalid_argument", "stage dependencies contain a cycle")
    return {"stages": norm, "default_effort": default_effort, "max_parallel": max_parallel, "stop_on": stop_on,
            "output_dir": out_dir, "note": spec.get("note")}


# ---------- persistence ----------
def _row(pid: str) -> dict:
    r = db.one("SELECT * FROM agent_pipelines WHERE id=?", pid)
    if not r:
        raise BridgeError("not_found", f"unknown pipeline {pid}")
    d = dict(r); d["spec"] = json.loads(d["spec"]); d["state"] = json.loads(d["state"] or "{}")
    d["summary"] = json.loads(d["summary"]) if d["summary"] else None
    return d


def _save_state(pid: str, state: dict) -> None:
    db.q("UPDATE agent_pipelines SET state=? WHERE id=?", json.dumps(state, ensure_ascii=False, default=str), pid)


def info(pid: str) -> dict:
    r = _row(pid)
    st = r["state"]
    stages = []
    for s in r["spec"]["stages"]:
        e = st.get(s["id"], {"status": "pending"})
        row = {"id": s["id"], "agent": s["agent"], "effort": s["effort"], "after": s["after"], "status": e.get("status", "pending"),
               "run_id": e.get("run_id"), "output": e.get("output"), "task_status": e.get("task_status"), "error_code": e.get("error_code"),
               "conversation_url": e.get("conversation_url"), "upstream_blocks_observed": e.get("upstream_blocks_observed", 0)}
        if e.get("run_id") and e.get("status") == "running":
            try:
                live = agents.info(e["run_id"])
                row.update({"phase": live.get("phase"), "tool_calls": live.get("tool_calls"), "conversation_url": live.get("conversation_url")})
            except BridgeError:
                pass
        stages.append(row)
    counts = {}
    for s in stages:
        counts[s["status"]] = counts.get(s["status"], 0) + 1
    return {"pipeline_id": pid, "workspace_id": r["workspace_id"], "status": r["status"], "created_at": r["created_at"], "start_ts": r["start_ts"],
            "end_ts": r["end_ts"], "elapsed_s": round((r["end_ts"] or time.time()) - (r["start_ts"] or r["created_at"]), 1),
            "output_dir": st.get("_dir"), "summary_path": st.get("_summary_path"), "counts": counts, "stages": stages,
            "summary": r["summary"], "note": r["spec"].get("note"), "attached": pid in _tasks}


def list_pipelines(workspace_id: str | None = None, limit: int = 20) -> list[dict]:
    rows = db.all_("SELECT id FROM agent_pipelines WHERE (?1 IS NULL OR workspace_id=?1) ORDER BY created_at DESC LIMIT ?2", workspace_id, limit)
    return [info(r["id"]) for r in rows]


# ---------- submit / cancel / recovery ----------
def start(workspace_id: str, spec: dict, subject: str | None = None) -> dict:
    ws = workspace_get(workspace_id)
    norm = validate(workspace_id, spec)
    pid = "pipe_" + uuid.uuid4().hex[:10]
    rel_dir = norm["output_dir"].replace("{pipeline_id}", pid)
    abs_dir = resolve_in_workspace(ws, rel_dir, must_exist=False)
    abs_dir.mkdir(parents=True, exist_ok=True)
    state = {"_dir": rel_dir, **{s["id"]: {"status": "pending"} for s in norm["stages"]}}
    db.q("INSERT INTO agent_pipelines(id,workspace_id,status,created_at,spec,state) VALUES(?,?,?,?,?,?)",
         pid, workspace_id, "queued", time.time(), json.dumps(norm, ensure_ascii=False), json.dumps(state, ensure_ascii=False))
    (abs_dir / "spec.json").write_text(json.dumps(norm, ensure_ascii=False, indent=1), encoding="utf-8")
    db.audit("agent_pipeline", f"{pid} stages={len(norm['stages'])}", subject=subject, workspace_id=workspace_id)
    _tasks[pid] = asyncio.get_running_loop().create_task(_guard(pid, subject))
    return info(pid)


async def cancel(pid: str, subject: str | None = None) -> dict:
    r = _row(pid)
    if r["status"] not in STATUS_ACTIVE:
        return info(pid)
    t = _tasks.get(pid)
    if t:
        t.cancel()
    st = r["state"]
    for sid, e in st.items():
        if sid.startswith("_"):
            continue
        if e.get("status") == "running" and e.get("run_id"):
            try:
                await agents.cancel(e["run_id"], subject)
            except BridgeError:
                pass
            e["status"] = "cancelled"
        elif e.get("status") == "pending":
            e["status"] = "skipped"; e["error_code"] = "pipeline_cancelled"
    _save_state(pid, st)
    _close(pid, "cancelled", subject)
    return info(pid)


def recover_on_startup() -> list[str]:
    notes = []
    for r in db.all_("SELECT id FROM agent_pipelines WHERE status IN ('queued','running')"):
        st = _row(r["id"])["state"]
        for sid, e in st.items():
            if not sid.startswith("_") and e.get("status") in ("running", "pending"):
                e["status"] = "interrupted" if e.get("status") == "running" else "skipped"
                e.setdefault("error_code", "interrupted")
        _save_state(r["id"], st)
        db.q("UPDATE agent_pipelines SET status='interrupted', end_ts=? WHERE id=?", time.time(), r["id"])
        notes.append(r["id"])
    return notes


# ---------- the runner ----------
def _expand(pid: str, stage: dict, state: dict) -> str:
    def sub(m):
        ref, field = m.group(1), m.group(2)
        if ref == "pipeline":
            return state["_dir"] if field == "dir" else pid
        e = state.get(ref, {})
        return {"output": e.get("output") or "", "run_id": e.get("run_id") or "", "dir": state["_dir"]}[field]
    return _PLACEHOLDER.sub(sub, stage["prompt"])


def _stage_ok(e: dict, stop_on: list[str]) -> bool:
    if e.get("status") not in ("completed", "succeeded"):
        return False
    return (e.get("task_status") or "unverified") not in stop_on


async def _guard(pid: str, subject: str | None) -> None:
    try:
        await _run(pid, subject)
    except asyncio.CancelledError:
        pass
    except Exception as e:  # noqa: BLE001 - recorded, never silent
        st = _row(pid)["state"]; st["_error"] = f"{type(e).__name__}: {str(e)[:400]}"; _save_state(pid, st)
        _close(pid, "failed", subject)
    finally:
        _tasks.pop(pid, None)


async def _run(pid: str, subject: str | None) -> None:
    r = _row(pid)
    spec, ws_id = r["spec"], r["workspace_id"]
    stop_on, max_par = spec["stop_on"], spec["max_parallel"]
    db.q("UPDATE agent_pipelines SET status='running', start_ts=? WHERE id=?", time.time(), pid)
    state = r["state"]
    by_id = {s["id"]: s for s in spec["stages"]}
    while True:
        # 1. harvest finished stages
        for sid, e in state.items():
            if sid.startswith("_") or e.get("status") != "running":
                continue
            live = agents.info(e["run_id"])
            if live["status"] in agents.STATUS_ACTIVE:
                continue
            if live.get("error_code") == "rate_limited" and e.get("retries", 0) < 1:
                # chatgpt.com throttle, not the stage's fault: queue it again once the bridge-wide backoff has passed
                e.update({"status": "pending", "retries": e.get("retries", 0) + 1, "previous_run_id": e["run_id"], "run_id": None})
                continue
            e.update({"status": live["status"], "task_status": live.get("task_status"), "error_code": live.get("error_code"),
                      "error": (live.get("error") or "")[:400] or None, "conversation_url": live.get("conversation_url"),
                      "upstream_blocks_observed": live.get("upstream_blocks_observed", 0), "end_ts": time.time()})
        # 2. skip stages whose dependencies did not pass
        for sid, e in state.items():
            if sid.startswith("_") or e.get("status") != "pending":
                continue
            deps = [state[a] for a in by_id[sid]["after"]]
            bad = [a for a, d in zip(by_id[sid]["after"], deps) if d.get("status") not in ("pending", "running") and not _stage_ok(d, stop_on)]
            if bad:
                e.update({"status": "skipped", "error_code": "upstream_stage_failed", "error": f"depends on {', '.join(bad)}"})
        # 3. start what is ready, within max_parallel
        running = sum(1 for k, e in state.items() if not k.startswith("_") and e.get("status") == "running")
        for sid, e in state.items():
            if running >= max_par:
                break
            if sid.startswith("_") or e.get("status") != "pending":
                continue
            if any(not _stage_ok(state[a], stop_on) for a in by_id[sid]["after"]):
                continue
            s = by_id[sid]
            rel_out = f"{state['_dir']}/{sid}.md"
            try:
                run = agents.start(ws_id, _expand(pid, s, state), agent=s["agent"], effort=s["effort"], timeout=s.get("timeout_seconds"),
                                   title=s.get("title") or f"[pipeline {pid}] {sid}", subject=subject, output_path=rel_out,
                                   browser_sites=s["browser_sites"] or None)
            except BridgeError as ex:
                if ex.code == "rate_limited":      # another caller holds a slot; try again next tick
                    break
                e.update({"status": "failed", "error_code": ex.code, "error": ex.message[:400], "end_ts": time.time()})
                continue
            e.update({"status": "running", "run_id": run["run_id"], "output": rel_out, "start_ts": time.time()})
            running += 1
        _save_state(pid, state)
        if all(e.get("status") not in ("pending", "running") for k, e in state.items() if not k.startswith("_")):
            break
        await asyncio.sleep(POLL_S)
    ok = all(_stage_ok(e, stop_on) for k, e in state.items() if not k.startswith("_"))
    _close(pid, "completed" if ok else "partial", subject)


def _close(pid: str, status: str, subject: str | None) -> None:
    r = _row(pid)
    if r["status"] not in STATUS_ACTIVE:
        return
    st = r["state"]
    lines = [f"# pipeline {pid} — {status}", "", f"workspace {r['workspace_id']} · started {time.strftime('%Y-%m-%d %H:%M', time.localtime(r['start_ts'] or r['created_at']))}", ""]
    summary = {"pipeline_id": pid, "status": status, "stages": {}}
    for s in r["spec"]["stages"]:
        e = st.get(s["id"], {})
        summary["stages"][s["id"]] = {k: e.get(k) for k in ("status", "task_status", "error_code", "run_id", "output", "conversation_url", "upstream_blocks_observed")}
        lines.append(f"- **{s['id']}** ({s['agent'] or 'no persona'}, {s['effort']}): {e.get('status')}"
                     + (f" / {e.get('task_status')}" if e.get("task_status") else "") + (f" — {e.get('error_code')}: {e.get('error')}" if e.get("error_code") else "")
                     + (f" → `{e.get('output')}`" if e.get("output") else "") + (f" · {e.get('conversation_url')}" if e.get("conversation_url") else ""))
    try:
        ws = workspace_get(r["workspace_id"])
        p = resolve_in_workspace(ws, f"{st['_dir']}/summary.md", must_exist=False)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        st["_summary_path"] = f"{st['_dir']}/summary.md"
    except (BridgeError, OSError) as e:
        st["_summary_error"] = str(e)[:200]
    _save_state(pid, st)
    db.q("UPDATE agent_pipelines SET status=?, end_ts=?, summary=? WHERE id=?", status, time.time(), json.dumps(summary, ensure_ascii=False), pid)
    from .state import inbox_put
    inbox_put(r["workspace_id"], "pipeline_finished", summary)
    db.audit("agent_pipeline_finished", f"{pid} {status}", subject=subject, workspace_id=r["workspace_id"])
