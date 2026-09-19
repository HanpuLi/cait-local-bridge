"""coding_task: the implement -> test -> fix loop that a coding agent (Codex / Claude Code) runs internally, executed here by the bridge
as a deterministic state machine. No model lives in this file: every "think" step is a sub-agent conversation in the user's own
chatgpt.com session (agents.start); every "verify" step is the project's real test command run by the bridge itself, whose exit code —
not the model's word — decides whether the task is done.

Shape of one task (all state in table coding_tasks, files under <repo>/.clb/<task_id>/):
  preflight   git repo check; `git worktree add .clb/<id>/wt -b clb/<slug>-<id>` from HEAD (the user's checkout is never switched)
  baseline    optional: run the test command once before any change, so a pre-existing failure is not blamed on the sub-agent
  round r     implement (r=1) or fix (r>1: reads round<r-1>-test.log) -> sub-agent conversation
              verify  -> test command in the worktree, exit 0 = verified, else the log becomes the next round's input
  commit      the bridge commits whatever changed on the task branch (deterministic message), writes diff.patch + summary.md, inbox entry
Terminal statuses: verified · unverified (no test command) · failed_tests (rounds exhausted) · blocked (OpenAI dropped the sub-agent's
calls) · failed · cancelled · interrupted · timeout. The branch and worktree stay for the user to inspect, merge or delete.
"""
from __future__ import annotations
import asyncio, json, re, shlex, subprocess, time, uuid
from pathlib import Path
from . import db, agents, jobs
from .config import load_config, JOB_PATH
from .policy import BridgeError, workspace_get, resolve_in_workspace

CFG = load_config()
POLL_S = float(CFG.get("coding_poll_seconds", 8))
STATUS_ACTIVE = ("queued", "running")
MAX_ROUNDS = int(CFG.get("coding_max_rounds", 6))
TASK_DIR = ".clb"
_GIT_ENV = {"PATH": JOB_PATH, "GIT_TERMINAL_PROMPT": "0", "LANG": "en_US.UTF-8", "HOME": str(Path.home())}

db.conn().executescript("""
CREATE TABLE IF NOT EXISTS coding_tasks(id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, status TEXT NOT NULL,
  created_at REAL NOT NULL, start_ts REAL, end_ts REAL, spec TEXT NOT NULL, state TEXT NOT NULL DEFAULT '{}', summary TEXT);
""")

_tasks: dict[str, asyncio.Task] = {}


# ---------- helpers ----------
def _slug(s: str, n: int = 28) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return (s[:n].rstrip("-") or "task")


def _git(cwd: Path, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout, env=_GIT_ENV)


def _row(tid: str) -> dict:
    r = db.one("SELECT * FROM coding_tasks WHERE id=?", tid)
    if not r:
        raise BridgeError("not_found", f"unknown coding task {tid}")
    d = dict(r); d["spec"] = json.loads(d["spec"]); d["state"] = json.loads(d["state"] or "{}")
    d["summary"] = json.loads(d["summary"]) if d["summary"] else None
    return d


def _save(tid: str, state: dict) -> None:
    db.q("UPDATE coding_tasks SET state=? WHERE id=?", json.dumps(state, ensure_ascii=False, default=str), tid)


def _bridge_calls_between(t0: float, t1: float) -> int:
    """Tool calls that actually reached the bridge in a window (all clients — the main session's own calls in that window count too)."""
    r = db.one("SELECT COUNT(*) c FROM audit WHERE tool='mcp.tool_received' AND ts>=? AND ts<=?", t0, t1)
    return int(r["c"]) if r else 0


def info(tid: str) -> dict:
    r = _row(tid)
    st = r["state"]
    rounds = []
    for e in st.get("rounds", []):
        row = dict(e)
        if e.get("run_id") and e.get("agent_status") == "running":
            try:
                live = agents.info(e["run_id"])
                row.update({"phase": live.get("phase"), "tool_calls": live.get("tool_calls"), "conversation_url": live.get("conversation_url")})
            except BridgeError:
                pass
        rounds.append(row)
    return {"task_id": tid, "workspace_id": r["workspace_id"], "status": r["status"], "step": st.get("_step"), "created_at": r["created_at"],
            "start_ts": r["start_ts"], "end_ts": r["end_ts"], "elapsed_s": round((r["end_ts"] or time.time()) - (r["start_ts"] or r["created_at"]), 1),
            "task": r["spec"]["task"], "repo_path": r["spec"]["repo_path"], "test_command": r["spec"]["test_command"], "max_rounds": r["spec"]["max_rounds"],
            "branch": st.get("branch"), "worktree": st.get("worktree"), "base_commit": st.get("base_commit"), "head_commit": st.get("head_commit"),
            "baseline": st.get("baseline"), "rounds": rounds, "commit": st.get("commit"), "diffstat": st.get("diffstat"),
            "task_dir": st.get("_dir"), "summary_path": st.get("_summary_path"), "error_code": st.get("_error_code"), "error": st.get("_error"),
            "metrics": st.get("metrics"), "summary": r["summary"], "attached": tid in _tasks}


def list_tasks(workspace_id: str | None = None, limit: int = 20) -> list[dict]:
    rows = db.all_("SELECT id FROM coding_tasks WHERE (?1 IS NULL OR workspace_id=?1) ORDER BY created_at DESC LIMIT ?2", workspace_id, limit)
    return [info(r["id"]) for r in rows]


# ---------- submit / cancel / recovery ----------
def start(workspace_id: str, task: str, repo_path: str = ".", test_command: str | list[str] | None = None, max_rounds: int = 3,
          effort: str = "extra_high", agent: str | None = None, profile: str | None = None, agent_timeout_seconds: int | None = None,
          test_timeout_seconds: int = 900, baseline: bool = True, branch: str | None = None, browser_sites: list[str] | None = None,
          notes: str | None = None, protected_paths: list[str] | None = None, subject: str | None = None) -> dict:
    ws = workspace_get(workspace_id)
    if not task or not task.strip():
        raise BridgeError("invalid_argument", "task is empty")
    if effort not in agents.EFFORTS + ["auto"]:
        raise BridgeError("invalid_argument", f"effort must be one of {agents.EFFORTS} or auto")
    if agent:
        agents.persona(agent)
    if not 1 <= int(max_rounds) <= MAX_ROUNDS:
        raise BridgeError("invalid_argument", f"max_rounds must be 1..{MAX_ROUNDS}")
    if isinstance(test_command, list):
        if not all(isinstance(x, str) for x in test_command) or not test_command:
            raise BridgeError("invalid_argument", "test_command list must be non-empty strings")
    elif test_command is not None and not isinstance(test_command, str):
        raise BridgeError("invalid_argument", "test_command must be a string (zsh) or argv list")
    if test_command is not None and not str(test_command).strip():
        test_command = None
    profile = profile or ("trusted-host" if "trusted-host" in ws["profiles"] else "sandboxed")
    if profile not in ws["profiles"]:
        raise BridgeError("permission_denied", f"profile {profile} is not granted on workspace {workspace_id}")
    repo = resolve_in_workspace(ws, repo_path)
    if not repo.is_dir():
        raise BridgeError("invalid_argument", f"repo_path is not a directory: {repo_path}")
    r = _git(repo, "rev-parse", "--show-toplevel")
    if r.returncode != 0:
        raise BridgeError("invalid_argument", f"{repo_path} is not inside a git repository (coding_task works on a branch): {r.stderr.strip()[:200]}")
    top = Path(r.stdout.strip())
    try:
        top.relative_to(Path(ws["root"]).resolve())
    except ValueError:
        raise BridgeError("permission_denied", f"the git repository containing {repo_path} lies outside the workspace root")
    protected = [str(x).strip().lstrip("./") for x in (protected_paths or []) if str(x).strip()]
    if any(".." in x or x.startswith("/") for x in protected):
        raise BridgeError("invalid_argument", "protected_paths must be plain paths relative to the repository root")
    if branch and not re.fullmatch(r"[A-Za-z0-9._/-]{1,80}", branch):
        raise BridgeError("invalid_argument", "branch must be a plain git branch name")
    tid = "task_" + uuid.uuid4().hex[:10]
    spec = {"task": task.strip(), "repo_path": repo_path, "repo_top": str(top), "test_command": test_command, "max_rounds": int(max_rounds), "effort": effort,
            "agent": agent, "profile": profile, "agent_timeout": int(agent_timeout_seconds or agents.DEFAULT_TIMEOUT), "test_timeout": int(test_timeout_seconds),
            "baseline": bool(baseline) and test_command is not None, "branch": branch or f"clb/{_slug(task)}-{tid[5:11]}", "browser_sites": browser_sites or [], "notes": notes, "protected_paths": protected}
    db.q("INSERT INTO coding_tasks(id,workspace_id,status,created_at,spec,state) VALUES(?,?,?,?,?,?)", tid, workspace_id, "queued", time.time(),
         json.dumps(spec, ensure_ascii=False), json.dumps({"_step": "queued", "rounds": []}))
    db.audit("coding_task", f"{tid} repo={repo_path} rounds<={max_rounds} test={'yes' if test_command else 'no'}", subject=subject, workspace_id=workspace_id)
    _tasks[tid] = asyncio.get_running_loop().create_task(_guard(tid, subject))
    return info(tid)


async def cancel(tid: str, subject: str | None = None) -> dict:
    r = _row(tid)
    if r["status"] not in STATUS_ACTIVE:
        return info(tid)
    t = _tasks.get(tid)
    if t:
        t.cancel()
    st = r["state"]
    for e in st.get("rounds", []):
        if e.get("agent_status") == "running" and e.get("run_id"):
            try:
                await agents.cancel(e["run_id"], subject)
            except BridgeError:
                pass
            e["agent_status"] = "cancelled"
        if e.get("test_job_id") and e.get("test_status") == "running":
            try:
                jobs.cancel(e["test_job_id"], subject)
            except BridgeError:
                pass
            e["test_status"] = "cancelled"
    _save(tid, st)
    _close(tid, "cancelled", subject)
    return info(tid)


def recover_on_startup() -> list[str]:
    notes = []
    for r in db.all_("SELECT id FROM coding_tasks WHERE status IN ('queued','running')"):
        st = _row(r["id"])["state"]
        st["_error_code"] = "interrupted"; st["_error"] = "bridge restarted while the task was running"
        for e in st.get("rounds", []):
            if e.get("agent_status") == "running":
                e["agent_status"] = "interrupted"
            if e.get("test_status") == "running":
                e["test_status"] = "interrupted"
        _save(r["id"], st)
        db.q("UPDATE coding_tasks SET status='interrupted', end_ts=? WHERE id=?", time.time(), r["id"])
        notes.append(r["id"])
    return notes


# ---------- prompts (human wording on purpose: see agents.compose) ----------
def _prompt(spec: dict, st: dict, rnd: int, ws_root: Path) -> str:
    wt = st["worktree"]
    test = spec["test_command"]
    test_line = (" ".join(shlex.quote(x) for x in test) if isinstance(test, list) else test) if test else None
    lines = [f"我要在仓库里完成一个改动。工作目录是工作区里的 `{wt}`（这是仓库的一个独立 worktree，分支 `{st['branch']}`，专门给这件事用的）——所有改动只放在这个目录里，不要碰它外面的文件，不要切分支，不要 commit，也不要 push，提交我自己来。",
             f"跑命令时 cwd 用 `{wt}`，profile 用 {spec['profile']}。为了少走弯路：先用 repo_outline 看一遍结构，改动尽量用 file_edit（精确替换），命令用 exec_run 一次拿到结果。"]
    if test_line:
        lines.append(f"验证命令是：`{test_line}`（在 `{wt}` 里跑）。改完必须自己跑一遍，跑到退出码为 0 才算完；把最后一次的输出原样贴在回复里。")
        b = st.get("baseline")
        if b and b.get("exit_code") not in (0, None):
            lines.append(f"注意：改之前我已经跑过这条验证命令，退出码 {b['exit_code']}（输出在 `{b['log']}`，可以先看一眼）——它现在就是失败的，任务就是让它通过。")
    else:
        lines.append("这个仓库没有给我验证命令，改完请自己想办法验证（能跑的就跑），把验证的过程和结果写在回复里。")
    if rnd > 1:
        prev = st["rounds"][rnd - 2]
        lines.append(f"这是第 {rnd} 轮。上一轮改完后我自己跑了验证命令，退出码 {prev.get('test_exit')}，还是失败；完整输出在 `{prev.get('test_log')}`，先读它再改。上一轮的改动已经在工作目录里（未提交），接着改就行。")
    if spec.get("protected_paths"):
        lines.append("这些文件是验收用的，不能改（改了我也会恢复原样再验证）：" + "、".join(f"`{x}`" for x in spec["protected_paths"]) + "。")
    if spec.get("notes"):
        lines += ["", "补充说明：", spec["notes"]]
    lines += ["", "要做的事：", spec["task"]]
    return "\n".join(lines)


# ---------- runner ----------
async def _wait_agent(run_id: str, timeout: int) -> dict:
    t0 = time.time()
    while True:
        live = agents.info(run_id)
        if live["status"] not in agents.STATUS_ACTIVE:
            return live
        if time.time() - t0 > timeout + 120:
            return {**live, "status": "timeout", "error_code": "timeout", "error": "sub-agent run overran its timeout"}
        await asyncio.sleep(POLL_S)


async def _run_test(ws_id: str, spec: dict, st: dict, label: str, subject: str | None) -> dict:
    """Run the test command in the worktree as a bridge job; the exit code is the verdict, the log file the next round's input."""
    j = jobs.start(ws_id, spec["profile"], spec["test_command"], st["worktree"], None, spec["test_timeout"], False, None, None, 120, 40, subject)
    jid = j["job_id"]
    while j["status"] in jobs.STATUS_ACTIVE:
        await asyncio.sleep(1.0)
        j = jobs.info(jid)
    out = jobs.logs(jid, "stdout", 0, 1_000_000)["text"]; err = jobs.logs(jid, "stderr", 0, 1_000_000)["text"]
    rel = f"{st['_dir']}/{label}-test.log"
    p = Path(st["_abs_dir"]) / f"{label}-test.log"
    p.write_text(f"$ {spec['test_command'] if isinstance(spec['test_command'], str) else ' '.join(spec['test_command'])}\n(cwd {st['worktree']}, exit {j['exit_code']}, "
                 f"{'timed out, ' if j['timed_out'] else ''}{round((j['end_ts'] or time.time()) - (j['start_ts'] or 0), 1)}s)\n\n--- stdout ---\n{out}\n--- stderr ---\n{err}\n", encoding="utf-8")
    return {"job_id": jid, "exit_code": j["exit_code"], "status": j["status"], "timed_out": j["timed_out"], "log": rel,
            "elapsed_s": round((j["end_ts"] or time.time()) - (j["start_ts"] or 0), 1), "tail": (out + err)[-1500:]}


def _restore_protected(wt: Path, spec: dict, st: dict) -> list[str]:
    """Put protected files (tests, fixtures) back to their base-commit content before verifying; returns what had been changed."""
    reverted = []
    for rel in spec.get("protected_paths") or []:
        r = _git(wt, "diff", "--quiet", st["base_commit"], "--", rel)
        untracked = _git(wt, "ls-files", "--others", "--exclude-standard", "--", rel).stdout.strip()
        if r.returncode != 0 or untracked:
            _git(wt, "checkout", st["base_commit"], "--", rel)
            if untracked:
                _git(wt, "clean", "-fdq", "--", rel)
            reverted.append(rel)
    return reverted


async def _guard(tid: str, subject: str | None) -> None:
    try:
        await _run(tid, subject)
    except asyncio.CancelledError:
        pass
    except BridgeError as e:
        st = _row(tid)["state"]; st["_error_code"] = e.code; st["_error"] = e.message[:400]; _save(tid, st)
        _close(tid, "failed", subject)
    except Exception as e:  # noqa: BLE001 - recorded, never silent
        st = _row(tid)["state"]; st["_error_code"] = "internal"; st["_error"] = f"{type(e).__name__}: {str(e)[:400]}"; _save(tid, st)
        _close(tid, "failed", subject)
    finally:
        _tasks.pop(tid, None)


async def _run(tid: str, subject: str | None) -> None:
    r = _row(tid)
    spec, ws_id, st = r["spec"], r["workspace_id"], r["state"]
    ws = workspace_get(ws_id); ws_root = Path(ws["root"]).resolve()
    top = Path(spec["repo_top"])
    db.q("UPDATE coding_tasks SET status='running', start_ts=? WHERE id=?", time.time(), tid)

    # -- preflight: task dir + worktree on a fresh branch (the user's checkout stays where it is)
    st["_step"] = "preflight"; _save(tid, st)
    abs_dir = top / TASK_DIR / tid
    abs_dir.mkdir(parents=True, exist_ok=True)
    excl = top / ".git" / "info" / "exclude"
    try:
        if excl.parent.is_dir() and (not excl.exists() or f"/{TASK_DIR}/" not in excl.read_text()):
            with open(excl, "a") as f:
                f.write(f"\n# Cait Local Bridge coding_task worktrees\n/{TASK_DIR}/\n")
    except OSError:
        pass
    head = _git(top, "rev-parse", "HEAD")
    if head.returncode != 0:
        raise BridgeError("invalid_argument", f"repository has no commits yet: {head.stderr.strip()[:200]}")
    wt_abs = abs_dir / "wt"
    r2 = _git(top, "worktree", "add", "-b", spec["branch"], str(wt_abs), "HEAD")
    if r2.returncode != 0:
        raise BridgeError("conflict", f"git worktree add failed: {(r2.stderr or r2.stdout).strip()[:400]}")
    st.update({"_dir": str(abs_dir.relative_to(ws_root)), "_abs_dir": str(abs_dir), "worktree": str(wt_abs.relative_to(ws_root)), "branch": spec["branch"],
               "base_commit": head.stdout.strip(), "base_branch": _git(top, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()})
    _save(tid, st)

    # -- baseline
    if spec["baseline"]:
        st["_step"] = "baseline"; _save(tid, st)
        st["baseline"] = await _run_test(ws_id, spec, st, "baseline", subject)
        _save(tid, st)

    # -- rounds
    final = "unverified" if not spec["test_command"] else "failed_tests"
    for rnd in range(1, spec["max_rounds"] + 1):
        e = {"round": rnd, "kind": "implement" if rnd == 1 else "fix", "agent_status": "starting", "start_ts": time.time()}
        st["rounds"].append(e); st["_step"] = f"round{rnd}:agent"; _save(tid, st)
        prompt = _prompt(spec, st, rnd, ws_root)
        (abs_dir / f"round{rnd}-prompt.md").write_text(prompt, encoding="utf-8")
        while True:
            try:
                run = agents.start(ws_id, prompt, agent=spec["agent"], effort=spec["effort"], timeout=spec["agent_timeout"], subject=subject,
                                   title=f"[task {tid}] round {rnd}", output_path=f"{st['_dir']}/round{rnd}.md", browser_sites=spec["browser_sites"] or None)
                break
            except BridgeError as ex:
                if ex.code != "rate_limited":
                    raise
                e["agent_status"] = "waiting_slot"; _save(tid, st)
                await asyncio.sleep(max(POLL_S, agents.throttled_for() or 0))
        e.update({"run_id": run["run_id"], "agent_status": "running"}); _save(tid, st)
        live = await _wait_agent(run["run_id"], spec["agent_timeout"])
        t_end = time.time()
        e.update({"agent_status": live["status"], "task_status": live.get("task_status"), "error_code": live.get("error_code"), "error": (live.get("error") or "")[:300] or None,
                  "conversation_url": live.get("conversation_url"), "tool_calls": live.get("tool_calls", 0), "upstream_blocks_observed": live.get("upstream_blocks_observed", 0),
                  "bridge_calls_in_window": _bridge_calls_between(e["start_ts"], t_end), "agent_elapsed_s": round(t_end - e["start_ts"], 1), "output": f"{st['_dir']}/round{rnd}.md"})
        _save(tid, st)
        if live["status"] in ("cancelled",):
            final = "cancelled"; break
        if live["status"] == "timeout" or live.get("error_code") == "timeout":
            final = "timeout"; break
        if live.get("task_status") == "blocked" or live.get("error_code") in ("upstream_blocked", "reported_safety_blocked"):
            final = "blocked"; break
        if live.get("task_status") == "needs_user_action" or live.get("error_code") == "needs_user_action":
            st["_error_code"] = "needs_user_action"; st["_error"] = "the sub-agent asked for the user's decision (see its output)"; final = "failed"; break
        poll_lost = live["status"] not in ("completed", "succeeded")
        if poll_lost:
            # the bridge could not read the conversation to its end (typically chatgpt.com HTTP 429 on the poll), but the sub-agent
            # may well have finished the work: the test command is the verdict, not the transcript (bench 2026-09-17: 2 of 5 runs
            # were reported failed this way while their worktrees passed the hidden tests)
            st["_error_code"] = live.get("error_code") or live["status"]; st["_error"] = (live.get("error") or "sub-agent run did not complete")[:300]
            e["warning"] = "conversation could not be read to the end; verifying the worktree anyway"
            final = "failed"
            if not spec["test_command"]:
                break
        elif not spec["test_command"]:
            final = "unverified"; break
        st["_step"] = f"round{rnd}:test"; e["test_status"] = "running"
        reverted = _restore_protected(wt_abs, spec, st)
        if reverted:
            e["protected_reverted"] = reverted
        _save(tid, st)
        t = await _run_test(ws_id, spec, st, f"round{rnd}", subject)
        e.update({"test_status": t["status"], "test_job_id": t["job_id"], "test_exit": t["exit_code"], "test_log": t["log"], "test_elapsed_s": t["elapsed_s"], "test_tail": t["tail"]})
        _save(tid, st)
        if t["exit_code"] == 0:
            final = "verified"
            if poll_lost:
                st["_error_code"] = None; st["_error"] = None
            break
        if poll_lost:
            break   # do not start another conversation on top of a poll failure (it would hit the same limit)

    # -- commit whatever the rounds produced, on the task branch only
    st["_step"] = "commit"; _save(tid, st)
    status_out = _git(wt_abs, "status", "--porcelain").stdout
    if status_out.strip():
        _git(wt_abs, "add", "-A")
        msg = f"clb: {spec['task'].splitlines()[0][:70]}\n\ncoding_task {tid} · rounds={len(st['rounds'])} · tests={final}\n"
        c = _git(wt_abs, "-c", "user.name=Cait Local Bridge", "-c", "user.email=bridge@local", "commit", "-q", "-m", msg)
        st["commit"] = {"ok": c.returncode == 0, "output": (c.stdout + c.stderr).strip()[-300:]}
    else:
        st["commit"] = {"ok": False, "output": "no changes in the worktree"}
    st["head_commit"] = _git(wt_abs, "rev-parse", "HEAD").stdout.strip()
    st["diffstat"] = _git(wt_abs, "diff", "--stat", f"{st['base_commit']}..HEAD").stdout.strip()[-3000:]
    (abs_dir / "diff.patch").write_text(_git(wt_abs, "diff", f"{st['base_commit']}..HEAD").stdout, encoding="utf-8")
    st["metrics"] = {"rounds": len(st["rounds"]), "agent_tool_calls": sum(e.get("tool_calls") or 0 for e in st["rounds"]),
                     "bridge_calls_in_windows": sum(e.get("bridge_calls_in_window") or 0 for e in st["rounds"]),
                     "upstream_blocks_observed": sum(e.get("upstream_blocks_observed") or 0 for e in st["rounds"]),
                     "agent_seconds": round(sum(e.get("agent_elapsed_s") or 0 for e in st["rounds"]), 1),
                     "test_seconds": round(sum(e.get("test_elapsed_s") or 0 for e in st["rounds"]) + ((st.get("baseline") or {}).get("elapsed_s") or 0), 1)}
    _save(tid, st)
    _close(tid, final, subject)


def _close(tid: str, status: str, subject: str | None) -> None:
    r = _row(tid)
    if r["status"] not in STATUS_ACTIVE:
        return
    st, spec = r["state"], r["spec"]
    lines = [f"# coding_task {tid} — {status}", "", f"**task:** {spec['task']}", "",
             f"workspace {r['workspace_id']} · repo `{spec['repo_path']}` · branch `{st.get('branch')}` · worktree `{st.get('worktree')}`",
             f"base {st.get('base_commit', '')[:10]} → head {st.get('head_commit', '')[:10]} · test: `{spec['test_command'] or '(none)'}`", ""]
    b = st.get("baseline")
    if b:
        lines.append(f"- baseline: exit {b.get('exit_code')} ({b.get('elapsed_s')}s) → `{b.get('log')}`")
    for e in st.get("rounds", []):
        lines.append(f"- round {e['round']} ({e['kind']}): agent {e.get('agent_status')}/{e.get('task_status') or '-'} in {e.get('agent_elapsed_s')}s, "
                     f"{e.get('tool_calls', 0)} tool calls seen, {e.get('bridge_calls_in_window', 0)} reached the bridge, {e.get('upstream_blocks_observed', 0)} dropped upstream"
                     + (f"; tests exit {e.get('test_exit')} ({e.get('test_elapsed_s')}s) → `{e.get('test_log')}`" if e.get("test_log") else "")
                     + (f" · {e.get('conversation_url')}" if e.get("conversation_url") else "") + (f" — {e.get('error_code')}: {e.get('error')}" if e.get("error_code") else ""))
    if st.get("_error"):
        lines.append(f"- error: {st.get('_error_code')}: {st.get('_error')}")
    if st.get("commit"):
        lines += ["", f"commit: {st['commit'].get('output')}", "", "```", st.get("diffstat") or "(no diff)", "```"]
    lines += ["", f"next: `git -C <repo> log {st.get('base_commit', '')[:10]}..{st.get('branch')}` · merge with `git merge {st.get('branch')}` · "
              f"discard with `git worktree remove {st.get('worktree')} && git branch -D {st.get('branch')}`"]
    summary = {"task_id": tid, "status": status, "branch": st.get("branch"), "worktree": st.get("worktree"), "head_commit": st.get("head_commit"),
               "rounds": [{k: e.get(k) for k in ("round", "kind", "agent_status", "task_status", "test_exit", "tool_calls", "bridge_calls_in_window", "upstream_blocks_observed", "conversation_url")} for e in st.get("rounds", [])],
               "metrics": st.get("metrics"), "error_code": st.get("_error_code")}
    try:
        p = Path(st["_abs_dir"]) / "summary.md"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        st["_summary_path"] = f"{st['_dir']}/summary.md"
    except (KeyError, OSError) as e:
        st["_summary_error"] = str(e)[:200]
    st["_step"] = "done"
    _save(tid, st)
    db.q("UPDATE coding_tasks SET status=?, end_ts=?, summary=? WHERE id=?", status, time.time(), json.dumps(summary, ensure_ascii=False), tid)
    from .state import inbox_put
    inbox_put(r["workspace_id"], "coding_task_finished", summary)
    db.audit("coding_task_finished", f"{tid} {status}", subject=subject, workspace_id=r["workspace_id"])
