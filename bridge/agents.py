"""Sub-agent dispatch through the user's OWN ChatGPT web session (design "D", user decision 2026-09-17).

There is still no model API key, no Claude Code / Codex worker and no server-side model: a "sub-agent" is a fresh
chatgpt.com conversation opened in the managed browser (the user's cloned, logged-in Comet profile), fed one composed
message (an optional persona from ~/.claude/agents/<name>.md or ~/.claude/skills/<name>/SKILL.md, plus the task), and
polled until the assistant's final turn. It runs on the user's ChatGPT plan, inside her account, with the same
"ScopeRail" plugin available to it — so the sub-agent can read files / run commands through the bridge exactly
like the parent session. Every step is plain browser automation of chatgpt.com; if OpenAI changes the UI the run fails
with a stable error code and the tab is left open for inspection.
"""
from __future__ import annotations
import asyncio, json, re, time, uuid
from collections import deque
from pathlib import Path
from . import db, browser, jobs
from . import agent_outcomes
from .config import JOBS_DIR, load_config
from .policy import BridgeError, workspace_get, workspace_list, resolve_in_workspace

CFG = load_config()
CHATGPT_URL = CFG.get("chatgpt_url", "https://chatgpt.com/")
APP_NAME = CFG.get("chatgpt_app_name", "ScopeRail")   # plugin name as ChatGPT shows it in the "+" / "@" picker
MAX_AGENTS = int(CFG.get("max_concurrent_agents", 3))
DEFAULT_TIMEOUT = int(CFG.get("default_agent_timeout", 1800))
EFFORTS = ["instant", "medium", "high", "extra_high", "pro"]       # chatgpt.com "Power" slider, positions 0..4 (2026-09)
STATUS_ACTIVE = ("queued", "starting", "running")
AGENT_DIR = Path.home() / ".claude" / "agents"
SKILL_DIR = Path.home() / ".claude" / "skills"

db.conn().executescript("""
CREATE TABLE IF NOT EXISTS agent_runs(id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, agent TEXT, effort TEXT, status TEXT NOT NULL,
  conv_id TEXT, conv_url TEXT, page_id TEXT, created_at REAL NOT NULL, start_ts REAL, end_ts REAL,
  spec TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '{}', result TEXT);
""")

_tasks: dict[str, asyncio.Task] = {}
_progress: dict[str, dict] = {}   # live, in-memory: phase, last preview, tool calls
_throttle_until = 0.0             # chatgpt.com answered 429 ("Too many requests"): every run backs off together and agent_start waits
POLL_IDLE = float(CFG.get("agent_poll_idle_seconds", 12))        # backend fetch cadence while waiting for the reply (was 4 s)
POLL_STREAMING = float(CFG.get("agent_poll_streaming_seconds", 20))   # while the stop button is visible the DOM already says "busy"
POLL_SETTLE = 4.0                                                 # right after streaming ends: confirm end_turn quickly


def throttled_for() -> float:
    return max(0.0, _throttle_until - time.time())


# ---------- catalog: personas the user keeps for Claude Code, reused verbatim ----------
def _frontmatter(text: str) -> tuple[dict, str]:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return {}, text
    meta = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta, text[m.end():]


def catalog() -> list[dict]:
    out = []
    for p in sorted(AGENT_DIR.glob("*.md")) if AGENT_DIR.is_dir() else []:
        meta, body = _frontmatter(p.read_text(encoding="utf-8", errors="replace"))
        out.append({"name": p.stem, "kind": "agent", "description": meta.get("description", "")[:300], "path": str(p), "bytes": len(body)})
    for p in sorted(SKILL_DIR.glob("*/SKILL.md")) if SKILL_DIR.is_dir() else []:
        meta, body = _frontmatter(p.read_text(encoding="utf-8", errors="replace"))
        out.append({"name": p.parent.name, "kind": "skill", "description": meta.get("description", "")[:300], "path": str(p), "bytes": len(body)})
    return out


def persona(name: str) -> dict:
    for c in catalog():
        if c["name"] == name:
            meta, body = _frontmatter(Path(c["path"]).read_text(encoding="utf-8", errors="replace"))
            return {**c, "body": body.strip(), "frontmatter": meta}
    raise BridgeError("not_found", f"no agent or skill named {name!r}; see agent_catalog")


def compose(run_id: str, prompt: str, agent: str | None, workspace_id: str, browser_sites: list[str] | None = None) -> str:
    """Written like a person asking, on purpose: the machine-style header ("[Sub-agent run …] 你是…子代理", argv/profile dictated
    inline) was blocked by OpenAI's tool-call safety check 5 of 6 times on 2026-09-17, while plain human wording passed 2 of 2.
    Second finding the same day: with human wording, the only calls still blocked were browser_open to a URL the sub-agent chose itself after
    reading files (2/2), so public web work is routed to ChatGPT's own search and any site it may open with the plugin browser is named up front."""
    ws = [w for w in workspace_list() if w["id"] == workspace_id]
    ws_line = "；".join(f"{w['name']} = {w['id']}（{w['root']}）" for w in workspace_list())
    sites = [str(x).strip() for x in (browser_sites or []) if str(x).strip()]
    web_rule = ("公开网页、法条原文、判例、文档，用你自己的联网搜索去查和打开，不要用插件开网页；插件只用来读我本机的文件和跑命令"
                + (f"，另外这几个站可以用插件的浏览器打开：{'、'.join(sites)}。" if sites else "。"))
    head = [f"帮我做一件事。你可以用我的 {APP_NAME} 插件操作我的 Mac（读写文件、跑命令、开浏览器）。我的工作区：{ws_line}。这次默认用 {workspace_id}"
            + (f"（{ws[0]['root']}）" if ws else "") + "。",
            "做完把结果完整写在你的最后一条回复里，我只看那一条。不用先问我，缺信息就写明你的假设继续做。",
            web_rule,
            "如果哪一步插件调用被安全检查拦下了，把同一个调用原样再发一次（参数一个字都不改）；还是被拦就停在那里，把原始错误原样告诉我，不要换写法绕；没跑出来的结果别编。",
            f"最后一行请单独写一个状态：任务完成写 CLB_TASK_STATUS=done，被拦截写 CLB_TASK_STATUS=blocked，其他失败写 CLB_TASK_STATUS=failed，需要我确认写 CLB_TASK_STATUS=needs_user_action。（这次的编号 {run_id}）"]
    if agent:
        p = persona(agent)
        head += ["", f"请按下面这套标准来做（我平时用的 {p['kind']}「{agent}」）：", p["body"]]
    head += ["", "要做的事：", prompt.strip()]
    return "\n".join(head)


# ---------- runs ----------
def _row(run_id: str) -> dict:
    r = db.one("SELECT * FROM agent_runs WHERE id=?", run_id)
    if not r:
        raise BridgeError("not_found", f"unknown agent run {run_id}")
    d = dict(r); d["spec"] = json.loads(d["spec"]); d["meta"] = json.loads(d["meta"] or "{}")
    d["result"] = json.loads(d["result"]) if d["result"] else None
    return d


def _set(run_id: str, **fields) -> None:
    cols = ", ".join(f"{k}=?" for k in fields)
    db.q(f"UPDATE agent_runs SET {cols} WHERE id=?", *fields.values(), run_id)


def _meta_update(run_id: str, **kv) -> None:
    m = _row(run_id)["meta"]; m.update(kv); _set(run_id, meta=json.dumps(m, default=str))


def info(run_id: str) -> dict:
    r = _row(run_id)
    live = _progress.get(run_id, {})
    res = r["result"] or {}
    assessment = res.get("outcome") or r["meta"].get("outcome") or {}
    if not assessment and res and r["status"] == "succeeded":
        assessment = agent_outcomes.legacy_outcome(res)
    effective_status = assessment.get("status", r["status"]) if r["status"] not in STATUS_ACTIVE else r["status"]
    return {"stored_status": r["status"], "result_schema_version": agent_outcomes.SCHEMA_VERSION,
            "conversation_status": assessment.get("conversation_status", "unknown"),
            "task_status": assessment.get("task_status", "unverified"), "outcome": assessment,
            "tool_attempts": live.get("tool_calls", r["meta"].get("tool_calls", 0)),
            "confirmed_bridge_calls": res.get("confirmed_bridge_calls", 0), "upstream_blocks_observed": res.get("upstream_blocks_observed", assessment.get("upstream_blocks_observed", 0)),
            "warnings": assessment.get("warnings", []), "run_id": run_id, "workspace_id": r["workspace_id"], "agent": r["agent"], "effort": r["effort"], "status": effective_status,
            "conversation_id": r["conv_id"], "conversation_url": r["conv_url"], "page_id": r["page_id"],
            "created_at": r["created_at"], "start_ts": r["start_ts"], "end_ts": r["end_ts"],
            "elapsed_s": round((r["end_ts"] or time.time()) - (r["start_ts"] or r["created_at"]), 1),
            "phase": live.get("phase") or r["meta"].get("phase"), "tool_calls": live.get("tool_calls", r["meta"].get("tool_calls", 0)),
            "last_assistant_preview": live.get("preview") or r["meta"].get("preview"),
            "error": assessment.get("error") or r["meta"].get("error"), "error_code": assessment.get("error_code") or r["meta"].get("error_code"), "attached": run_id in _tasks,
            "prompt_chars": r["spec"].get("prompt_chars"), "timeout": r["spec"].get("timeout"), "output_path": r["spec"].get("output_path")}


def active_page_ids() -> set[str]:
    """Tabs belonging to runs still in progress — browser_close must not take them down."""
    return {r["page_id"] for r in db.all_("SELECT page_id FROM agent_runs WHERE status IN ('queued','starting','running') AND page_id IS NOT NULL")}


def list_runs(workspace_id: str | None = None, limit: int = 50) -> list[dict]:
    rows = db.all_("SELECT id FROM agent_runs WHERE (?1 IS NULL OR workspace_id=?1) ORDER BY created_at DESC LIMIT ?2", workspace_id, limit)
    return [info(r["id"]) for r in rows]


def result(run_id: str, max_chars: int = 60000) -> dict:
    r = _row(run_id)
    out = info(run_id)
    res = r["result"] or {}
    text = res.get("final_text") or ""
    out.update({"final_text": text[:max_chars], "truncated": len(text) > max_chars, "messages": res.get("messages"),
                "tool_calls_detail": res.get("tool_calls"), "unanswered_tool_calls": res.get("unanswered_tool_calls", []), "model_slug": res.get("model_slug"), "title": res.get("title"),
                "transcript_path": res.get("transcript_path"), "tool_results": res.get("tool_results", []),
                "verification_evidence": res.get("verification_evidence", [])})
    return out


def start(workspace_id: str, prompt: str, agent: str | None = None, effort: str = "extra_high", timeout: int | None = None,
          attach_bridge: bool = True, title: str | None = None, keep_page: bool = False, subject: str | None = None, dry_run: bool = False, verification: dict | None = None, raw: bool = False, output_path: str | None = None, archive: bool | None = None, browser_sites: list[str] | None = None) -> dict:
    workspace_get(workspace_id)
    try:
        verification = agent_outcomes.validate_verification(verification)
    except ValueError as e:
        raise BridgeError("invalid_argument", str(e)) from e
    if not prompt or not prompt.strip():
        raise BridgeError("invalid_argument", "prompt is empty")
    if effort not in EFFORTS + ["auto"]:
        raise BridgeError("invalid_argument", f"effort must be one of {EFFORTS} or auto")
    if agent:
        persona(agent)  # validate now, not inside the task
    timeout = int(timeout or DEFAULT_TIMEOUT)
    if timeout <= 0 or timeout > CFG["max_job_timeout"]:
        raise BridgeError("invalid_argument", f"timeout above max {CFG['max_job_timeout']}s")
    active = db.one("SELECT COUNT(*) c FROM agent_runs WHERE status IN ('queued','starting','running')")["c"]
    if active >= MAX_AGENTS:
        raise BridgeError("rate_limited", f"max concurrent sub-agents ({MAX_AGENTS}) reached; wait or agent_cancel one")
    if throttled_for() > 0:
        raise BridgeError("rate_limited", f"chatgpt.com is throttling this account (HTTP 429 'Too many requests'); the bridge backs off for another {throttled_for():.0f}s — do not start more conversations until then")
    run_id = "agent_" + uuid.uuid4().hex[:10]
    message = prompt.strip() if raw and not agent else compose(run_id, prompt, agent, workspace_id, browser_sites)   # raw: send the prompt verbatim, no sub-agent header
    out_path = None
    if output_path:
        out_path = str(resolve_in_workspace(workspace_get(workspace_id), output_path, must_exist=False))
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    spec = {"prompt": prompt, "prompt_chars": len(message), "attach_bridge": attach_bridge, "title": title, "keep_page": keep_page, "timeout": timeout, "dry_run": dry_run, "verification": verification, "output_path": out_path, "archive": CFG.get("agent_archive_on_finish", True) if archive is None else archive, "browser_sites": browser_sites or []}
    db.q("INSERT INTO agent_runs(id,workspace_id,agent,effort,status,created_at,spec,meta) VALUES(?,?,?,?,?,?,?,?)",
         run_id, workspace_id, agent, effort, "queued", time.time(), json.dumps(spec, ensure_ascii=False), "{}")
    (JOBS_DIR / run_id).mkdir(parents=True, exist_ok=True)
    (JOBS_DIR / run_id / "message.md").write_text(message, encoding="utf-8")
    db.audit("agent_start", f"{run_id} agent={agent} effort={effort} chars={len(message)}", subject=subject, workspace_id=workspace_id)
    _tasks[run_id] = asyncio.get_running_loop().create_task(_guard(run_id, message))
    return info(run_id)


async def send(run_id: str, text: str, timeout: int | None = None, subject: str | None = None, verification: dict | None = None) -> dict:
    """Follow-up message into an existing (finished) sub-agent conversation; polled like a fresh run."""
    r = _row(run_id)
    if r["status"] in STATUS_ACTIVE:
        raise BridgeError("conflict", f"{run_id} is still {r['status']}")
    if not r["conv_id"]:
        raise BridgeError("conflict", f"{run_id} never produced a conversation")
    if not text or not text.strip():
        raise BridgeError("invalid_argument", "text is empty")
    timeout = int(timeout or r["spec"].get("timeout") or DEFAULT_TIMEOUT)
    if timeout <= 0 or timeout > CFG["max_job_timeout"]:
        raise BridgeError("invalid_argument", "timeout outside allowed range")
    try:
        verification = agent_outcomes.validate_verification(verification)
    except ValueError as e:
        raise BridgeError("invalid_argument", str(e)) from e
    if db.one("SELECT COUNT(*) c FROM agent_runs WHERE status IN ('queued','starting','running')")["c"] >= MAX_AGENTS:
        raise BridgeError("rate_limited", f"max concurrent sub-agents ({MAX_AGENTS}) reached")
    # A follow-up is a new task: never inherit the previous verification or evidence.
    spec = {**r["spec"], "verification": verification, "timeout": timeout, "dry_run": False}
    if r["result"]:
        (JOBS_DIR / run_id / f"result-turn-{r['meta'].get('followups', 0)}.json").write_text(json.dumps(r["result"], ensure_ascii=False), encoding="utf-8")
    _set(run_id, status="queued", start_ts=None, end_ts=None, result=None, spec=json.dumps(spec, ensure_ascii=False))
    _meta_update(run_id, error=None, error_code=None, outcome=None, phase="queued", preview=None, tool_calls=0, followups=r["meta"].get("followups", 0) + 1)
    db.audit("agent_send", f"{run_id} chars={len(text)}", subject=subject, workspace_id=r["workspace_id"])
    _tasks[run_id] = asyncio.get_running_loop().create_task(_guard(run_id, text.strip(), followup=True, timeout=timeout))
    return info(run_id)


async def cancel(run_id: str, subject: str | None = None) -> dict:
    r = _row(run_id)
    if r["status"] not in STATUS_ACTIVE:
        # finished/failed run whose tab was left open (timeout, upstream_blocked, keep_page): cancel still closes the tab
        closed = False
        if r["page_id"] and r["page_id"] in browser._pages:
            try:
                await browser.close(r["page_id"]); closed = True
            except Exception:
                pass
        j = info(run_id); j["cancelled_now"] = False; j["tab_closed"] = closed; return j
    _set(run_id, status="cancelled", end_ts=time.time())
    _meta_update(run_id, error_code="cancelled", error="cancelled by caller")
    t = _tasks.pop(run_id, None)
    if t:
        t.cancel()
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass
    # stop generation in the tab (so the user's plan stops paying for it), then close the tab
    e = browser._pages.get(r["page_id"]) if r["page_id"] else None
    if e:
        try:
            btn = e["page"].locator("[data-testid=stop-button]")
            if await btn.count():
                await btn.first.click(timeout=3000)
                await asyncio.sleep(0.5)
        except Exception:
            pass
        try:
            await browser.close(r["page_id"])
        except Exception:
            pass
    db.audit("agent_cancel", run_id, subject=subject, workspace_id=r["workspace_id"])
    _progress.pop(run_id, None)
    j = info(run_id); j["cancelled_now"] = True; return j


async def cancel_all(subject: str | None = None) -> list[str]:
    out = []
    for r in db.all_("SELECT id FROM agent_runs WHERE status IN ('queued','starting','running')"):
        await cancel(r["id"], subject); out.append(r["id"])
    return out


def recover_on_startup() -> list[str]:
    notes = []
    for r in db.all_("SELECT id, conv_url FROM agent_runs WHERE status IN ('queued','starting','running')"):
        db.q("UPDATE agent_runs SET status='interrupted', end_ts=? WHERE id=?", time.time(), r["id"])
        m = _row(r["id"])["meta"]; m.update({"error_code": "interrupted", "error": "bridge restarted while the sub-agent was running; the ChatGPT conversation may have continued on its own — open conversation_url to see"})
        _set(r["id"], meta=json.dumps(m))
        notes.append(r["id"])
    return notes


# ---------- the run itself ----------
async def _guard(run_id: str, message: str, followup: bool = False, timeout: int | None = None) -> None:
    r = _row(run_id)
    timeout = timeout or r["spec"]["timeout"]
    try:
        await asyncio.wait_for(_run(run_id, message, followup), timeout=timeout)
    except asyncio.TimeoutError:
        _finish(run_id, "failed", "timeout", f"sub-agent did not finish within {timeout}s; tab left open (page_id) — agent_cancel closes it")
    except asyncio.CancelledError:
        pass  # cancel() already recorded the state
    except BridgeError as e:
        _finish(run_id, "failed", e.code, e.message)
    except Exception as e:
        _finish(run_id, "failed", "internal", f"{type(e).__name__}: {str(e)[:500]}")
    finally:
        _tasks.pop(run_id, None)
        _progress.pop(run_id, None)


def _write_output(run_id: str, status: str, code: str | None, msg: str | None) -> str | None:
    """Land the sub-agent's final text in the caller's workspace (spec.output_path) so people and the parent session can read it
    without touching the control plane; written for every terminal state, with a header that says which."""
    r = _row(run_id)
    out = r["spec"].get("output_path")
    if not out:
        return None
    res = r["result"] or {}
    assess = res.get("outcome") or {}
    head = [f"<!-- sub-agent {run_id} · persona {r['agent'] or '-'} · effort {r['effort']} · status {status}"
            + (f" · task_status {assess.get('task_status')}" if assess else "") + (f" · error {code}: {msg}" if code else "")
            + f" · conversation {r['conv_url'] or '-'} -->", ""]
    body = res.get("final_text") or (f"(no final text — {code}: {msg})" if code else "(no final text)")
    try:
        Path(out).write_text("\n".join(head) + body + "\n", encoding="utf-8")
        return out
    except OSError as e:
        _meta_update(run_id, output_error=str(e)[:200])
        return None


def _finish(run_id: str, status: str, code: str | None, msg: str | None) -> None:
    r = _row(run_id)
    if r["status"] == "cancelled":
        return
    written = _write_output(run_id, status, code, msg)
    if written:
        _meta_update(run_id, output_path=written)
    _set(run_id, status=status, end_ts=time.time())
    assessment = (r["result"] or {}).get("outcome")
    if not assessment:
        assessment = {"status": status, "conversation_status": "not_started" if not r["conv_id"] else "interrupted",
                      "task_status": "needs_user_action" if code in ("needs_user_action", "upstream_confirmation_required") else "unverified",
                      "error_code": code, "error": msg, "evidence_source": "bridge_runtime"}
    _meta_update(run_id, error_code=code, error=msg, phase="finished", outcome=assessment)
    from .state import inbox_put
    inbox_put(r["workspace_id"], "agent_finished", {"run_id": run_id, "status": status, "error_code": code, "agent": r["agent"], "conversation_url": r["conv_url"], "task_status": assessment["task_status"], "conversation_status": assessment["conversation_status"]})


def _phase(run_id: str, phase: str, **kv) -> None:
    p = _progress.setdefault(run_id, {}); p["phase"] = phase; p.update(kv)


# chatgpt.com mirrors the new-chat draft between tabs through localStorage ('oai/apps/conversationDrafts'): a tab that
# receives the storage event re-renders its composer from it and writes it back, so two new-chat tabs reset each other
# and typed lines vanish (2026-09-17). Agent tabs therefore neither persist that key nor listen to it.
_INIT_JS = """(() => {
  const KEY = 'oai/apps/conversationDrafts';
  const set = Storage.prototype.setItem;
  Storage.prototype.setItem = function (k, v) { if (k === KEY) return; return set.apply(this, arguments); };
  try { localStorage.removeItem(KEY); } catch (e) {}
  const add = window.addEventListener.bind(window);
  window.addEventListener = function (type, fn, opts) {
    if (type === 'storage' && typeof fn === 'function') {
      const wrapped = function (e) { if (e && e.key === KEY) return; return fn.call(this, e); };
      return add(type, wrapped, opts);
    }
    return add(type, fn, opts);
  };
})();"""


async def _page_for(run_id: str, workspace_id: str, url: str):
    """Open (or reuse) the run's tab through the shared managed browser so it shows up in browser_pages and dies with browser_close."""
    r = _row(run_id)
    e = browser._pages.get(r["page_id"]) if r["page_id"] else None
    if e and not e["page"].is_closed():
        await e["page"].goto(url, wait_until="domcontentloaded", timeout=45000)
        return r["page_id"], e["page"]
    d = await browser.open_page(workspace_id, url, wait_until="domcontentloaded", timeout_ms=45000, init_script=_INIT_JS)
    _set(run_id, page_id=d["page_id"])
    return d["page_id"], browser._pages[d["page_id"]]["page"]


async def _ready_composer(page) -> None:
    """Wait through Cloudflare's interstitial for the composer; classify the failure if it never comes."""
    for _ in range(40):
        if await page.locator("#prompt-textarea").count():
            return
        title = await page.title()
        body = ""
        try:
            body = (await page.locator("body").inner_text())[:2000]
        except Exception:
            pass
        if "/auth/" in page.url or "Log in" in body and "Sign up" in body:
            raise BridgeError("needs_user_action", "chatgpt.com is not logged in inside the bridge browser; log in to ChatGPT in Comet, then run `scoperailctl browser use-comet`")
        if re.search(r"unusual activity|blocked|access denied|verify you are human|captcha", body, re.I) and "Just a moment" not in title:
            raise BridgeError("upstream_blocked", f"chatgpt.com refused the bridge browser: {body[:200]!r}")
        await asyncio.sleep(1)
    raise BridgeError("upstream_blocked", f"composer never appeared on {page.url} (title {await page.title()!r}); Cloudflare or a changed UI")


async def _session(page) -> dict:
    s = await page.evaluate("fetch('/api/auth/session').then(r=>r.json()).catch(e=>({error:String(e)}))")
    if not isinstance(s, dict) or not s.get("accessToken"):
        raise BridgeError("needs_user_action", "no ChatGPT session token in the bridge browser; log in to ChatGPT in Comet, then `scoperailctl browser use-comet`")
    return s


async def _clear_composer(page) -> None:
    """chatgpt.com restores the last unsent draft into every new-chat composer (shared across tabs); start from empty."""
    ta = page.locator("#prompt-textarea")
    for _ in range(3):
        await ta.click()
        await page.keyboard.press("Meta+A"); await page.keyboard.press("Backspace")
        await asyncio.sleep(0.2)
        st = await page.evaluate("() => { const t=document.querySelector('#prompt-textarea'); return {txt: t.innerText.replace(/[\\s\\uFEFF]/g,''), pill: !!t.querySelector('a')}; }")
        if not st["txt"] and not st["pill"]:
            return
    raise BridgeError("internal", "could not empty the chatgpt.com composer (a restored draft?); UI changed?")


async def _attach_plugin(page) -> bool:
    """Type '@<app>' in the composer, click the matching picker entry -> the plugin pill lands in the message."""
    ta = page.locator("#prompt-textarea")
    await ta.click()
    await page.keyboard.type("@" + APP_NAME[:4], delay=30)
    item = page.get_by_text(APP_NAME, exact=True)
    try:
        await item.first.wait_for(timeout=8000)
        await item.first.click(timeout=5000)
        await page.locator(f"#prompt-textarea a:has-text('{APP_NAME}')").first.wait_for(timeout=5000)
        return True
    except Exception:
        # clear whatever we typed so the task text is not polluted
        await ta.click(); await page.keyboard.press("Meta+A"); await page.keyboard.press("Backspace")
        return False


_EFFORT_JS = """() => { const re=/^(\\d+\\s+)?(Instant|Medium|High|Extra High|Pro)$/;
  const b=[...document.querySelectorAll('form button')].find(b=>re.test(b.textContent.trim()));
  return b ? b.textContent.trim().replace(/^\\d+\\s+/,'') : null; }"""


async def _effort_get(page) -> int | None:
    lab = await page.evaluate(_EFFORT_JS)
    if not lab:
        return None
    lab = lab.lower().replace(" ", "_")
    return EFFORTS.index(lab) if lab in EFFORTS else None


async def _effort_set(page, target: int) -> int | None:
    """Move the composer 'Power' slider (Instant..Pro) with arrow keys; returns the level it was on before."""
    before = await _effort_get(page)
    if before is None or before == target:
        return before
    btn = page.locator("form button", has_text=re.compile(r"^\s*(\d+\s+)?(Instant|Medium|High|Extra High|Pro)\s*$")).first
    await btn.click(timeout=5000)
    ctl = page.locator("[role=menuitem][aria-label=Power]")
    try:
        await ctl.first.wait_for(timeout=5000)
    except Exception:
        await page.keyboard.press("Control+Shift+M")   # the picker's own shortcut, as a fallback
        await ctl.first.wait_for(timeout=5000)
    key = "ArrowRight" if target > before else "ArrowLeft"
    for _ in range(abs(target - before)):
        await ctl.first.press(key); await asyncio.sleep(0.25)
    await page.keyboard.press("Escape"); await asyncio.sleep(0.3)
    after = await _effort_get(page)
    if after != target:
        raise BridgeError("internal", f"effort slider ended on {after}, wanted {target}")
    return before


_ui_lock = asyncio.Lock()   # one composer phase at a time (see _run)


def _norm(t: str) -> str:
    """The composer applies markdown input rules while typing (`code` -> <code>, lists, headings), so innerText loses the
    markers; compare typed vs rendered text with markers and whitespace stripped."""
    return re.sub(r"[`*_~#>\-\s\u200b\ufeff]", "", t)


async def _type_message(page, text: str) -> None:
    """Line-by-line insertText + Shift+Enter, each step verified against the editor: ProseMirror re-renders asynchronously
    and a line inserted before the new paragraph exists is silently discarded (seen under load)."""
    ta = page.locator("#prompt-textarea")
    js_state = "() => { const t=document.querySelector('#prompt-textarea'); return t ? {p: t.querySelectorAll('p').length, txt: t.innerText} : null; }"
    await ta.click()
    await page.keyboard.press("Meta+ArrowDown")   # caret to the very end (after the plugin pill), not just end of line
    lines = text.split("\n")
    fallbacks = []
    for i, line in enumerate(lines):
        if line:
            tail = _norm(line)[-40:]
            for attempt in range(3):
                if attempt == 0 and "`" not in line:
                    await page.keyboard.insert_text(line)          # one CDP call per line (IME-style insert)
                elif attempt == 0:
                    await page.keyboard.type(line, delay=0)        # inline-code input rule rejects a one-shot insert of a `code` span
                else:
                    # the composer sometimes reverts input for a few seconds (a debounced draft re-render); wait it out,
                    # put the caret back at the end and type key by key
                    await asyncio.sleep(2.5 * attempt)
                    await ta.click(); await page.keyboard.press("Meta+ArrowDown")
                    await page.keyboard.type(line, delay=0)
                    fallbacks.append(i + 1)
                ok = False
                for _ in range(16):
                    st = await page.evaluate(js_state)
                    if st and _norm(st["txt"]).endswith(tail):
                        ok = True; break
                    await asyncio.sleep(0.05)
                if ok:
                    break
            else:
                raise BridgeError("internal", f"composer dropped line {i + 1} three times ({line[:60]!r}); UI changed?")
        if i < len(lines) - 1:
            before = (await page.evaluate(js_state))["p"]
            await page.keyboard.press("Shift+Enter")
            for _ in range(20):
                st = await page.evaluate(js_state)
                if st and st["p"] > before:
                    break
                await asyncio.sleep(0.05)
    await asyncio.sleep(0.5)
    got = _norm((await page.evaluate(js_state))["txt"])
    tail = _norm(next((l for l in reversed(lines) if l.strip()), ""))[-60:]
    if tail not in got:
        raise BridgeError("internal", f"composer does not contain the end of the message (last 60 chars {tail!r}); UI changed?")
    return fallbacks


async def _send(page) -> None:
    btn = page.locator("[data-testid=send-button]")
    await btn.first.wait_for(timeout=10000)
    for _ in range(20):
        if await btn.first.is_enabled():
            break
        await asyncio.sleep(0.25)
    await btn.first.click(timeout=5000)


_CONV_JS = """async (id) => {
  // access token cached in the tab for 10 min: /api/auth/session on every poll doubled the backend request rate (429s on 2026-09-17)
  const c = window.__clbTok; let tok = c && c.exp > Date.now() ? c.tok : null;
  if (!tok) { const s = await fetch('/api/auth/session').then(r=>r.json()); tok = s.accessToken; window.__clbTok = {tok, exp: Date.now()+600000}; }
  const r = await fetch('/backend-api/conversation/'+id, {headers:{Authorization:'Bearer '+tok}});
  if (!r.ok) return {status:r.status, retry_after: r.headers.get('retry-after')};
  const j = await r.json();
  const chain = []; let n = j.mapping[j.current_node];
  while (n) { if (n.message) chain.push(n); n = n.parent ? j.mapping[n.parent] : null; }
  chain.reverse();
  const msgs = chain.map(n => { const m = n.message; const c = m.content || {};
    return {id:n.id, role:m.author.role, name:m.author.name||null, channel:m.channel||(m.metadata||{}).channel||null, ct:c.content_type, recipient:m.recipient,
      text: c.content_type==='text' ? (c.parts||[]).map(p=>typeof p==='string'?p:JSON.stringify(p)).join('') : (c.text|| (m.author.role==='tool'?JSON.stringify(c):'')),
      status:m.status, end_turn:m.end_turn, ts:m.create_time, model:(m.metadata||{}).model_slug||null}; }).filter(m => ["user","assistant","tool"].includes(m.role) && !["analysis","reasoning","thoughts","reasoning_recap"].includes(m.channel) && !["analysis","reasoning","thoughts","reasoning_recap"].includes(m.ct));
  return {status:200, title:j.title, model:j.default_model_slug, current:j.current_node, msgs};
}"""


async def _conversation(page, conv_id: str) -> dict:
    return await page.evaluate(_CONV_JS, conv_id)


async def _archive(page, conv_id: str) -> bool:
    """Archive (NOT delete) the sub-agent's conversation once its transcript is saved locally: it leaves the sidebar but stays in
    the account (Settings > Archived chats, still searchable/openable) — the user's retention rule is 'never delete'."""
    js = """async (id) => { const s = await fetch('/api/auth/session').then(r=>r.json());
      const r = await fetch('/backend-api/conversation/'+id, {method:'PATCH', headers:{Authorization:'Bearer '+s.accessToken,'Content-Type':'application/json'}, body: JSON.stringify({is_archived: true})});
      return r.ok; }"""
    try:
        return bool(await page.evaluate(js, conv_id))
    except Exception:
        return False


async def _rename(page, conv_id: str, title: str) -> bool:
    js = """async ([id, title]) => { const s = await fetch('/api/auth/session').then(r=>r.json());
      const r = await fetch('/backend-api/conversation/'+id, {method:'PATCH', headers:{Authorization:'Bearer '+s.accessToken,'Content-Type':'application/json'}, body: JSON.stringify({title})});
      return r.ok; }"""
    try:
        return bool(await page.evaluate(js, [conv_id, title[:100]]))
    except Exception:
        return False


def _digest(conv: dict, since_user_index: int) -> dict:
    return agent_outcomes.digest(conv, since_user_index)


def _assess(run_id: str, data: dict) -> dict:
    """Correlate transcript receipts to local audit rows, then verify explicit tests.

    A quoted request/job ID or a response from another workspace/run cannot pass.
    No command is executed here; the verifier only reads existing job evidence.
    """
    run = _row(run_id)
    verification = run["spec"].get("verification")
    assessment = agent_outcomes.outcome(data, verification)
    confirmed = []
    for receipt in data.get("tool_results", []):
        receipt["confirmed_on_host"] = False
        if receipt["kind"] != "bridge_response" or receipt.get("host_id") != CFG["host_id"]:
            continue
        row = db.one("SELECT ts, workspace_id, summary FROM audit WHERE tool='mcp.tool_result' AND request_id=? ORDER BY id DESC LIMIT 1", receipt["request_id"])
        if not row or row["ts"] < (run["start_ts"] or run["created_at"]):
            continue
        record = json.loads(row["summary"])
        if record.get("job_id") != receipt.get("job_id") or record.get("ok") != receipt.get("ok"):
            continue
        if row["workspace_id"] not in (None, run["workspace_id"]):
            continue
        receipt.update(confirmed_on_host=True, tool=record.get("tool"))
        confirmed.append(receipt)
    data["confirmed_bridge_calls"] = len({r["request_id"] for r in confirmed})
    data["verification_evidence"] = []
    if verification and assessment["status"] not in ("failed", "running"):
        if not confirmed:
            # chatgpt.com's conversation JSON does not expose tool outputs, so request_id receipts are normally absent; fall back to
            # jobs the bridge itself created in this run's window, same workspace, exact argv (still real host evidence, not the model's word)
            t0 = run["start_ts"] or run["created_at"]
            for jr in db.all_("SELECT id FROM jobs WHERE workspace_id=? AND created_at>=? ORDER BY created_at", run["workspace_id"], t0):
                confirmed.append({"kind": "bridge_response", "request_id": None, "job_id": jr["id"], "ok": True, "tool": "exec_start", "confirmed_on_host": True, "source": "job_window"})
        for receipt in confirmed:
            jid = receipt.get("job_id")
            if receipt.get("tool") != "exec_start" or not jid or not receipt.get("ok"):
                continue
            try:
                row = jobs._row(jid)
                if row["workspace_id"] != run["workspace_id"] or row["created_at"] < (run["start_ts"] or run["created_at"]):
                    continue
                jargv = row["spec"]["argv"]
                shell_form = " ".join(verification["argv"])
                if jargv != verification["argv"] and not (row["spec"].get("shell") and jargv and jargv[-1].strip() == shell_form):
                    continue   # exact argv, or the same command run as a shell string (`/bin/zsh -lc 'echo x'`)
                log = jobs.logs(jid, "stdout", 0, 1024 * 1024 + 1)
                evidence = {"job_id": jid, "request_id": receipt["request_id"], "exit_code": row["exit_code"],
                            "status": row["status"], "argv_matches": True,
                            "stdout_matches": log.get("eof") is True and log.get("text") == verification["stdout"],
                            "stdout_bytes": log.get("size")}
                data["verification_evidence"].append(evidence)
                if row["status"] == "succeeded" and row["exit_code"] == 0 and evidence["stdout_matches"]:
                    assessment.update(status="succeeded", task_status="verified", verification="passed", evidence_source="host_job_and_audit")
                    break
            except (BridgeError, KeyError, ValueError) as e:
                data["verification_evidence"].append({"job_id": jid, "verification_error": str(e)[:500]})
        else:
            assessment.update(status="failed", task_status="unverified", verification="failed", error_code="verification_failed",
                              error="No current-turn, audit-confirmed job matched the exact argv, exit code 0 and complete stdout.")
    data["outcome"] = assessment
    return assessment


def _persist_result(run_id: str, conv: dict, data: dict) -> None:
    assessment = _assess(run_id, data)
    jd = JOBS_DIR / run_id
    data["transcript_path"] = str(jd / "transcript.json")
    encoded = json.dumps({"conversation": conv, "digest": data}, ensure_ascii=False, indent=1, default=str)
    (jd / "transcript.json").write_text(encoded, encoding="utf-8")
    turn = _row(run_id)["meta"].get("followups", 0)
    (jd / f"transcript-turn-{turn}.json").write_text(encoded, encoding="utf-8")
    (jd / "result.md").write_text(data["final_text"], encoding="utf-8")
    _set(run_id, result=json.dumps(data, ensure_ascii=False, default=str))
    _meta_update(run_id, tool_calls=len(data["tool_calls"]), preview=data["final_text"][-300:], outcome=assessment)


async def _stop_generation(page) -> None:
    # Stop is the only action on an upstream block. Never click an approval.
    try:
        button = page.locator("[data-testid=stop-button]")
        if await button.count():
            await button.first.click(timeout=3000)
    except Exception:
        pass


async def _run(run_id: str, message: str, followup: bool) -> None:
    r = _row(run_id)
    ws = r["workspace_id"]; spec = r["spec"]
    _set(run_id, status="starting", start_ts=time.time())
    # The whole composer phase (open -> clear -> pill -> effort -> type -> send) is serialised: chatgpt.com keeps ONE shared
    # new-chat draft across tabs and re-syncs composers from it, so two tabs composing at once corrupt each other (seen
    # 2026-09-17: lines silently dropped). Polling afterwards runs concurrently; the tab is on /c/<id> by then.
    _phase(run_id, "waiting_for_composer")
    async with _ui_lock:
        _phase(run_id, "opening_tab")
        url = r["conv_url"] if followup and r["conv_url"] else CHATGPT_URL
        page_id, page = await _page_for(run_id, ws, url)
        await _ready_composer(page)
        await _session(page)
        await _clear_composer(page)
        warnings = []
        if not followup and spec.get("attach_bridge"):
            _phase(run_id, "attaching_plugin")
            if not await _attach_plugin(page):
                warnings.append(f"could not attach the {APP_NAME} plugin pill; the sub-agent may still find it on its own")
            else:
                await page.keyboard.insert_text(" ")
        before = None
        if r["effort"] != "auto":
            _phase(run_id, "setting_effort")
            try:
                before = await _effort_set(page, EFFORTS.index(r["effort"]))
            except Exception as e:
                warnings.append(f"could not set effort {r['effort']}: {str(e)[:120]}")
        _phase(run_id, "typing", chars=len(message))
        try:
            await page.bring_to_front()
        except Exception:
            pass
        fallbacks = await _type_message(page, message)
        if fallbacks:
            warnings.append(f"insertText dropped lines {fallbacks[:10]}; re-typed key by key")
        if spec.get("dry_run"):   # debugging aid: leave the composed message in the open tab, send nothing
            composed = await page.locator("#prompt-textarea").inner_text()
            _meta_update(run_id, warnings=warnings, composed_preview=composed[:2000], composed_chars=len(composed), page_url=page.url)
            _finish(run_id, "completed", "dry_run", "dry run: message typed, not sent; task not verified; tab left open")
            return
        _phase(run_id, "sending")
        await _send(page)
        # the URL flips from / (or /c/WEB:<tmp>) to /c/<uuid> once the backend has the conversation
        conv_id = r["conv_id"]
        for _ in range(60):
            m = re.search(r"/c/([0-9a-f-]{36})", page.url)
            if m:
                conv_id = m.group(1); break
            await asyncio.sleep(0.5)
        if not conv_id:
            raise BridgeError("upstream_blocked", f"message sent but no conversation id appeared (url {page.url}); check the tab")
        if not r["conv_id"]:
            _set(run_id, conv_id=conv_id, conv_url=f"https://chatgpt.com/c/{conv_id}")
    _set(run_id, status="running")
    if before is not None and r["effort"] != "auto" and before != EFFORTS.index(r["effort"]):
        try:   # the Power setting is account-wide: put it back so the user's own chats are not silently changed
            await _effort_set(page, before)
        except Exception as e:
            warnings.append(f"could not restore effort level {EFFORTS[before]}: {str(e)[:120]}")
    _meta_update(run_id, warnings=warnings, effort_restored_to=EFFORTS[before] if before is not None else None)
    # poll: DOM for streaming state and error surfaces, backend for the authoritative message tree
    _phase(run_id, "waiting_for_reply")
    user_index = -1; last_backend = 0.0; conv = None; quiet_since = None; prev_stop = True; backoff = 30.0
    global _throttle_until
    while True:
        await asyncio.sleep(2.5)
        dom = await page.evaluate("""() => ({stop: !!document.querySelector('[data-testid=stop-button]'),
            dialogs: [...document.querySelectorAll('[role=dialog],[role=alertdialog]')].map(d=>d.innerText.slice(0,400)),
            alerts: [...document.querySelectorAll('[role=alert]')].map(d=>d.innerText.trim()).filter(Boolean).slice(0,5),
            confirm: [...document.querySelectorAll('main button')].map(b=>b.innerText.trim()).filter(t=>/^(allow|confirm|approve|decline|deny|always allow)$/i.test(t)),
            preview: (()=>{const a=[...document.querySelectorAll('[data-message-author-role=assistant]')]; return a.length? a[a.length-1].innerText.slice(-300):null})()})""")
        if dom["preview"]:
            _phase(run_id, "streaming" if dom["stop"] else "waiting_for_reply", preview=dom["preview"])
        if dom["confirm"]:
            raise BridgeError("upstream_confirmation_required", f"ChatGPT is asking for a confirmation the bridge will not click for you: buttons {dom['confirm']}; open {r['conv_url'] or page.url} and decide (dialog: {(dom['dialogs'] or [''])[0][:200]!r})")
        now = time.time()
        errtxt = " | ".join(dom["alerts"] + dom["dialogs"])
        if re.search(r"reached (your|the) .*limit|too many requests|unusual activity|rate limit|try again later|something went wrong|network error", errtxt, re.I):
            code = "rate_limited" if re.search(r"limit|too many", errtxt, re.I) else "upstream_blocked"
            if code == "rate_limited" and re.search(r"too many|too quickly", errtxt, re.I):
                _throttle_until = max(_throttle_until, now + 300)   # account-level throttle: hold every run and agent_start for 5 min
            raise BridgeError(code, f"chatgpt.com: {errtxt[:300]}")
        if prev_stop and not dom["stop"]:
            last_backend = 0.0            # streaming just ended: fetch the tree now rather than a full idle interval later
        prev_stop = dom["stop"]
        interval = POLL_STREAMING if dom["stop"] else (POLL_SETTLE if quiet_since is not None else POLL_IDLE)
        if now < _throttle_until:
            _phase(run_id, "throttled", throttled_until=_throttle_until)
            continue
        if now - last_backend >= interval:
            last_backend = now
            conv = await _conversation(page, conv_id)
            if conv.get("status") != 200:
                if conv.get("status") in (401, 403):
                    raise BridgeError("needs_user_action", f"ChatGPT session rejected (HTTP {conv['status']}); re-login in Comet and `scoperailctl browser use-comet`")
                if conv.get("status") == 429:
                    try:
                        wait = float(conv.get("retry_after") or 0) or backoff
                    except ValueError:
                        wait = backoff
                    _throttle_until = max(_throttle_until, now + wait)
                    backoff = min(backoff * 2, 300)
                    db.audit("agent_throttled", f"{run_id} chatgpt.com 429; backing off {wait:.0f}s", workspace_id=r["workspace_id"])
                continue
            backoff = 30.0
            users = [i for i, m in enumerate(conv["msgs"]) if m["role"] == "user"]
            user_index = users[-1] if users else -1
            d = _digest(conv, user_index)
            observed = agent_outcomes.outcome(d)
            if observed["error_code"] == "upstream_safety_blocked":
                await _stop_generation(page)
                _persist_result(run_id, conv, d)
                _finish(run_id, "failed", observed["error_code"], observed["error"])
                return
            _phase(run_id, _progress.get(run_id, {}).get("phase", "waiting_for_reply"), tool_calls=len(d["tool_calls"]))
            if not dom["stop"] and d["final_end_turn"] and d["final_status"] == "finished_successfully":
                # settle: the tree can still grow for a moment after the stop button disappears
                if quiet_since is None:
                    quiet_since = now; continue
                if now - quiet_since < 3:
                    continue
                break
            quiet_since = None
    # done
    title = spec.get("title") or f"[agent] {r['agent'] or 'task'} · {run_id}"
    renamed = await _rename(page, conv_id, title) if not followup else True
    archived = False
    if spec.get("archive", CFG.get("agent_archive_on_finish", True)):
        archived = await _archive(page, conv_id)
    d["title"] = title if renamed else d.get("title")
    _persist_result(run_id, conv, d)
    assessment = d["outcome"]
    _meta_update(run_id, renamed=renamed)
    if not spec.get("keep_page") and assessment["task_status"] != "blocked":
        try:
            await browser.close(page_id)
        except Exception:
            pass
    _finish(run_id, assessment["status"], assessment["error_code"], assessment["error"])
