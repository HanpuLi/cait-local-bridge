"""Named persistent shell sessions built on the bridge job/PTY runtime.

The process is deliberately a thin stateful layer over jobs.py: workspace/profile
policy, environment scrubbing, process-group cleanup, logs and audit remain owned by
one execution substrate.  Sessions retain cwd, exported variables, shell functions
and aliases until close/reset/restart.

Design cues: Shellby's named persistent-shell UX and retry identity, while preserving
Cait Local Bridge's sandbox/trusted-host boundary and retry-safe job primitives.
"""
from __future__ import annotations

import base64
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from . import jobs
from .policy import BridgeError, workspace_get

_MAX_SESSIONS = 6
_MAX_CAPTURE = 1_000_000
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_DONE_RE = re.compile(r"\x1eCLB_DONE:([0-9a-f]+):(-?\d+):([A-Za-z0-9+/=]*)\x1e")


@dataclass
class Session:
    shell_id: str
    workspace_id: str
    profile: str
    job_id: str
    cwd: str
    created_at: float
    last_used: float
    cursor: int = 0
    active: dict[str, Any] | None = None
    requests: dict[str, dict[str, Any]] = field(default_factory=dict)


_lock = threading.RLock()
_sessions: dict[str, Session] = {}


def _validate_id(shell_id: str) -> str:
    if not _ID_RE.fullmatch(shell_id or ""):
        raise BridgeError("invalid_argument", "shell_id must match [A-Za-z0-9._-]{1,64}")
    return shell_id


def _status(session: Session) -> dict[str, Any]:
    j = jobs.info(session.job_id)
    return {
        "shell_id": session.shell_id,
        "workspace_id": session.workspace_id,
        "profile": session.profile,
        "job_id": session.job_id,
        "status": j["status"],
        "cwd": session.cwd,
        "created_at": session.created_at,
        "last_used": session.last_used,
        "active_command": bool(session.active),
        "active_request_id": session.active.get("request_id") if session.active else None,
    }


def _ensure_alive(session: Session) -> None:
    status = jobs.info(session.job_id)["status"]
    if status not in jobs.STATUS_ACTIVE:
        raise BridgeError(
            "conflict",
            f"persistent shell {session.shell_id!r} is {status}; call shell_reset or shell_open",
        )


def open_shell(
    workspace_id: str,
    shell_id: str = "default",
    profile: str = "sandboxed",
    cwd: str = ".",
    env: dict[str, str] | None = None,
    subject: str | None = None,
) -> dict[str, Any]:
    shell_id = _validate_id(shell_id)
    workspace_get(workspace_id)
    with _lock:
        existing = _sessions.get(shell_id)
        if existing:
            if existing.workspace_id != workspace_id or existing.profile != profile:
                raise BridgeError(
                    "conflict",
                    f"shell {shell_id!r} already belongs to workspace={existing.workspace_id} profile={existing.profile}",
                )
            try:
                _ensure_alive(existing)
                existing.last_used = time.time()
                return {**_status(existing), "reused": True}
            except BridgeError:
                _sessions.pop(shell_id, None)

        if len(_sessions) >= _MAX_SESSIONS:
            idle = [s for s in _sessions.values() if not s.active]
            if not idle:
                raise BridgeError("rate_limited", f"all {_MAX_SESSIONS} persistent shell slots are busy")
            victim = min(idle, key=lambda s: s.last_used)
            try:
                jobs.cancel(victim.job_id, subject)
            except Exception:
                pass
            _sessions.pop(victim.shell_id, None)

        # Keep stdin open without a PTY.  A non-interactive shell retains cwd,
        # exports, functions and aliases but does not run ZLE or echo our command
        # wrapper into stdout.  This mirrors Shellby's clean persistent-shell model.
        # Use -f in both profiles so user startup files cannot stall or inject
        # output into the protocol. Sandbox jobs still pass through jobs.py's
        # Seatbelt wrapper and scrubbed environment.
        command = ["/bin/zsh", "-f"]
        j = jobs.start(
            workspace_id, profile, command, cwd, env, 6 * 3600, False,
            None, "", 160, 48, subject, None,
        )
        session = Session(
            shell_id=shell_id, workspace_id=workspace_id, profile=profile,
            job_id=j["job_id"], cwd=j["cwd"], created_at=time.time(), last_used=time.time(),
        )
        _sessions[shell_id] = session

    # Keep the shell process itself alive when shell_interrupt sends SIGINT to
    # the process group. Executed children reset caught signal handlers on exec,
    # so a foreground command such as sleep still receives the interrupt.
    jobs.send_input(session.job_id, text="trap ':' INT\n", subject=subject)
    # Spawn is synchronous. Give an immediately-failing shell a brief chance to
    # surface before returning a live session.
    time.sleep(0.03)
    _ensure_alive(session)
    session.cursor = jobs.info(session.job_id)["log_sizes"]["stdout"]
    return {**_status(session), "reused": False, "ready": True}


def _session(shell_id: str) -> Session:
    shell_id = _validate_id(shell_id)
    with _lock:
        s = _sessions.get(shell_id)
    if not s:
        raise BridgeError("not_found", f"unknown persistent shell {shell_id!r}; call shell_open")
    _ensure_alive(s)
    return s


def _decode_pwd(encoded: str, fallback: str) -> str:
    try:
        return base64.b64decode(encoded).decode("utf-8", "replace")
    except Exception:
        return fallback


def _read_active(session: Session, max_output_bytes: int) -> dict[str, Any]:
    active = session.active
    if not active:
        return {**_status(session), "running": False, "output": "", "exit_code": None}

    info = jobs.info(session.job_id)
    size = info["log_sizes"]["stdout"]
    if size > active["cursor"]:
        d = jobs.logs(session.job_id, "stdout", active["cursor"], min(size - active["cursor"], 1_000_000))
        active["cursor"] = d["next_cursor"]
        active["buffer"] += d["text"]
        if len(active["buffer"]) > _MAX_CAPTURE:
            active["buffer"] = active["buffer"][-_MAX_CAPTURE:]
            active["capture_truncated"] = True

    match = _DONE_RE.search(active["buffer"])
    if match and match.group(1) == active["token"]:
        output = active["buffer"][: match.start()].replace("\r\n", "\n").replace("\r", "\n")
        exit_code = int(match.group(2))
        session.cwd = _decode_pwd(match.group(3), session.cwd)
        session.cursor = active["cursor"]
        request_id = active.get("request_id")
        command = active["command"]
        capture_truncated = active["capture_truncated"]
        # Clear active state before taking _status so both the immediate result
        # and any deduplicated replay describe the finished command accurately.
        session.active = None
        session.last_used = time.time()
        result = {
            **_status(session),
            "running": False,
            "request_id": request_id,
            "command": command,
            "exit_code": exit_code,
            "output": output[-max_output_bytes:],
            "output_bytes": len(output.encode("utf-8", "replace")),
            "truncated": capture_truncated or len(output.encode("utf-8", "replace")) > max_output_bytes,
            "cwd": session.cwd,
        }
        if request_id:
            session.requests[request_id] = {
                "command": command,
                "result": dict(result),
                "finished_at": time.time(),
            }
            if len(session.requests) > 64:
                oldest = sorted(session.requests.items(), key=lambda kv: kv[1]["finished_at"])[0][0]
                session.requests.pop(oldest, None)
        return result

    if info["status"] not in jobs.STATUS_ACTIVE:
        session.active = None
        raise BridgeError("conflict", f"persistent shell process ended unexpectedly with status={info['status']}")

    return {
        **_status(session),
        "running": True,
        "request_id": active.get("request_id"),
        "command": active["command"],
        "exit_code": None,
        "output": active["buffer"][-max_output_bytes:].replace("\r\n", "\n").replace("\r", "\n"),
        "truncated": active["capture_truncated"] or len(active["buffer"].encode("utf-8", "replace")) > max_output_bytes,
    }


def run(
    shell_id: str,
    command: str,
    request_id: str | None = None,
    wait_ms: int = 15_000,
    max_output_bytes: int = 32_000,
    subject: str | None = None,
) -> dict[str, Any]:
    if not isinstance(command, str) or not command.strip():
        raise BridgeError("invalid_argument", "command must be a non-empty string")
    if len(command) > 500_000:
        raise BridgeError("invalid_argument", "command must be <= 500000 characters")
    if request_id is not None and (not isinstance(request_id, str) or len(request_id) > 128):
        raise BridgeError("invalid_argument", "request_id must be a string <= 128 characters")
    wait_ms = max(0, min(int(wait_ms), 120_000))
    max_output_bytes = max(1024, min(int(max_output_bytes), 200_000))
    session = _session(shell_id)

    with _lock:
        if request_id and request_id in session.requests:
            previous = session.requests[request_id]
            if previous["command"] != command:
                raise BridgeError("conflict", "request_id was already used for different shell text")
            result = dict(previous["result"])
            result["deduplicated"] = True
            return result

        if session.active:
            if request_id and session.active.get("request_id") == request_id:
                if session.active["command"] != command:
                    raise BridgeError("conflict", "request_id is active with different shell text")
            else:
                raise BridgeError(
                    "conflict",
                    f"shell {shell_id!r} already has a foreground command; call shell_poll or shell_interrupt",
                )
        else:
            token = uuid.uuid4().hex
            encoded = base64.b64encode(command.encode("utf-8")).decode("ascii")
            # Preserve cwd/environment/functions in the current shell.  PWD is
            # base64-encoded in the marker so ':' and unicode cannot break parsing.
            fn = "__clb_run_" + token
            wrapper = (
                f"__clb_cmd=$(/bin/echo -n '{encoded}' | /usr/bin/base64 -D); "
                f"{fn}() {{ trap 'return 130' INT; eval \"$__clb_cmd\" 2>&1; }}; "
                f"{fn}; __clb_ec=$?; unfunction {fn} 2>/dev/null; trap ':' INT; "
                "__clb_pwd=$(/bin/echo -n \"$PWD\" | /usr/bin/base64); "
                f"/usr/bin/printf '\\036CLB_DONE:{token}:%s:%s\\036\\n' \"$__clb_ec\" \"$__clb_pwd\"\n"
            )
            info = jobs.info(session.job_id)
            start_cursor = info["log_sizes"]["stdout"]
            session.active = {
                "token": token,
                "command": command,
                "request_id": request_id,
                "cursor": start_cursor,
                "buffer": "",
                "capture_truncated": False,
                "started_at": time.time(),
            }
            jobs.send_input(session.job_id, text=wrapper, subject=subject)

    deadline = time.time() + wait_ms / 1000
    while True:
        result = _read_active(session, max_output_bytes)
        if not result["running"] or time.time() >= deadline:
            return result
        time.sleep(0.05)


def poll(shell_id: str, wait_ms: int = 0, max_output_bytes: int = 32_000) -> dict[str, Any]:
    session = _session(shell_id)
    wait_ms = max(0, min(int(wait_ms), 120_000))
    max_output_bytes = max(1024, min(int(max_output_bytes), 200_000))
    deadline = time.time() + wait_ms / 1000
    while True:
        result = _read_active(session, max_output_bytes)
        if not result.get("running") or time.time() >= deadline:
            return result
        time.sleep(0.05)


def interrupt(shell_id: str, subject: str | None = None) -> dict[str, Any]:
    session = _session(shell_id)
    if session.active:
        jobs.send_input(session.job_id, interrupt=True, subject=subject)
    session.last_used = time.time()
    return {**_status(session), "interrupt_sent": bool(session.active)}


def close(shell_id: str, subject: str | None = None) -> dict[str, Any]:
    shell_id = _validate_id(shell_id)
    with _lock:
        session = _sessions.pop(shell_id, None)
    if not session:
        return {"shell_id": shell_id, "closed": False, "reason": "not_found"}
    try:
        result = jobs.cancel(session.job_id, subject)
    except Exception as exc:
        return {"shell_id": shell_id, "closed": True, "job_id": session.job_id, "warning": str(exc)[:500]}
    return {"shell_id": shell_id, "closed": True, "job_id": session.job_id, "job_status": result["status"]}


def reset(
    shell_id: str,
    workspace_id: str | None = None,
    profile: str | None = None,
    cwd: str = ".",
    env: dict[str, str] | None = None,
    subject: str | None = None,
) -> dict[str, Any]:
    old = None
    with _lock:
        old = _sessions.get(shell_id)
    if old:
        workspace_id = workspace_id or old.workspace_id
        profile = profile or old.profile
        close(shell_id, subject)
    if not workspace_id:
        raise BridgeError("invalid_argument", "workspace_id is required when resetting an unknown shell")
    return open_shell(workspace_id, shell_id, profile or "sandboxed", cwd, env, subject)


def list_shells(workspace_id: str | None = None) -> list[dict[str, Any]]:
    with _lock:
        sessions = list(_sessions.values())
    out = []
    for s in sessions:
        if workspace_id and s.workspace_id != workspace_id:
            continue
        try:
            out.append(_status(s))
        except Exception:
            out.append({
                "shell_id": s.shell_id, "workspace_id": s.workspace_id, "profile": s.profile,
                "job_id": s.job_id, "status": "unknown", "cwd": s.cwd,
            })
    return sorted(out, key=lambda x: x["shell_id"])


def close_all(subject: str | None = None) -> list[str]:
    with _lock:
        ids = list(_sessions)
    for shell_id in ids:
        try:
            close(shell_id, subject)
        except Exception:
            pass
    return ids


# Pure helper used by unit tests.
parse_done_marker = lambda text: (_DONE_RE.search(text).groups() if _DONE_RE.search(text) else None)
