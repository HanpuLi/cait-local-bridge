"""Pull-based process evidence over the existing jobs store.

No new execution authority or credential store. Read-only tool annotations are
not authorization; every entry point rechecks the registered workspace and binds
the job to it. Output is untrusted data, not instructions or a test verdict.

The separation and sanitizer rules are adapted from codex-with-chatgpt; see
LICENSES/codex-with-chatgpt-MIT.txt and docs/execution-review.md.

Upstream notice is retained here as well so it ships with the Python module.
MIT License

Copyright (c) 2026 codex-with-chatgpt contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from contextlib import ExitStack
from typing import Any

from . import db, jobs, policy
from .policy import BridgeError

SCHEMA_VERSION = 1
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
DEFAULT_PAGE_BYTES = 4096
MAX_PAGE_BYTES = 16384
AUTO_INLINE_BYTES = 4096
_JOB_ID = re.compile(r"job_[0-9a-f]{12}\Z")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----", re.IGNORECASE)
_ANSI = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]")
_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_BARE_SECRET = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}"
    r"|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b"
)
_AUTH_HEADER = re.compile(r"(?im)\b((?:proxy-)?authorization\s*:\s*)[^\r\n]+")
_ASSIGNMENT = re.compile(
    r'''(?ix)(?<![a-z0-9_-])(["']?(?:[a-z0-9]+[_-])*(?:api[_-]?key|secret|password|passwd|token|authorization)["']?\s*[:=]\s*)'''
    r'''(?:"(?:\\[^\r\n]|[^"\\\r\n])*"|'(?:\\[^\r\n]|[^'\\\r\n])*'|[^\s,;}]+)'''
)
_URL_USERINFO = re.compile(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@")
_HOME_PATH = re.compile(r"/(Users|home)/[^/\s\"'`]+")
_WIN_HOME = re.compile(r"(?i)C:\\Users\\[^\\\s\"'`]+")


def _integer(value: Any, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise BridgeError("invalid_argument", f"{name} must be an integer between {low} and {high}")
    return value


def validate_run_options(output_mode: str, max_output_bytes: int) -> None:
    """Validate before launching: a bad presentation option must not start a job."""
    if output_mode not in ("auto", "summary", "inline"):
        raise BridgeError("invalid_argument", "output_mode must be auto, summary or inline")
    _integer(max_output_bytes, "max_output_bytes", 1, 200_000)


def _bound_row(workspace_id: str, job_id: str) -> dict:
    policy.workspace_get(workspace_id)
    if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
        raise BridgeError("invalid_argument", "invalid process job_id")
    row = db.one("SELECT * FROM jobs WHERE id=? AND workspace_id=?", job_id, workspace_id)
    if row is None:
        # The same response covers unknown jobs and jobs belonging to another workspace.
        raise BridgeError("not_found", "job not found in this workspace")
    result = dict(row)
    result["meta"] = json.loads(result["meta"])
    return result


def summary(workspace_id: str, job_id: str) -> dict:
    """Observed process metadata only; do not echo argv, environment, paths or logs."""
    row = _bound_row(workspace_id, job_id)
    meta = row["meta"]
    return {
        "schema_version": SCHEMA_VERSION,
        "job_id": job_id,
        "workspace_id": workspace_id,
        "status": row["status"],
        "profile": row["profile"],
        "exit_code": row["exit_code"],
        "signal": row["signal"],
        "timed_out": bool(meta.get("timed_out", False)),
        "start_ts": row["start_ts"],
        "end_ts": row["end_ts"],
        "terminal": row["status"] not in jobs.STATUS_ACTIVE,
        "output_complete": meta.get("output_complete") is True,
        "output_truncated": bool(meta.get("output_truncated", False)),
        "evidence_kind": "process_record",
        "test_verdict": "not_assessed",
        "task_verdict": "not_assessed",
    }


def sanitize(raw: bytes) -> dict:
    """Sanitize the entire bounded snapshot before slicing. Never promise perfect DLP."""
    if len(raw) > MAX_SNAPSHOT_BYTES:
        return {"status": "restricted", "reason": "snapshot_too_large"}
    if b"\x00" in raw:
        return {"status": "restricted", "reason": "binary_output"}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"status": "restricted", "reason": "non_utf8_output"}
    text = _CONTROLS.sub("", _ANSI.sub("", text))
    if _PRIVATE_KEY.search(text):
        return {"status": "restricted", "reason": "private_key"}
    text = _AUTH_HEADER.sub(r"\1[REDACTED]", text)
    text = _ASSIGNMENT.sub(r"\1[REDACTED]", text)
    text = _BARE_SECRET.sub("[REDACTED]", text)
    text = _URL_USERINFO.sub(r"\1[REDACTED]@", text)
    text = _HOME_PATH.sub(r"/\1/[user]", text)
    text = _WIN_HOME.sub(lambda _: r"C:\Users\[user]", text)
    clean = text.encode("utf-8")
    return {"status": "readable", "body": clean, "transformed": clean != raw}


def _read_log(job_id: str, stream: str) -> bytes:
    """Read only a fixed log name via directory fds; never follow a symlink/FIFO."""
    if stream not in ("stdout", "stderr"):
        raise BridgeError("invalid_argument", "stream must be stdout or stderr")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise BridgeError("missing_dependency", "safe log reads require directory-fd and no-follow support")
    with ExitStack() as stack:
        def open_fd(path, flags, parent=None):
            fd = os.open(path, flags, dir_fd=parent)
            stack.callback(os.close, fd)
            return fd
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            root_fd = open_fd(jobs.JOBS_DIR, flags)
            job_fd = open_fd(job_id, flags, root_fd)
            fd = open_fd(f"{stream}.log", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, job_fd)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise BridgeError("permission_denied", "log is not a private regular file")
            if before.st_size > MAX_SNAPSHOT_BYTES:
                raise BridgeError("output_restricted", "snapshot_too_large")
            chunks, remaining = [], before.st_size
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    raise BridgeError("conflict", "log changed while being read")
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ):
                raise BridgeError("conflict", "log changed while being read")
            return b"".join(chunks)
        except FileNotFoundError:
            raise BridgeError("not_found", "log is not available") from None
        except OSError:
            raise BridgeError("permission_denied", "log could not be opened safely") from None


def _snapshot(workspace_id: str, job_id: str, stream: str) -> tuple[dict, bytes]:
    row = _bound_row(workspace_id, job_id)
    meta = {"job_id": job_id, "stream": stream, "status": "restricted"}
    if row["status"] in jobs.STATUS_ACTIVE:
        return {**meta, "status": "pending", "reason": "job_active"}, b""
    if row["meta"].get("output_complete") is not True:
        return {**meta, "reason": "output_completion_unverified"}, b""
    if row["meta"].get("output_truncated"):
        return {**meta, "reason": "capture_truncated"}, b""
    try:
        raw = _read_log(job_id, stream)
    except BridgeError as exc:
        if exc.code == "output_restricted":
            return {**meta, "reason": exc.message}, b""
        if exc.code == "not_found":
            return {**meta, "status": "unavailable", "reason": "log_missing"}, b""
        raise
    clean = sanitize(raw)
    # Revocation/expiry during disk access must not release the result.
    _bound_row(workspace_id, job_id)
    if clean["status"] != "readable":
        return {**meta, "reason": clean["reason"]}, b""
    body = clean["body"]
    binding = json.dumps([SCHEMA_VERSION, workspace_id, job_id, stream], separators=(",", ":")).encode()
    snapshot_id = hashlib.sha256(binding + b"\0" + body).hexdigest()
    return {
        **meta, "status": "readable", "snapshot_id": snapshot_id,
        "size_bytes": len(body), "raw_size_bytes": len(raw), "transformed": clean["transformed"],
    }, body


def output(workspace_id: str, job_id: str, action: str = "list", stream: str = "stdout",
           cursor: int = 0, max_bytes: int = DEFAULT_PAGE_BYTES,
           snapshot_id: str | None = None) -> dict:
    """List release metadata, then read a UTF-8-safe page of the sanitized view."""
    _bound_row(workspace_id, job_id)
    if action not in ("list", "read") or stream not in ("stdout", "stderr"):
        raise BridgeError("invalid_argument", "action must be list/read and stream must be stdout/stderr")
    _integer(cursor, "cursor", 0, MAX_SNAPSHOT_BYTES * 4)
    _integer(max_bytes, "max_bytes", 4, MAX_PAGE_BYTES)
    if snapshot_id is not None and (not isinstance(snapshot_id, str) or not re.fullmatch(r"[0-9a-f]{64}", snapshot_id)):
        raise BridgeError("invalid_argument", "snapshot_id must be a SHA-256 view identifier")
    if action == "list":
        if cursor or snapshot_id is not None:
            raise BridgeError("invalid_argument", "list does not take a cursor or snapshot_id")
        items = [_snapshot(workspace_id, job_id, name)[0] for name in ("stdout", "stderr")]
        return {"schema_version": SCHEMA_VERSION, "job_id": job_id, "workspace_id": workspace_id, "items": items}
    if cursor and snapshot_id is None:
        raise BridgeError("invalid_argument", "continuation reads require snapshot_id")
    meta, body = _snapshot(workspace_id, job_id, stream)
    if meta["status"] != "readable":
        return {**meta, "workspace_id": workspace_id, "text": "", "next_cursor": None,
                "snapshot_eof": False, "truncated": False}
    if snapshot_id is not None and snapshot_id != meta["snapshot_id"]:
        raise BridgeError("conflict", "output view changed; list again and restart at cursor 0")
    if cursor > len(body) or (cursor < len(body) and body[cursor] & 0xC0 == 0x80):
        raise BridgeError("invalid_argument", "cursor is not a valid UTF-8 byte boundary in this view")
    end = min(cursor + max_bytes, len(body))
    while end < len(body) and body[end] & 0xC0 == 0x80:
        end -= 1
    more = end < len(body)
    return {**meta, "workspace_id": workspace_id, "cursor": cursor,
            "text": body[cursor:end].decode("utf-8"), "next_cursor": end if more else None,
            "snapshot_eof": not more, "truncated": more}


def run_response(j: dict, output_mode: str, max_output_bytes: int, started_at: float,
                 deduplicated: bool = False) -> dict:
    """Build a bounded control response without re-executing or reclassifying a job."""
    validate_run_options(output_mode, max_output_bytes)
    job_id, workspace_id = j["job_id"], j["workspace_id"]
    observed = summary(workspace_id, job_id)
    data = {"job_id": job_id, "status": j["status"], "exit_code": j["exit_code"],
            "signal": j["signal"], "timed_out": j["timed_out"], "profile": j["profile"],
            "deduplicated": bool(deduplicated), "wait_exhausted": j["status"] in jobs.STATUS_ACTIVE,
            "elapsed_s": round((j["end_ts"] or time.time()) - (j["start_ts"] or started_at), 2),
            "stdout": "", "stderr": "", "stdout_bytes": j["log_sizes"]["stdout"],
            "stderr_bytes": j["log_sizes"]["stderr"], "output_mode": output_mode,
            "output_complete": observed["output_complete"], "output_truncated": observed["output_truncated"],
            "output_deferred": False, "truncated": False}
    if output_mode == "inline":
        # Explicit compatibility path. It is intentionally RAW, like exec_logs.
        cap = max(1024, min(max_output_bytes, 200_000))
        for stream in ("stdout", "stderr"):
            size = j["log_sizes"][stream]
            data[stream] = jobs.logs(job_id, stream, max(0, size - cap), cap)["text"]
            data["truncated"] |= size > cap
        data.update(argv=j["argv"], cwd=j["cwd"], output_sanitized=False)
        return data
    limit = min(AUTO_INLINE_BYTES, max_output_bytes)
    inline = (output_mode == "auto" and observed["terminal"] and observed["output_complete"]
              and sum(j["log_sizes"].values()) <= limit)
    if inline:
        views = [_snapshot(workspace_id, job_id, stream) for stream in ("stdout", "stderr")]
        inline = all(meta["status"] == "readable" for meta, _ in views) and sum(len(body) for _, body in views) <= limit
        if inline:
            for (meta, body), stream in zip(views, ("stdout", "stderr")):
                data[stream] = body.decode("utf-8")
                data[f"{stream}_bytes"] = meta["raw_size_bytes"]
            data["output_sanitized"] = True
            data["output_transformed"] = any(meta["transformed"] for meta, _ in views)
    if not inline:
        data.update(output_deferred=True, truncated=any(j["log_sizes"].values()))
    data["output_ref"] = {"tool": "execution_output", "arguments": {
        "workspace_id": workspace_id, "job_id": job_id, "action": "list"}}
    return data
