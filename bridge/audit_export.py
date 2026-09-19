"""Read-only, redacted audit export for local operator review."""
from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from typing import Any

from . import db

SCHEMA = "scoperail.audit/v1"
MAX_EXPORT_ROWS = 10_000
MAX_SUMMARY_CHARS = 512

_SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(?:authorization|cookie|cookies|passphrase|password|passwd|secret|token|credential|"
    r"api[_-]?key|apikey|environment|env|headers?)(?:$|[_-])",
    re.I,
)
_SECRET_PATTERNS = [
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{6,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(?:password|passphrase|secret|token|api[_-]?key|authorization|cookie)\s*[:=]\s*[^\s,;}]+"),
]


def parse_time_bound(value: str | float | int | None) -> float | None:
    """Parse an epoch or ISO-8601 timestamp. Naive ISO values are interpreted as UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("time bound must be finite")
        return number
    raw = str(value).strip()
    try:
        number = float(raw)
    except ValueError:
        number = None
    if number is not None:
        if not math.isfinite(number):
            raise ValueError("time bound must be finite")
        return number
    text = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"invalid time bound: {value!r}; use epoch seconds or ISO-8601") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _bounded(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = "".join(ch for ch in str(value) if ch >= " " and ch != "\x7f")
    return text[:limit]


def _redact_obj(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            name = str(key)
            if _SENSITIVE_KEY.search(name):
                out[name] = "[REDACTED]"
            else:
                out[name] = _redact_obj(item)
        return out
    if isinstance(value, list):
        return [_redact_obj(item) for item in value[:50]]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _redact_text(text: str) -> str:
    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return _bounded(out, MAX_SUMMARY_CHARS) or ""


def schedule_audit_summary(
    schedule_id: str,
    next_run: float,
    profile: str,
    cwd: str,
    interval: int | None,
    name: str,
) -> str:
    """Create the metadata-only audit row for a scheduled command.

    The command itself is intentionally absent; even display fields are redacted before
    persistence so future exports are not the first/only secret boundary.
    """
    data = {
        "schedule_id": _bounded(schedule_id, 128),
        "next": float(next_run),
        "profile": _bounded(profile, 64),
        "cwd": _redact_text(cwd),
        "interval": interval,
        "name": _redact_text(name),
    }
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def _safe_summary(tool: str, summary: str) -> tuple[str, str | None]:
    """Return (redacted_summary, job_id) under a conservative tool-specific policy."""
    if tool == "mcp.tool_received":
        try:
            data = json.loads(summary)
        except (TypeError, ValueError):
            return '{"tool":"[unparseable]"}', None
        return json.dumps({"tool": _bounded(data.get("tool"), 128)}, separators=(",", ":")), None

    if tool == "mcp.tool_result":
        try:
            data = json.loads(summary)
        except (TypeError, ValueError):
            return '{"tool":"[unparseable]","ok":false}', None
        allowed = {
            "tool": _bounded(data.get("tool"), 128),
            "ok": bool(data.get("ok")) if data.get("ok") is not None else None,
            "job_id": _bounded(data.get("job_id"), 128),
            "status": _bounded(data.get("status"), 64),
            "error": _bounded(data.get("error"), 64),
        }
        return json.dumps(allowed, separators=(",", ":")), allowed["job_id"]

    if tool == "job_schedule":
        # Current rows are metadata-only JSON. Older rows may contain a truncated repr
        # of the entire schedule spec, including the raw command; never export that tail.
        try:
            data = json.loads(summary)
        except (TypeError, ValueError):
            data = None
        if isinstance(data, dict) and data.get("schedule_id"):
            allowed = {
                "schedule_id": _bounded(data.get("schedule_id"), 128),
                "next": data.get("next") if isinstance(data.get("next"), (int, float)) else None,
                "profile": _bounded(data.get("profile"), 64),
                "cwd": _redact_text(str(data.get("cwd") or "")),
                "interval": data.get("interval") if isinstance(data.get("interval"), (int, float)) else None,
                "name": _redact_text(str(data.get("name") or "")),
            }
            return json.dumps(allowed, ensure_ascii=False, separators=(",", ":")), None
        match = re.match(r"^(sch_[A-Za-z0-9_-]+)\s+next=([0-9.]+)", summary or "")
        if match:
            return f"{match.group(1)} next={match.group(2)} details=[REDACTED]", None
        return "scheduled command details=[REDACTED]", None

    if tool == "killswitch":
        try:
            data = json.loads(summary)
        except (TypeError, ValueError):
            return "killswitch event details=[REDACTED]", None
        return _redact_text(json.dumps(_redact_obj(data), ensure_ascii=False, separators=(",", ":"))), None

    if tool == "scheduler":
        return "scheduler event details=[REDACTED]", None

    if tool in {"server", "file_import"}:
        return _redact_text(summary), None

    # Future audit call sites must opt in to a safe summary policy rather than
    # accidentally exporting arbitrary arguments from a newly added tool.
    return f"{tool} details=[REDACTED]", None


def _record(row: Any) -> dict[str, Any]:
    item = dict(row)
    ts = float(item["ts"])
    summary, job_id = _safe_summary(str(item["tool"]), str(item.get("summary") or ""))
    return {
        "schema": SCHEMA,
        "id": int(item["id"]),
        "ts": ts,
        "timestamp": _iso_utc(ts),
        "subject": _bounded(item.get("subject"), 256),
        "tool": _bounded(item["tool"], 128),
        "workspace_id": _bounded(item.get("workspace_id"), 128),
        "request_id": _bounded(item.get("request_id"), 128),
        "job_id": job_id,
        "summary": summary,
    }


def export_records(
    since: float | None = None,
    until: float | None = None,
    workspace_id: str | None = None,
    limit: int = MAX_EXPORT_ROWS,
) -> list[dict[str, Any]]:
    if since is not None and until is not None and since > until:
        raise ValueError("since must be <= until")
    if not 1 <= int(limit) <= MAX_EXPORT_ROWS:
        raise ValueError(f"limit must be between 1 and {MAX_EXPORT_ROWS}")

    conditions: list[str] = []
    args: list[Any] = []
    if since is not None:
        conditions.append("ts>=?")
        args.append(float(since))
    if until is not None:
        conditions.append("ts<=?")
        args.append(float(until))
    if workspace_id:
        conditions.append("workspace_id=?")
        args.append(workspace_id)
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = (
        "SELECT id,ts,subject,tool,workspace_id,request_id,summary FROM audit"
        + where
        + " ORDER BY ts ASC, id ASC LIMIT ?"
    )
    args.append(int(limit))
    records = [_record(row) for row in db.all_(sql, *args)]
    records.sort(key=lambda item: (item["ts"], item["id"]))
    return records


def render(records: list[dict[str, Any]], format: str = "jsonl") -> str:
    if format == "jsonl":
        return "".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in records)
    if format == "json":
        return json.dumps(
            {"schema": "scoperail.audit-export/v1", "count": len(records), "records": records},
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        ) + "\n"
    raise ValueError("format must be jsonl or json")
