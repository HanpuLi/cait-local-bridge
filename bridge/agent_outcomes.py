"""Deterministic, conservative interpretation of sub-agent transcripts.

Conversation completion is not task verification. Tool text is evidence only when
it is an actual tool message; quoted errors in user prompts and file contents are
not platform errors. This module performs no I/O and never retries an action.
"""
from __future__ import annotations
import json
import re
from typing import Any

SCHEMA_VERSION = 2
_SAFETY = re.compile(
    r"^This tool call was blocked by OpenAI because (?:we couldn't determine the safety status of the request\.?|.*safety.*)$",
    re.I | re.S,
)
_MARKER = re.compile(r"^CLB_TASK_STATUS=(done|blocked|failed|needs_user_action)$", re.M)
_HIDDEN = {"analysis", "reasoning", "thoughts", "reasoning_recap"}


def validate_verification(value: Any) -> dict | None:
    """An opt-in exact command/stdout check, not a semantic task success claim."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"kind", "argv", "stdout"}:
        raise ValueError("verification must contain exactly kind, argv and stdout")
    argv = value.get("argv")
    if value.get("kind") != "exec" or not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("verification.kind must be exec and argv must be a non-empty string list")
    if not isinstance(value.get("stdout"), str) or len(value["stdout"].encode()) > 1024 * 1024:
        raise ValueError("verification.stdout must be a string of at most 1 MiB")
    return {"kind": "exec", "argv": list(argv), "stdout": value["stdout"]}


def _envelopes(value: Any, depth: int = 0) -> list[dict]:
    """Unwrap MCP transport containers, never arbitrary file/output data."""
    if depth > 5:
        return []
    if isinstance(value, str):
        try:
            return _envelopes(json.loads(value), depth + 1)
        except (ValueError, TypeError):
            return []
    if isinstance(value, list):
        return [e for part in value for e in _envelopes(part, depth + 1)]
    if not isinstance(value, dict):
        return []
    if isinstance(value.get("ok"), bool) and isinstance(value.get("request_id"), str) and isinstance(value.get("provenance"), dict):
        return [value]
    out = []
    for key in ("structured_content", "structuredContent", "content", "text", "result"):
        if key in value:
            out.extend(_envelopes(value[key], depth + 1))
    return out


def digest(conv: dict, since_user_index: int) -> dict:
    messages = [m for m in conv.get("msgs", [])[since_user_index + 1:]
                if m.get("role") in ("assistant", "tool")
                and m.get("channel") not in _HIDDEN and m.get("ct") not in _HIDDEN]
    attempts, results, unanswered = [], [], []
    for i, m in enumerate(messages):
        text = m.get("text") or ""
        if m.get("role") == "assistant" and m.get("recipient") not in (None, "all"):
            name = m["recipient"].rsplit(".", 1)[-1]
            try:
                path = json.loads(text).get("path", "")
                if path:
                    name = path.rsplit("/", 1)[-1]
            except (ValueError, AttributeError, TypeError):
                pass
            attempt = {"message_id": m.get("id"), "recipient": m["recipient"], "tool": name, "ts": m.get("ts")}
            attempts.append(attempt)
            # A call OpenAI blocks before dispatch leaves no tool message at all: the next message is the assistant again (or nothing).
            nxt = messages[i + 1] if i + 1 < len(messages) else None
            if m["recipient"].startswith("api_tool") and (nxt is None or nxt.get("role") != "tool"):
                unanswered.append(attempt)
        if m.get("role") != "tool":
            continue
        common = {"message_id": m.get("id"), "name": m.get("name"), "ts": m.get("ts")}
        envelopes = _envelopes(text)
        if envelopes:
            seen = set()
            for env in envelopes:
                rid = env["request_id"]
                if rid in seen:
                    continue
                seen.add(rid)
                results.append({**common, "kind": "bridge_response", "request_id": rid,
                                "host_id": env["provenance"].get("host_id"),
                                "workspace_id": env["provenance"].get("workspace_id"),
                                "job_id": env.get("job_id"), "ok": env["ok"],
                                "error": env.get("error"), "raw_error": env.get("message") if not env["ok"] else None})
        elif _SAFETY.fullmatch(text.strip()):
            results.append({**common, "kind": "platform_safety_block", "raw_error": text})
        else:
            results.append({**common, "kind": "opaque_tool_result", "raw_error": None})
    finals = [m for m in messages if m.get("role") == "assistant" and m.get("ct") == "text"
              and m.get("recipient") in (None, "all") and m.get("text")]
    final = finals[-1] if finals else None
    return {"schema_version": SCHEMA_VERSION, "final_text": final["text"] if final else "",
            "final_end_turn": bool(final and final.get("end_turn")),
            "final_status": final.get("status") if final else None,
            "messages": [{k: (m.get(k) or "")[:4000] if k == "text" else m.get(k)
                          for k in ("id", "role", "name", "recipient", "channel", "ct", "text", "status", "end_turn", "ts")}
                         | {"text_truncated": len(m.get("text") or "") > 4000} for m in messages],
            "tool_calls": attempts, "tool_results": results, "unanswered_tool_calls": unanswered,
            "tool_attempts": len(attempts), "tool_responses": len(results), "upstream_blocks_observed": len(unanswered),
            "model_slug": conv.get("model"), "title": conv.get("title")}


def outcome(data: dict, verification: dict | None = None) -> dict:
    """Classify observed errors; verified success is assigned only by the host verifier."""
    done = data.get("final_end_turn") and data.get("final_status") == "finished_successfully"
    blocks = int(data.get("upstream_blocks_observed") or 0)
    base = {"status": "completed" if done else "running", "conversation_status": "completed" if done else "running",
            "task_status": "unverified", "error_code": None, "error": None,
            "evidence_source": "transcript", "verification": "not_requested" if verification is None else "pending",
            "upstream_blocks_observed": blocks,
            # The worker may repeat a blocked call once, verbatim; a run that then finished is not a blocked run, but the block is on record.
            "warnings": [f"{blocks} plugin call(s) were dropped by OpenAI's safety check before reaching the bridge (see unanswered_tool_calls)"] if blocks else []}
    for result in data.get("tool_results", []):
        if result["kind"] == "platform_safety_block":
            return {**base, "status": "failed", "task_status": "blocked", "error_code": "upstream_safety_blocked",
                    "error": result["raw_error"], "evidence_source": "tool_return"}
    text = data.get("final_text") or ""
    # New workers report an exact terminal marker, outside code fences. Legacy short
    # RESULT reports remain distinguishable from an observed platform tool error.
    plain = re.sub(r"```.*?```", "", text, flags=re.S)
    match = _MARKER.search(plain) if done else None
    reported = match.group(1) if match else None
    legacy = (done and reported is None and len(text) < 600 and "```" not in text and
              re.search(r"(?:exec_start|工具调用|tool call)[^\n]{0,90}(?:被安全检查(?:拦截|阻止)|被(?:OpenAI|ChatGPT)[^\n]{0,30}拦截|was blocked by OpenAI)", text, re.I))
    if reported == "blocked" or legacy:
        return {**base, "status": "failed", "task_status": "blocked", "error_code": "reported_safety_blocked",
                "error": text, "evidence_source": "assistant_report"}
    if reported in ("failed", "needs_user_action"):
        return {**base, "status": "failed", "task_status": reported,
                "error_code": "reported_" + reported, "error": text, "evidence_source": "assistant_report"}
    errors = [r for r in data.get("tool_results", []) if r["kind"] == "bridge_response" and r["ok"] is False]
    if done and errors and verification is None:
        last = errors[-1]
        return {**base, "status": "failed", "task_status": "needs_review", "error_code": "tool_error",
                "error": last.get("raw_error") or last.get("error"), "evidence_source": "tool_return"}
    return base


def legacy_outcome(data: dict) -> dict:
    """Read-only reinterpretation. Never mutate or relabel historical evidence on disk."""
    messages = data.get("messages") or []
    d = digest({"msgs": messages}, -1)
    d.update(final_text=data.get("final_text", ""), final_end_turn=data.get("final_end_turn", True),
             final_status=data.get("final_status", "finished_successfully"))
    result = outcome(d)
    result["legacy_reclassified"] = True
    return result
