"""Versioned work state written explicitly by ChatGPT (never a server-generated summary), plus the persistent inbox
that receives job completions and scheduled-run results for the next ChatGPT call to read."""
from __future__ import annotations
import json, time
from . import db
from .policy import BridgeError, workspace_get


def read(workspace_id: str, key: str | None = None, history: bool = False) -> dict:
    workspace_get(workspace_id)
    if key is None:
        rows = db.all_("SELECT key, revision, updated_at, length(content) AS size FROM state WHERE workspace_id=? ORDER BY key", workspace_id)
        return {"workspace_id": workspace_id, "keys": [dict(r) for r in rows]}
    r = db.one("SELECT * FROM state WHERE workspace_id=? AND key=?", workspace_id, key)
    if not r:
        return {"workspace_id": workspace_id, "key": key, "revision": 0, "content": None, "exists": False}
    out = {"workspace_id": workspace_id, "key": key, "revision": r["revision"], "updated_at": r["updated_at"], "content": json.loads(r["content"]), "exists": True}
    if history:
        out["history"] = [dict(h) for h in db.all_("SELECT revision, updated_at FROM state_history WHERE workspace_id=? AND key=? ORDER BY revision", workspace_id, key)]
    return out


def write(workspace_id: str, key: str, content, expected_revision: int | None = None, subject: str | None = None) -> dict:
    workspace_get(workspace_id)
    if len(key) > 200 or "/" in key:
        raise BridgeError("invalid_argument", "key must be a short name without '/'")
    body = json.dumps(content, ensure_ascii=False)
    if len(body) > 1_000_000:
        raise BridgeError("invalid_argument", "state entry over 1 MB; store large content as a file and reference it")
    r = db.one("SELECT revision, content, updated_at FROM state WHERE workspace_id=? AND key=?", workspace_id, key)
    cur = r["revision"] if r else 0
    if expected_revision is not None and expected_revision != cur:
        raise BridgeError("conflict", f"state '{key}' is at revision {cur}, expected {expected_revision}; read it and merge")
    if r:
        db.q("INSERT INTO state_history VALUES(?,?,?,?,?)", workspace_id, key, r["revision"], r["content"], r["updated_at"])
    db.q("INSERT OR REPLACE INTO state(workspace_id,key,revision,content,updated_at) VALUES(?,?,?,?,?)", workspace_id, key, cur + 1, body, time.time())
    db.audit("state_write", f"{key} rev={cur + 1} bytes={len(body)}", subject=subject, workspace_id=workspace_id)
    return {"workspace_id": workspace_id, "key": key, "revision": cur + 1}


def inbox_list(workspace_id: str, include_acked: bool = False, limit: int = 100) -> dict:
    workspace_get(workspace_id)
    rows = db.all_("SELECT * FROM inbox WHERE workspace_id=? AND (?2=1 OR acked=0) ORDER BY id DESC LIMIT ?3", workspace_id, 1 if include_acked else 0, limit)
    return {"workspace_id": workspace_id, "items": [{"id": r["id"], "kind": r["kind"], "payload": json.loads(r["payload"]), "created_at": r["created_at"], "acked": bool(r["acked"])} for r in rows]}


def inbox_ack(workspace_id: str, ids: list[int]) -> dict:
    workspace_get(workspace_id)
    for i in ids:
        db.q("UPDATE inbox SET acked=1 WHERE id=? AND workspace_id=?", int(i), workspace_id)
    return {"acked": ids}


def inbox_put(workspace_id: str, kind: str, payload: dict) -> None:
    db.q("INSERT INTO inbox(workspace_id,kind,payload,created_at) VALUES(?,?,?,?)", workspace_id, kind, json.dumps(payload, default=str), time.time())
