"""File tools: list / glob / search / read / write / patch / move / copy / quarantine, all inside a registered workspace,
with SHA-256 revisions and expected-hash checks so nothing silently overwrites a file changed by someone else."""
from __future__ import annotations
import base64, difflib, fnmatch, hashlib, mimetypes, os, re, shutil, subprocess, tempfile, time, uuid
from pathlib import Path
from . import db
from .config import STATE_DIR, load_config
from .policy import BridgeError, workspace_get, resolve_in_workspace, sha256_file

CFG = load_config()
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pw", "dist", ".next", ".cache"}
TEXT_MIMES = ("text/", "application/json", "application/xml", "application/javascript", "application/x-sh", "application/toml", "application/yaml")


def _stat(p: Path) -> dict:
    st = p.lstat()
    d = {"path": str(p), "type": "symlink" if p.is_symlink() else "dir" if p.is_dir() else "file", "size": st.st_size, "mtime": st.st_mtime}
    if p.is_symlink():
        d["target"] = os.readlink(p)
    return d


def list_dir(workspace_id: str, path: str = ".", depth: int = 1, include_hidden: bool = False, limit: int = 500) -> dict:
    ws = workspace_get(workspace_id)
    base = resolve_in_workspace(ws, path)
    if not base.is_dir():
        raise BridgeError("invalid_argument", f"not a directory: {path}")
    root = Path(ws["root"])
    entries, truncated = [], False
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        rel_depth = len(Path(dirpath).relative_to(base).parts)
        dirnames[:] = sorted(d for d in dirnames if (include_hidden or not d.startswith(".")) and d not in SKIP_DIRS)
        if rel_depth >= depth:
            dirnames[:] = []
        for n in sorted(dirnames) + sorted(f for f in filenames if include_hidden or not f.startswith(".")):
            p = Path(dirpath) / n
            e = _stat(p); e["path"] = str(p.relative_to(root))
            entries.append(e)
            if len(entries) >= limit:
                truncated = True; break
        if truncated:
            break
    return {"workspace_id": workspace_id, "root": str(root), "entries": entries, "truncated": truncated}


def glob(workspace_id: str, pattern: str, limit: int = 1000) -> dict:
    ws = workspace_get(workspace_id); root = Path(ws["root"])
    out = []
    for p in sorted(root.glob(pattern)):
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts[:-1]):
            continue
        try:
            resolve_in_workspace(ws, str(p.relative_to(root)))
        except BridgeError:
            continue
        out.append({"path": str(p.relative_to(root)), "type": "dir" if p.is_dir() else "file", "size": p.stat().st_size if p.is_file() else None})
        if len(out) >= limit:
            return {"matches": out, "truncated": True}
    return {"matches": out, "truncated": False}


def search(workspace_id: str, pattern: str, path: str = ".", regex: bool = True, case_sensitive: bool = False,
           glob_filter: str | None = None, max_results: int = 200, context: int = 0) -> dict:
    """ripgrep-backed search returning real file paths and 1-based line numbers."""
    ws = workspace_get(workspace_id)
    base = resolve_in_workspace(ws, path)
    cmd = ["rg", "--json", "--max-count", "50", "--no-messages", "-C", str(context)]
    if not regex: cmd.append("-F")
    if not case_sensitive: cmd.append("-i")
    if glob_filter: cmd += ["-g", glob_filter]
    for d in SKIP_DIRS: cmd += ["-g", f"!{d}"]
    cmd += ["--", pattern, str(base)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise BridgeError("missing_dependency", "ripgrep (rg) not installed")
    import json
    hits, truncated = [], False
    root = Path(ws["root"])
    for line in r.stdout.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("type") in ("match", "context"):
            d = ev["data"]
            hits.append({"path": str(Path(d["path"]["text"]).relative_to(root)), "line": d["line_number"],
                         "kind": ev["type"], "text": d["lines"]["text"].rstrip("\n")[:500]})
            if len(hits) >= max_results:
                truncated = True; break
    return {"pattern": pattern, "hits": hits, "truncated": truncated, "exit_code": r.returncode}


def read(workspace_id: str, path: str, start_line: int | None = None, end_line: int | None = None,
         byte_offset: int = 0, max_bytes: int | None = None, encoding: str = "utf-8") -> dict:
    ws = workspace_get(workspace_id)
    p = resolve_in_workspace(ws, path)
    if not p.is_file():
        raise BridgeError("invalid_argument", f"not a file: {path}")
    max_bytes = min(int(max_bytes or CFG["max_read_bytes"]), CFG["max_read_bytes"])
    size = p.stat().st_size
    sha = sha256_file(p)
    mime = mimetypes.guess_type(str(p))[0] or "application/octet-stream"
    if start_line is not None:
        with open(p, "rb") as f:
            raw = f.read(CFG["max_read_bytes"] * 4)
        text = raw.decode(encoding, "replace")
        lines = text.splitlines(keepends=True)
        s = max(1, int(start_line)); e = int(end_line or s + 200)
        chunk = "".join(lines[s - 1:e])
        return {"path": path, "size": size, "sha256": sha, "mime": mime, "encoding": encoding, "start_line": s,
                "end_line": min(e, len(lines)), "total_lines": len(lines), "text": chunk[:max_bytes],
                "truncated": len(chunk) > max_bytes or len(raw) < size}
    with open(p, "rb") as f:
        f.seek(byte_offset); data = f.read(max_bytes)
    is_text = mime.startswith(TEXT_MIMES) or b"\x00" not in data[:8192]
    out = {"path": path, "size": size, "sha256": sha, "mime": mime, "byte_offset": byte_offset, "bytes_returned": len(data),
           "next_offset": byte_offset + len(data) if byte_offset + len(data) < size else None, "truncated": byte_offset + len(data) < size}
    if is_text:
        out["encoding"] = encoding; out["text"] = data.decode(encoding, "replace")
    else:
        out["encoding"] = "base64"; out["base64"] = base64.b64encode(data).decode()
    return out


def _atomic_write(p: Path, data: bytes) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".clb-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        if p.exists():
            shutil.copymode(p, tmp)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def write(workspace_id: str, path: str, content: str, expected_sha256: str | None = None, create_only: bool = False,
          encoding: str = "utf-8", base64_content: bool = False, subject: str | None = None) -> dict:
    ws = workspace_get(workspace_id)
    p = resolve_in_workspace(ws, path, must_exist=False, allow_root=False)
    if p.is_dir():
        raise BridgeError("invalid_argument", f"is a directory: {path}")
    if p.exists():
        if create_only:
            raise BridgeError("conflict", f"file exists: {path}")
        cur = sha256_file(p)
        data = base64.b64decode(content) if base64_content else content.encode(encoding)
        if cur == hashlib.sha256(data).hexdigest():
            # the file already holds exactly this content: a retried call (e.g. after OpenAI dropped the first one) is a no-op, not a conflict
            return {"path": path, "bytes": len(data), "sha256": cur, "already_applied": True}
        if expected_sha256 is None:
            raise BridgeError("conflict", f"file exists; pass expected_sha256={cur} (read it first) to overwrite")
        if cur != expected_sha256:
            raise BridgeError("conflict", f"file changed since you read it: current sha256={cur}, expected={expected_sha256}")
    elif expected_sha256 not in (None, "", "new"):
        raise BridgeError("conflict", "expected_sha256 given but file does not exist (pass 'new' or omit)")
    data = base64.b64decode(content) if base64_content else content.encode(encoding)
    _atomic_write(p, data)
    db.audit("file_write", f"{path} bytes={len(data)}", subject=subject, workspace_id=workspace_id)
    return {"path": path, "bytes": len(data), "sha256": sha256_file(p)}


def apply_patch(workspace_id: str, unified_diff: str, expected: dict[str, str] | None = None, subject: str | None = None) -> dict:
    """Apply a unified diff (possibly multi-file) with GNU patch in dry-run first; all-or-nothing when the dry run
    succeeds, otherwise nothing is touched. Files may be created (/dev/null source) or deleted."""
    ws = workspace_get(workspace_id); root = Path(ws["root"])
    files = re.findall(r"^\+\+\+ (?:b/)?(\S+)", unified_diff, re.M) + re.findall(r"^--- (?:a/)?(\S+)", unified_diff, re.M)
    targets = sorted({f for f in files if f != "/dev/null"})
    for t in targets:
        resolve_in_workspace(ws, t, must_exist=False)
    before = {}
    for t in targets:
        p = root / t
        before[t] = sha256_file(p) if p.is_file() else None
        if expected and t in expected and expected[t] != (before[t] or "new"):
            raise BridgeError("conflict", f"{t}: current sha256={before[t]} expected={expected[t]}")
    def run(dry: bool, reverse: bool = False):
        cmd = ["patch", "-p1", "--batch", "--forward", "-r", "-"] + (["--dry-run"] if dry else []) + (["-R"] if reverse else [])
        return subprocess.run(cmd, input=unified_diff, capture_output=True, text=True, cwd=root, timeout=60)
    d = run(True)
    if d.returncode != 0:
        if run(True, reverse=True).returncode == 0:
            # every hunk is already in place (same patch sent twice, e.g. a verbatim retry after an upstream drop): nothing to do, not a rejection
            return {"ok": True, "applied": False, "already_applied": True, "files": [{"path": t, "sha256_before": before[t], "sha256_after": before[t]} for t in targets]}
        return {"ok": False, "applied": False, "error": "patch_rejected", "output": (d.stdout + d.stderr)[-4000:], "files": targets}
    r = run(False)
    after = {t: (sha256_file(root / t) if (root / t).is_file() else None) for t in targets}
    db.audit("apply_patch", f"files={targets} rc={r.returncode}", subject=subject, workspace_id=workspace_id)
    return {"ok": r.returncode == 0, "applied": r.returncode == 0, "output": (r.stdout + r.stderr)[-4000:],
            "files": [{"path": t, "sha256_before": before[t], "sha256_after": after[t]} for t in targets]}


def edit(workspace_id: str, path: str, old: str, new: str, expected_sha256: str | None = None, replace_all: bool = False,
         encoding: str = "utf-8", subject: str | None = None) -> dict:
    """Replace one exact occurrence of `old` with `new` (Claude Code / Codex style edit): no whole-file round trip, no diff syntax to
    get wrong. Ambiguous (several matches, replace_all=False) or missing text is a conflict that touches nothing. Retry-safe: when `old`
    is gone but `new` is present the edit was already applied and the call returns ok with applied=False."""
    ws = workspace_get(workspace_id)
    p = resolve_in_workspace(ws, path, allow_root=False)
    if not p.is_file():
        raise BridgeError("invalid_argument", f"not a file: {path}")
    if not old:
        raise BridgeError("invalid_argument", "old is empty; use file_write to create or overwrite a file")
    if old == new:
        raise BridgeError("invalid_argument", "old and new are identical")
    cur = sha256_file(p)
    if expected_sha256 and cur != expected_sha256:
        raise BridgeError("conflict", f"file changed since you read it: current sha256={cur}, expected={expected_sha256}")
    text = p.read_bytes().decode(encoding, "replace")
    n = text.count(old)
    if n == 0:
        if new and new in text:
            return {"path": path, "applied": False, "already_applied": True, "sha256": cur, "replacements": 0}
        raise BridgeError("conflict", f"old text not found in {path} (match is exact, including whitespace and indentation); re-read the file")
    if n > 1 and not replace_all:
        lines = [i + 1 for i, l in enumerate(text.splitlines()) if old.splitlines()[0] in l][:10]
        raise BridgeError("conflict", f"old text occurs {n} times in {path} (first lines: {lines}); add surrounding context to make it unique or pass replace_all=true")
    line = text[: text.index(old)].count("\n") + 1
    out = text.replace(old, new) if replace_all else text.replace(old, new, 1)
    _atomic_write(p, out.encode(encoding))
    after = sha256_file(p)
    diff = "".join(difflib.unified_diff(text.splitlines(True), out.splitlines(True), f"a/{path}", f"b/{path}", n=2))
    db.audit("file_edit", f"{path} line={line} replacements={n if replace_all else 1}", subject=subject, workspace_id=workspace_id)
    return {"path": path, "applied": True, "replacements": n if replace_all else 1, "first_line": line, "sha256_before": cur, "sha256": after,
            "diff": diff[:6000], "diff_truncated": len(diff) > 6000}


def diff_text(workspace_id: str, path: str, new_content: str) -> dict:
    ws = workspace_get(workspace_id); p = resolve_in_workspace(ws, path)
    old = p.read_text(errors="replace")
    d = "".join(difflib.unified_diff(old.splitlines(True), new_content.splitlines(True), f"a/{path}", f"b/{path}"))
    return {"path": path, "sha256": sha256_file(p), "diff": d}


def mkdir(workspace_id: str, path: str, subject: str | None = None) -> dict:
    ws = workspace_get(workspace_id); p = resolve_in_workspace(ws, path, must_exist=False, allow_root=False)
    p.mkdir(parents=True, exist_ok=True)
    return {"path": path, "created": True}


def move(workspace_id: str, src: str, dst: str, overwrite: bool = False, copy: bool = False, subject: str | None = None) -> dict:
    ws = workspace_get(workspace_id)
    s = resolve_in_workspace(ws, src, allow_root=False); d = resolve_in_workspace(ws, dst, must_exist=False, allow_root=False)
    if d.exists() and not overwrite:
        raise BridgeError("conflict", f"destination exists: {dst}")
    d.parent.mkdir(parents=True, exist_ok=True)
    if copy:
        shutil.copytree(s, d, symlinks=True, dirs_exist_ok=overwrite) if s.is_dir() else shutil.copy2(s, d)
    else:
        shutil.move(str(s), str(d))
    db.audit("file_copy" if copy else "file_move", f"{src} -> {dst}", subject=subject, workspace_id=workspace_id)
    return {"src": src, "dst": dst, "copied": copy}


def quarantine(workspace_id: str, path: str, subject: str | None = None) -> dict:
    """Never rm -rf: moves the path into the bridge trash (~/.scoperail/trash/<ws>/<ts>-<name>), restorable by the user."""
    ws = workspace_get(workspace_id); p = resolve_in_workspace(ws, path, allow_root=False)
    tdir = STATE_DIR / "trash" / workspace_id
    tdir.mkdir(parents=True, exist_ok=True)
    dest = tdir / f"{int(time.time())}-{uuid.uuid4().hex[:6]}-{p.name}"
    shutil.move(str(p), str(dest))
    db.audit("file_quarantine", f"{path} -> {dest}", subject=subject, workspace_id=workspace_id)
    return {"path": path, "quarantined_to": str(dest)}
