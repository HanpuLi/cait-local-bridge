"""repo_outline: one call that gives a coding session its bearings — the file tree (git-tracked files when the workspace is a
repository, so ignored build output never shows) with line counts, plus a symbol outline (classes / functions / exports) per source
file from a handful of per-language regexes. No ctags dependency, no model; results are capped so the whole picture fits in one
tool result instead of a dozen file_list / file_read calls."""
from __future__ import annotations
import json, os, re, subprocess
from pathlib import Path
from .files import SKIP_DIRS
from .policy import BridgeError, workspace_get, resolve_in_workspace

# language -> (extensions, [ (kind, regex with a named group 'name') ])
_LANG = {
    "python": ((".py",), [("class", r"^\s*class\s+(?P<name>\w+)"), ("def", r"^\s*(?:async\s+)?def\s+(?P<name>\w+)")]),
    "javascript": ((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"), [
        ("class", r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+(?P<name>\w+)"),
        ("function", r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(?P<name>\w+)"),
        ("const", r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>"),
        ("interface", r"^\s*(?:export\s+)?(?:interface|type|enum)\s+(?P<name>\w+)")]),
    "go": ((".go",), [("func", r"^func\s+(?:\([^)]*\)\s*)?(?P<name>\w+)"), ("type", r"^type\s+(?P<name>\w+)")]),
    "rust": ((".rs",), [("fn", r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(?P<name>\w+)"),
                        ("type", r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait|impl(?:<[^>]*>)?)\s+(?P<name>[\w:<>]+)")]),
    "ruby": ((".rb",), [("class", r"^\s*(?:class|module)\s+(?P<name>[\w:]+)"), ("def", r"^\s*def\s+(?P<name>[\w.?!=]+)")]),
    "shell": ((".sh", ".zsh", ".bash"), [("function", r"^\s*(?:function\s+)?(?P<name>[\w-]+)\s*\(\)\s*\{?")]),
    "swift": ((".swift",), [("type", r"^\s*(?:public\s+|private\s+|internal\s+|final\s+)*(?:class|struct|enum|protocol|extension)\s+(?P<name>\w+)"),
                            ("func", r"^\s*(?:public\s+|private\s+|internal\s+|static\s+|override\s+)*func\s+(?P<name>\w+)")]),
    "java": ((".java", ".kt", ".scala"), [("type", r"^\s*(?:public\s+|private\s+|protected\s+|abstract\s+|final\s+|data\s+)*(?:class|interface|enum|object)\s+(?P<name>\w+)"),
                                          ("method", r"^\s*(?:public\s+|private\s+|protected\s+|static\s+|override\s+|suspend\s+)*(?:fun\s+|[\w<>\[\], ]+\s+)(?P<name>\w+)\s*\([^;]*\)\s*(?:\{|=|:)")]),
    "c": ((".c", ".h", ".cpp", ".cc", ".hpp", ".m", ".mm"), [("function", r"^[\w:<>*&\s]+?\b(?P<name>\w+)\s*\([^;]*\)\s*(?:const\s*)?\{"),
                                                            ("type", r"^\s*(?:typedef\s+)?(?:struct|class|enum|union)\s+(?P<name>\w+)")]),
}
_EXT = {e: (lang, [(k, re.compile(rx)) for k, rx in rules]) for lang, (exts, rules) in _LANG.items() for e in exts}
_TEST_HINT = re.compile(r"(^|/)(tests?|spec|__tests__)(/|$)|(^|/)test_[^/]+\.py$|[._-](test|spec)\.[jt]sx?$")


def _tracked(root: Path, base: Path) -> list[str] | None:
    """Files git knows about under `base` (tracked + untracked-but-not-ignored), as workspace-relative paths. Runs git from `base`
    itself so a nested worktree (coding_task's .clb/<id>/wt) or a repository below the workspace root is listed by its own index."""
    try:
        chk = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], capture_output=True, cwd=base, timeout=10)
        if chk.returncode != 0 or chk.stdout.strip() != b"true":
            return None
        r = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "."], capture_output=True, cwd=base, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    prefix = base.relative_to(root)
    return [str(prefix / x.decode("utf-8", "replace")) if str(prefix) != "." else x.decode("utf-8", "replace") for x in r.stdout.split(b"\0") if x]


def _walk(root: Path, base: Path) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in SKIP_DIRS)
        for f in sorted(filenames):
            if not f.startswith("."):
                out.append(str((Path(dirpath) / f).relative_to(root)))
    return out


def _symbols(p: Path, rules: list, max_symbols: int) -> tuple[list[dict], int, bool]:
    syms, n_lines, truncated = [], 0, False
    try:
        with open(p, "rb") as f:
            for i, raw in enumerate(f, 1):
                n_lines = i
                if len(syms) >= max_symbols:
                    truncated = True
                    continue
                line = raw.decode("utf-8", "replace")
                for kind, rx in rules:
                    m = rx.match(line)
                    if m:
                        indent = len(line) - len(line.lstrip())
                        syms.append({"line": i, "kind": kind, "name": m.group("name"), "depth": 1 if indent else 0})
                        break
    except OSError:
        pass
    return syms, n_lines, truncated


def outline(workspace_id: str, path: str = ".", max_files: int = 400, max_symbols_per_file: int = 60, symbols: bool = True,
            include_globs: list[str] | None = None, max_chars: int = 40000) -> dict:
    ws = workspace_get(workspace_id); root = Path(ws["root"])
    base = resolve_in_workspace(ws, path)
    if not base.is_dir():
        raise BridgeError("invalid_argument", f"not a directory: {path}")
    listed = _tracked(root, base)
    source = "git" if listed is not None else "walk"
    if listed is None:
        listed = _walk(root, base)
    if include_globs:
        import fnmatch
        listed = [f for f in listed if any(fnmatch.fnmatch(f, g) for g in include_globs)]
    listed = [f for f in listed if not any(part in SKIP_DIRS for part in Path(f).parts[:-1])]
    files, total_lines, langs = [], 0, {}
    budget = max(4000, int(max_chars)); spent = 0; symbols_dropped = 0
    for rel in listed[:max_files]:
        p = root / rel
        if not p.is_file():
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        lang, rules = _EXT.get(p.suffix.lower(), (None, []))
        entry = {"path": rel, "size": size}
        if lang and size <= 2_000_000:
            syms, n_lines, trunc = _symbols(p, rules, max_symbols_per_file) if symbols else ([], 0, False)
            if not symbols:
                try:
                    n_lines = sum(1 for _ in open(p, "rb"))
                except OSError:
                    n_lines = 0
            entry.update({"lang": lang, "lines": n_lines})
            if syms and spent < budget:
                entry["symbols"] = syms
            elif syms:
                symbols_dropped += 1    # over the character budget: keep the file, drop its outline (ask for a sub-path or include_globs)
            if trunc:
                entry["symbols_truncated"] = True
            total_lines += n_lines
            langs[lang] = langs.get(lang, 0) + 1
        if _TEST_HINT.search(rel):
            entry["test"] = True
        files.append(entry)
        spent += len(json.dumps(entry))
    rule_files = [str(Path(rel_base) / f) if rel_base != "." else f for f in ("README.md", "AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md") for rel_base in [str(base.relative_to(root))] if (base / f).exists()]
    tests = [f["path"] for f in files if f.get("test")]
    return {"path": path, "source": source, "file_count": len(listed), "shown": len(files), "truncated": len(listed) > max_files,
            "languages": langs, "source_lines": total_lines, "rule_files": rule_files, "test_files": tests[:50], "files": files,
            "symbols_dropped_for_budget": symbols_dropped, "hint": ("over max_chars: symbols omitted for some files — call again with a sub-path or include_globs" if symbols_dropped else None)}
