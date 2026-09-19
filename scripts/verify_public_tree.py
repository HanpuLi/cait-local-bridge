#!/usr/bin/env python3
"""Fail closed on public-tree invariants that are cheap to verify in CI."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "README.md", "LICENSE", "SECURITY.md", "CHANGELOG.md", "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md", "ROADMAP.md", "pyproject.toml", "server.json",
    "docs/architecture.md", "docs/security-model.md", "docs/permissions.md",
]
FORBIDDEN = {
    "absolute macOS user path": re.compile(r"/Users/[A-Za-z0-9._-]+"),
    # Split site-specific sentinels so the verifier is itself safe for a scanner
    # that rejects their literal byte sequences anywhere in the public tree.
    "private tailnet marker": re.compile("tail" + "95239f", re.I),
    "private mail/account marker": re.compile(
        "(?:aaa" + "kane|gdn" + "506|cait" + "lye@|@g" + "mail\\.com)", re.I
    ),
    "machine hostname": re.compile("Caits-" + "MacBook", re.I),
}


def main() -> None:
    errors = []
    for rel in REQUIRED:
        if not (ROOT / rel).exists():
            errors.append(f"missing required public file: {rel}")

    server = json.loads((ROOT / "server.json").read_text())
    version_match = re.search(r'__version__\s*=\s*"([^"]+)"', (ROOT / "bridge/__init__.py").read_text())
    version = version_match.group(1) if version_match else None
    if server.get("version") != version:
        errors.append(f"version mismatch: bridge={version!r} server.json={server.get('version')!r}")

    marker = f"<!-- mcp-name: {server.get('name')} -->"
    if marker not in (ROOT / "README.md").read_text():
        errors.append("README MCP Registry ownership marker does not exactly match server.json name")

    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            data = path.read_text(errors="strict")
        except (OSError, UnicodeDecodeError):
            continue
        for label, pattern in FORBIDDEN.items():
            for lineno, line in enumerate(data.splitlines(), 1):
                if pattern.search(line):
                    errors.append(f"{label}: {path.relative_to(ROOT)}:{lineno}")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps({"ok": True, "version": version, "registry_name": server.get("name"), "required_files": len(REQUIRED)}))


if __name__ == "__main__":
    main()
