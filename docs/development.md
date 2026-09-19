# Development

Use Python 3.12 or newer. macOS is required for the complete runtime and native test surface.

    python3 -m venv .venv
    . .venv/bin/activate
    pip install -e '.[dev]'
    python -m unittest discover -s tests -p 'test_*.py' -v
    ruff check --select E9,F63,F7,F82 bridge tests scripts
    python -m compileall -q bridge scripts tests
    python -m build
    twine check dist/*

Run security-sensitive regression tests after changing path resolution, grants, process environments, OAuth, browser destination policy or Accessibility refs.

## Public-tree validation

The public repository is intentionally a fresh-history distribution tree. Run `python scripts/verify_public_tree.py` before release work, then run the full test, lint, build and secret-scan suite. Maintainers who develop from a private operational repository must generate this public tree through their private allowlist/export process before pushing it; private Git history is never imported.

## Versioning

bridge.__version__ is the single source of truth for Python package metadata. server.json, release tags and changelog entries must match it for a release.
