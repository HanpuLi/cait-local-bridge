# Contributing

ScopeRail is security-sensitive local execution software. Contributions are welcome when they make a real capability safer, more portable, easier to operate, or easier to understand.

## Before coding

1. Search existing issues and discussions.
2. For security vulnerabilities, follow `SECURITY.md` instead of opening a public issue.
3. Keep changes narrow. Do not weaken workspace, grant, OAuth, sandbox or audit boundaries to make a feature easier.
4. Do not add operator-specific paths, endpoints, account names, browser profiles, credentials or test fixtures.

## Development

Use Python 3.12 or newer on macOS:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
python -m unittest discover -s tests -p 'test_*.py' -v
ruff check --select E9,F63,F7,F82 bridge tests scripts
python -m build
twine check dist/*
```

Native desktop tests require macOS. Pure policy/file logic should stay portable enough to run on Linux CI where practical.

## Pull requests

A PR should explain the problem, the security/permission impact, how it was tested, and any platform assumptions. Add regression tests for bug and security fixes. Public APIs and user-facing behavior require docs or changelog updates.

By submitting a contribution, you agree that it is licensed under Apache-2.0 under the terms described in `LICENSE`.

See `docs/contributing-architecture.md` for module boundaries and `docs/security-model.md` before touching authorization, paths, process execution, browser networking or desktop control.
