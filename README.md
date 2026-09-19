# Cait Local Bridge

<!-- mcp-name: io.github.hanpuli/cait-local-bridge -->

Cait Local Bridge is a local-first MCP execution bridge for AI clients that need to work on a real Mac without receiving unrestricted host access by default. Files, processes, browser sessions and native desktop UI are exposed through one workspace capability model with explicit grants and auditable actions.

It is not just a shell MCP. Shell access is one surface inside a broader permission model: a caller starts from a registered workspace, receives only the profiles and grants the operator enabled, and uses retry-safe primitives that return provenance and observable results.

## Install and run

Python 3.12+ and `pipx` on macOS:

```sh
brew install pipx  # skip if pipx is already installed
pipx install "https://github.com/HanpuLi/cait-local-bridge/releases/download/v0.1.0/cait_local_bridge-0.1.0-py3-none-any.whl"
CLB_WORKSPACE_ROOT="$PWD" cait-local-bridge stdio
```

The tagged GitHub wheel is the current working install path and is tested with `pipx`. PyPI Trusted Publishing is prepared but the first PyPI upload still requires the maintainer's one-time PyPI login; after that, `pipx install cait-local-bridge` is equivalent.

Or register once, then start stdio:

```sh
cait-local-bridge init "$PWD"
cait-local-bridge stdio
```

For the full OAuth HTTP service, launchd installation and optional reverse-proxy/Tailscale deployment, see [docs/install.md](docs/install.md).

> **Security:** `sandboxed` execution is the default. `trusted-host`, desktop control, Git publishing and similar capabilities are explicit operator choices. Read [SECURITY.md](SECURITY.md) and [docs/security-model.md](docs/security-model.md) before enabling them.

## What is different

| Surface | Boundary |
| --- | --- |
| Files | Workspace-confined paths, symlink-aware resolution, conflict-checked writes |
| Commands / PTY | macOS Seatbelt sandbox by default; explicit `trusted-host` profile for full user authority |
| Persistent shells | Named zsh sessions built on the same job/process boundary |
| Browser | Managed Playwright profile plus explicit attachment to loopback Chromium CDP sessions |
| Native UI | macOS Accessibility semantic tree and fingerprinted refs, with coordinate fallback |
| Git publish | Read operations are separate from parameter-bound publish grants |
| Audit/state | Request IDs, provenance, audit records, persistent workspace state |

The bridge does not embed a model. The connected client decides what to do; the bridge enforces and records the execution boundary.

```text
MCP client
   |
   +-- local stdio --------------------------------+
   |                                               |
   +-- OAuth 2.1 / remote HTTPS -- public plane ---+
                                                   v
                                      workspace + grant policy
                                      |      |       |
                           +----------+      |       +----------+
                           v                 v                  v
                       files/git        jobs/shells        browser/native UI
                           |                 |                  |
                           +-------- audit + provenance --------+
```

## Platform and client status

Cait Local Bridge is **macOS-first**. Native Accessibility control and the Seatbelt sandbox are macOS features. Pure policy/file/package tests may run on Linux CI, but Linux and Windows are not currently advertised as complete runtime platforms.

- **Generic MCP clients:** local stdio transport is supported.
- **ChatGPT:** remote OAuth/streamable-HTTP is the primary deployed integration and is exercised by the project.
- **Claude / Codex / other MCP clients:** the stdio server uses the standard MCP SDK transport; client-specific setup is documented as integration work rather than claimed as continuously tested compatibility.

## Native semantic UI

The native desktop path prefers Accessibility over coordinate-only clicking. Observation returns semantic elements and bounds; element actions use fingerprinted `ax:` refs and fail closed when the target becomes stale, ambiguous or materially moves. Secure values are redacted and secure fields reject semantic value-setting.

Screenshot, mouse and keyboard primitives remain available for apps with incomplete Accessibility trees.

## Browser sessions

The managed browser uses a bridge-owned profile. A trusted-host workspace may also attach to an already-running Chromium-family browser only through an operator-configured loopback DevTools endpoint. Existing tabs are treated as external resources: detaching the bridge does not close them.

## Remote service

A source checkout can run the full HTTP service with OAuth 2.1, PKCE, dynamic client registration, token rotation/revocation and DNS-rebinding protections. The admin plane listens separately on loopback and is not exposed through the public MCP route.

See [docs/quickstart.md](docs/quickstart.md), [docs/permissions.md](docs/permissions.md) and [docs/workspaces.md](docs/workspaces.md).

## Development

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
python -m unittest discover -s tests -p 'test_*.py' -v
ruff check --select E9,F63,F7,F82 bridge tests scripts
python -m build
twine check dist/*
```

The maintainer's operational repository may contain machine-specific acceptance evidence. Release candidates are produced as an allowlisted fresh-history tree before they reach this public repository. `scripts/verify_public_tree.py`, CI secret scanning and package checks enforce the public-tree invariants; the private operational Git history is never imported here.

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md), the [architecture](docs/architecture.md) and the [security model](docs/security-model.md). Issues intended for contributors describe the problem and acceptance criteria; the project does not create trivial work to inflate contributor counts.

## License

Apache-2.0. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.
