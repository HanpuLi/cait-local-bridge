# Changelog

All notable public changes are recorded here. The project follows Semantic Versioning once a public release exists.

## [0.2.1] - 2026-09-19

Security and release-engineering hardening.

- Paperless HomeLab credentials now use macOS Keychain; ScopeRail stores only non-secret lookup metadata for new configurations.
- Forgejo credentials are resolved through Git credential helpers rather than parsing `~/.git-credentials`.
- OAuth end-to-end evidence no longer serializes access/refresh tokens, and the standalone test client no longer persists them.
- Release asset handoffs verify `SHA256SUMS`; release reruns preserve existing assets instead of clobbering them.
- The MCP Registry publisher download is version-pinned and verified by upstream SHA-256 before execution.
- CodeQL scanning and Dependabot security updates are enabled on the public repository.

## [0.2.0] - 2026-09-19

Renamed the public project from Cait Local Bridge to **ScopeRail**.

- New public repository, package, CLI and MCP Registry identity: `scoperail`.
- New primary local control command: `scoperailctl`.
- New public environment prefix: `SCOPERAIL_*`.
- Existing `~/.cait-local-bridge`, `CLB_*`, `bridgectl` and the legacy launchd label remain upgrade-compatible where needed.
- Linux CI now runs only platform-neutral tests; macOS-only Quartz/AppKit coverage remains on macOS runners.
- Release recovery verifies and reuses exact published artifacts instead of rebuilding the same version from a later commit.

## [0.1.0] - 2026-09-19

Initial public release under the former project name.

- Workspace-scoped filesystem operations with retry-safe writes and conflict detection.
- Sandboxed and explicitly trusted-host process execution, PTY jobs and persistent shell sessions.
- OAuth-protected remote MCP service plus a local stdio transport.
- Managed Chromium/Playwright control and explicit attachment to loopback CDP sessions.
- macOS Accessibility-first semantic UI control with stable element references and coordinate fallback.
- Parameter-bound grants for sensitive actions such as desktop control and Git publishing.
- Audit records, persistent state, schedules and deterministic orchestration primitives.
- Fresh-history public export pipeline with private-marker checks and gitleaks integration.
