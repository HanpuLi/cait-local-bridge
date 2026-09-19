# Roadmap

ScopeRail is macOS-first. Roadmap items are product needs and distribution work, not promises and not contributor-count targets.

Current public baseline: **v0.2.2**.

## Near term

- Complete the first **PyPI Trusted Publishing** release using the existing GitHub OIDC workflow, then publish the matching MCP Registry entry only after the referenced PyPI package exists.
- Verify the post-PyPI install path (`pipx install scoperail`) against the exact release version and keep GitHub release bytes / `SHA256SUMS` immutable.
- Continue hardening workspace confinement, optimistic-concurrency writes, browser destination policy, CDP reconnect behaviour and semantic-UI stale-reference handling with regression tests.
- Keep release/supply-chain controls explicit: commit-pinned Actions, gitleaks, CodeQL, package clean-install verification and append-only release artifacts.
- Improve contributor-facing diagnostics for workspace policy, permissions and environment setup without weakening fail-closed defaults.
- Collect **real adoption evidence** only after public package/registry distribution exists. Do not create artificial dependents, downloads, PRs or contributors.

## Medium term

- Establish a stable Developer ID Application signing + notarisation path for any prebuilt macOS app/binary distribution that warrants one.
- Expand client integration documentation only where the client path is actually exercised; avoid claiming continuously tested compatibility that CI does not cover.
- Improve structured audit export, redaction and operational observability while keeping model reasoning outside the runtime.
- Extract platform interfaces needed for future Linux/Windows process backends only where doing so does not weaken the macOS security model.

## External ecosystem work

The maintainer's current Claude for Open Source baseline is tracked in:

- `docs/CLAUDE_OSS_ELIGIBILITY.md`
- `metrics/claude-oss-account.json`

Project work should not be chosen to inflate eligibility metrics. External OSS contributions belong in upstream projects where they solve real problems; ScopeRail should earn dependents, downloads and contributors through actual usefulness.

## Explicitly out of scope

- becoming an autonomous agent runtime;
- embedding or routing to a second model;
- silently granting host-wide access;
- fake cross-platform claims;
- self-dependent repo/package farms;
- artificial download or contributor activity;
- security features that exist only in documentation and are not enforced/tested.
