# Roadmap

The public project is macOS-first. Roadmap items are product needs, not promises or contributor-count targets.

## Near term

- Stabilize the v0.1 public packaging, stdio installation path and release process.
- Expand regression coverage around workspace confinement, browser destination policy and semantic UI stale-reference behavior.
- Improve contributor-facing diagnostics for workspace policy and macOS permissions.

## Later, if maintainable

- Extract platform interfaces needed for Linux/Windows process and accessibility backends without weakening the macOS security model.
- Add additional browser backends only where they preserve explicit session/profile boundaries.
- Improve structured audit export and redaction.

Out of scope for now: becoming an autonomous agent runtime, embedding a model, silently granting host-wide access, or adding platform claims that are not continuously tested.
