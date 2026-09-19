# Architecture

ScopeRail is a scoped control plane around local execution surfaces. The connected MCP client supplies intent; the bridge resolves that intent into bounded operations and records what actually ran.

## Layers

1. Transport/authentication. bridge.server provides OAuth-protected streamable HTTP. bridge.stdio is a separate local-only stdio process. The HTTP process never enables the stdio trust shortcut.
2. Workspace and grant policy. bridge.policy maps opaque workspace IDs to roots, profiles, network mode and parameter-bound grants.
3. Execution surfaces:
   - bridge.files: reads, search, atomic writes, patches and trash-based deletion.
   - bridge.jobs / bridge.shells: one-shot jobs, PTYs and persistent zsh sessions.
   - bridge.gitops: Git reads plus grant-gated publishing.
   - bridge.browser: managed Playwright plus explicitly configured loopback CDP attachment.
   - bridge.desktop / bridge.semantic_ui: macOS input, screenshots and Accessibility-first semantic control.
4. State and orchestration. SQLite stores workspaces, grants, jobs, state, schedules, auth state and audit receipts. Higher-level orchestration composes the same primitives rather than bypassing policy.
5. Operator-only integrations. HomeLab endpoints, browser profiles, workspace paths, hostnames, sidecars and credentials live in local config/state rather than public source.

## Public/private boundary

The public repository contains reusable runtime code, tests, docs, examples and packaging. It must not contain actual workspace IDs, personal paths, private hostnames/endpoints, browser profiles, credentials or machine evidence.

The operational repository may contain private acceptance evidence. Maintainers construct this public tree from an explicit allowlist and fresh Git history before publication. Public releases never inherit the private repository history; the public tree validates its own required files and private-marker invariants with `scripts/verify_public_tree.py`.

## Mutation model

Mutating file APIs use optimistic concurrency where applicable: a changed observed file fails with conflict rather than being overwritten. Retriable operations use idempotency keys where supported. Destructive file deletion moves into bridge-managed trash rather than using rm -rf.

Workspace path resolution is deliberately fail-closed. It rejects parent traversal, control characters, lexical escape, and existing or broken symlink ancestors that resolve outside the registered root. This is still a **user-space preflight check**, not a kernel-level filesystem transaction: another process running as the same user can race a validated path component between resolution and a later open/write. Seatbelt confines sandboxed jobs separately, and callers must not describe `resolve_in_workspace` as eliminating same-user TOCTOU races.

## Platform boundary

The first production runtime is macOS. Seatbelt, Accessibility, Quartz and AppKit are macOS-specific. Platform-neutral policy/file logic should remain separable so future adapters do not require false claims of current Linux or Windows parity.
