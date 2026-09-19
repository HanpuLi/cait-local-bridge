# Contributor architecture guide

Choose the narrowest module that owns the invariant you are changing.

- policy.py: workspace, grant, network authorization and path boundaries.
- files.py: filesystem operations after policy resolution.
- jobs.py: process spawning, Seatbelt profile, environment, timeout and lifecycle.
- shells.py: persistent shell state layered on jobs.
- gitops.py: Git command surface and publish grant checks.
- browser.py: Playwright/CDP session ownership and destination policy.
- desktop.py: screenshots, input and application lifecycle.
- semantic_ui.py: Accessibility tree, stable refs, semantic actions and waits.
- auth.py / server.py: OAuth, MCP transport and tool registration.
- db.py: control-plane schema and audit storage.

Do not fix a caller inconvenience by bypassing the owning boundary. Browser code, for example, must not read arbitrary host files because a test needs a cookie; tests should use disposable profiles.

Public code must not introduce real operator paths, IDs, endpoints or credentials. Tests should use temporary directories, synthetic hosts and clearly fake tokens.

Security fixes require a regression test that would fail under the vulnerable implementation. Platform adapters should preserve the same high-level permission semantics even when the OS mechanism differs.
