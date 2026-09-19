# Security model

ScopeRail can execute code and control a logged-in desktop. Its security model is capability reduction and auditability, not a claim that arbitrary local execution is harmless.

## Threat model

The primary threat is a connected client attempting a broader operation than the operator intended: reading outside a workspace, escaping through symlinks, inheriting credentials, reaching private services, controlling the desktop without a grant, or publishing Git changes without bound authorization.

The bridge assumes the local macOS user and the bridge process are trusted. It does not defend against malware or another process already running with the same user's full authority and racing local filesystem state.

## Trust boundaries

- Remote HTTP: OAuth is mandatory and tied to the configured operator subject.
- Local stdio: a separately launched local process may use the configured operator identity without OAuth. This process-local switch is never enabled by the HTTP service.
- Admin plane: loopback-only and separately authenticated.
- Workspace: paths resolve inside a registered root; unsafe roots and control-plane state are rejected.
- Sandboxed process: macOS Seatbelt confines writes to the workspace/per-workspace HOME/temp, restricts reads from normal home and sensitive config paths, and disables network unless allowed.
- Trusted-host process: deliberately runs with the logged-in user's authority. It is not a sandbox.

## Filesystem confinement

Parent traversal and control characters are rejected. Existing paths are resolved through the filesystem, and a create checks the real path of the deepest existing or symlink ancestor so an existing or broken symlink cannot redirect it outside the workspace.

Single-file whole-content writes stage a temporary file in the destination directory and atomically replace one directory entry. `file_write_batch` validates and stages every bounded mutation before committing any target and attempts rollback on process-level commit failure, but the filesystem does not provide a globally atomic transaction spanning several paths. See [files.md](files.md).

A malicious same-user process can still race local filesystem state after a policy check. That is outside the present same-user threat model.

## Process execution

Sandboxed jobs receive a constructed environment rather than inheriting the bridge environment. Sensitive credential prefixes and preload/path injection variables are rejected or controlled. Argv execution is used where the API accepts argv; APIs that explicitly request a shell command run it through zsh because shell semantics are the granted capability.

Processes run in groups and are supervised for cancellation and timeout. Recovery marks interrupted jobs after restart.

## Native desktop

Desktop/Accessibility actions require an explicit workspace grant plus macOS TCC permission. Semantic refs carry identity/frame information and fail closed when stale or ambiguous. Secure values are redacted and secure fields reject semantic value-setting.

Granting raw screenshot, mouse or keyboard control means trusting the client to act as the logged-in user inside visible applications.

## Browser

The managed Playwright browser uses a bridge-owned profile. Existing-browser attachment is limited to operator-configured loopback DevTools endpoints. Browser profiles and logged-in state are local operator data and never belong in the public repository.

## Authentication, CORS and network

The remote service enables DNS-rebinding protection and restricts allowed hosts to the configured public host plus loopback service addresses. CORS is applied only where browser-based OAuth needs it; CORS is not authorization and tool access still requires OAuth.

## Audit and secrets

Audit records contain tool/result metadata, request IDs, subjects and workspace IDs but avoid full tool arguments. Secret material belongs in local state/credential stores. Public export checks known private markers and gitleaks findings.

## Destructive operations

File deletion is trash-based. Git publish uses parameter-bound grants. trusted-host, desktop, SSH and comparable capabilities are explicit escalations rather than caller booleans.

## Not protected against

The bridge does not claim protection against OS/runtime compromise, malicious same-user processes, actions explicitly allowed through trusted-host or desktop grants, secrets already visible in an explicitly granted UI/browser session, or unsafe third-party commands the operator deliberately executes with host authority.
