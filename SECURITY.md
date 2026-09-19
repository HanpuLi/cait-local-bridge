# Security

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository when available. Do not open a public issue containing an exploit, credential, private endpoint, browser session data or other operator information.

## Trust boundaries

ScopeRail is a remote-control surface for a real Mac. Treat its MCP endpoint as security-sensitive infrastructure.

The main boundaries are:

1. **Remote network reach is not identity.** The streamable-HTTP MCP service requires OAuth. Local stdio is a separate process-local trust boundary for an MCP client already running as the operator.
2. **The control plane is local.** Workspace policy, grants, token administration and kill-switch operations live on a loopback-only admin service protected by a local secret.
3. **Sandboxed work is OS-confined.** The default execution profile uses macOS Seatbelt and denies the operator's home directory and credential stores except for the registered workspace and a synthetic per-workspace HOME/TMPDIR.
4. **Trusted-host is not a sandbox.** It runs with the logged-in user's authority and must be treated as such.
5. **Sensitive mutations use local grants.** A remote tool argument cannot approve its own publish/desktop/remote-host capability.

## Local stdio and remote OAuth

The packaged stdio entry point is intended for a local MCP client running under the same logged-in operator account. It does not use the remote OAuth request context. This trust shortcut is enabled only inside that stdio process and is not enabled by the HTTP service. An optional `SCOPERAIL_WORKSPACE_ROOT` bootstrap registers only a sandboxed, network-off workspace; it does not silently grant trusted-host or desktop authority.

The remote service uses authorization code + PKCE S256 with dynamic client registration for supported MCP clients. Access tokens are short-lived; refresh tokens rotate; token material is stored hashed where applicable; revocation is supported.

Deployments should:

- expose only the MCP/auth surface through the reverse proxy
- keep the admin service loopback-only
- restrict OAuth redirect hosts
- use HTTPS for any non-loopback public URL
- rate-limit login failures
- rotate an installation-generated operator passphrase if it was ever written to a readable file

## Execution profiles

### sandboxed

The Seatbelt profile denies access to common credential and messaging locations, including SSH/GPG/cloud credentials, browser profiles, Keychain, Mail/Messages and the bridge control plane. The only control-plane carve-out is the synthetic per-workspace HOME used for temporary/cache state; it does not contain operator secrets.

Network access is a workspace property. Model runtimes can be explicitly denied even when other developer tools are available.

### trusted-host

This profile intentionally runs as the real user. Prompt injection or malicious project instructions can therefore reach whatever that user can reach. Use it only for work that truly requires host fonts/apps/Xcode/SSH/private networks.

## Desktop control

Semantic Accessibility actions are preferred to coordinate actions.

Fingerprinted Accessibility refs are observation-scoped. Identity includes role/subrole/identifier/title/description plus rounded frame. Before an action, the bridge checks that the fingerprint is still unique in a bounded tree. Moved/reflowed, missing, unaddressable or ambiguous targets fail closed. Actions may take preconditions and postcondition verification and return a bounded before/after state diff. Multi-step semantic sequences are explicitly non-transactional: if a later step fails, earlier UI mutations may already have applied.

Secure-field values are redacted, and semantic `set_value` refuses secure/password fields.

Coordinate mouse/keyboard control remains a fallback and should be used with screenshot or semantic verification. `desktop_element_at` can convert a screenshot coordinate into a semantic ref only when the hit-tested element is addressable through the current application Accessibility tree.

## Browser control

Managed browser traffic applies destination policy. Loopback admin/listen ports are blocked.

Attaching to an operator-owned DevTools browser is trusted-host only and intentionally inherits that browser's normal network/session authority. Existing tabs are treated as external resources and are detached, not closed, by the bridge.

## Git publishing

Local Git writes are restricted to a non-destructive allowlist. Publishing requires a local grant bound to concrete parameters. Force-push is not supported.

## Secrets

Do not store operator credentials, tokens, private endpoints, case data or browser profiles in source control. Control-plane bootstrap material that must remain file-backed uses restrictive permissions; service credentials should use an OS credential store or an existing credential helper.

The HomeLab adapters follow that split: Forgejo asks Git's configured credential helper rather than parsing `~/.git-credentials`, and new Paperless credentials are stored in macOS Keychain. `scoperailctl homelab set-paperless` lets the `security` tool prompt for the secret directly, so the management CLI never receives it. Legacy Paperless clear-text state is read only for compatibility and is reported as legacy until the operator reruns that command.

End-to-end OAuth evidence keeps access/refresh tokens separate from the JSON evidence record, and the standalone test client does not persist OAuth tokens.

Before a public release, run `python scripts/verify_public_tree.py` in the public tree and require the CI secret scan to pass. The maintainer's private-to-public export step runs additional private-marker checks and gitleaks before this tree is created.

## Incident response

A deployment should provide a local kill switch that:

- removes its public ingress
- revokes OAuth tokens
- terminates bridge jobs
- closes/detaches managed browser resources
- optionally unloads the launch service

After suspected token compromise, revoke token families and re-authenticate clients. After suspected credential exposure, rotate the underlying credential, not only the bridge token.
