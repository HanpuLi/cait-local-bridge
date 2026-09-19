# Permissions

Permissions are split into workspace profiles and explicit grants.

## Workspace profiles

sandboxed is the default. Commands run under the macOS Seatbelt profile and receive a cleaned environment. Network is off unless the workspace network mode is explicitly public.

trusted-host is opt-in. Commands execute as the logged-in macOS user and can reach host files and credentials subject to normal OS permissions. It is not a stronger sandbox.

A workspace may enable both profiles, but the caller still chooses the profile for each job.

## Grants

Grants authorize operations that should not be implied by workspace membership. Examples include desktop control, a particular Git push target or a named SSH host. Grant parameters are matched by policy; authorization for one remote or branch is not a generic publish token.

The packaged CLI can register a workspace and create an explicit grant:

    cait-local-bridge init ~/src/project
    cait-local-bridge grant <workspace-id> desktop screen=*

Treat trusted-host, desktop grants and publish grants as privilege escalation decisions. They are not defaults in package metadata or examples.
