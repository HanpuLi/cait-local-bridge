# Workspaces

A workspace is the bridge's unit of local authority. It has an opaque ID, canonical root, execution profiles, network mode and optional expiry/notes.

## Registration

For the packaged CLI:

    scoperail init /absolute/path/to/project

For stdio clients that cannot perform a prior setup step, set SCOPERAIL_WORKSPACE_ROOT. The stdio entry point registers that path as sandboxed with network off. It does not automatically add trusted-host or desktop access.

The bridge rejects unsafe roots such as the user's entire home directory, filesystem root, its own control-plane state and other configured sensitive roots.

## Path resolution

Tool paths are relative to a workspace. Parent traversal and control characters are rejected. Existing paths are resolved through the filesystem, and creates inspect the deepest existing or symlink ancestor so an existing or broken symlink cannot redirect a write outside the workspace.

This is a user-space preflight policy check, not a kernel transaction. A same-user process can still race a path component between validation and a later filesystem operation; sandboxed execution is confined separately.

## Workspace doctor

Use the read-only doctor when a workspace/path decision is unclear:

```sh
scoperail workspace doctor ws_abcd1234
scoperail workspace doctor /absolute/registered/root --path src/new.py
scoperail workspace doctor ws_abcd1234 --path ../outside --json
```

The result reports the registered root, granted profiles, network mode, expiry/revocation/root availability, and — when requested — whether a relative path passes the workspace boundary. Rejected symlink targets are deliberately not disclosed outside the registered root.

MCP clients can call `workspace_doctor` with the same workspace ID-or-root and optional path.

## Network and lifecycle

Workspace network mode affects sandboxed processes. off is the default. public permits job network access, while browser destination policy remains separate.

Revoking a workspace prevents further operations through it. Grants are separate records and can expire or carry use limits. Runtime state belongs under the bridge state directory, not inside project repositories.
