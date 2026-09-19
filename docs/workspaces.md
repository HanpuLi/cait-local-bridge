# Workspaces

A workspace is the bridge's unit of local authority. It has an opaque ID, canonical root, execution profiles, network mode and optional expiry/notes.

## Registration

For the packaged CLI:

    scoperail init /absolute/path/to/project

For stdio clients that cannot perform a prior setup step, set SCOPERAIL_WORKSPACE_ROOT. The stdio entry point registers that path as sandboxed with network off. It does not automatically add trusted-host or desktop access.

The bridge rejects unsafe roots such as the user's entire home directory, filesystem root, its own control-plane state and other configured sensitive roots.

## Path resolution

Tool paths are relative to a workspace. Parent traversal is rejected. Existing paths are resolved through the filesystem, and creates verify the deepest existing ancestor so an existing symlink cannot redirect a write outside the workspace.

## Network and lifecycle

Workspace network mode affects sandboxed processes. off is the default. public permits job network access, while browser destination policy remains separate.

Revoking a workspace prevents further operations through it. Grants are separate records and can expire or carry use limits. Runtime state belongs under the bridge state directory, not inside project repositories.
