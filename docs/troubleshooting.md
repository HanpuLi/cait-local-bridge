# Troubleshooting

## permission_denied

Check that the path belongs to the workspace, the requested execution profile is enabled, and any sensitive action has the required grant. Do not work around the error by registering the entire home directory.

## Native UI is empty or actions fail

Confirm Screen Recording and Accessibility permission for the actual Python or launcher process. Some applications expose incomplete Accessibility trees; use semantic observation first, then screenshot/coordinate fallback where necessary.

## Sandboxed command cannot read normal home files

Expected behavior. The sandbox intentionally substitutes a per-workspace HOME and denies the user's normal home except the workspace itself.

## Network is unavailable in a job

Sandboxed workspaces default to network off. Enable public network only if the task requires it. Private or loopback browser and CDP access are separate capabilities.

## Existing Chromium tabs are not visible

Existing-session attachment requires a Chromium-family process explicitly started with a loopback DevTools port and configured as an allowed endpoint. The bridge does not scan arbitrary local ports.

## HTTP client reports OAuth or discovery problems

Verify the configured public URL exactly matches the externally reachable HTTPS mount and discovery endpoints are reachable. Avoid wildcard host acceptance; DNS-rebinding protection depends on a precise host set.

## conflict on a write

Re-read the file and decide whether to incorporate the intervening change. The error is optimistic concurrency protection, not a transient failure to ignore.

## Public export fails

Treat private-marker or gitleaks failures as release blockers. Remove or operator-configure the private value in source rather than weakening the scanner.
