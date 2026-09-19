# Release process

A release is cut from a validated public export, not from the private operational Git history.

1. Update bridge.__version__, CHANGELOG.md and server.json to the same version.
2. Run unit tests, fatal lint/static checks and compile checks in the private source tree.
3. Regenerate the public export into an empty destination.
4. Verify no private markers; run gitleaks on source worktree/history and exported tree.
5. In the exported tree run package build, twine check, clean-venv wheel install, import/CLI smoke tests and the unit suite.
6. Commit the clean export to the public repository.
7. Wait for public CI/security checks to pass.
8. Create the vX.Y.Z GitHub release/tag and publish package artifacts.
9. Publish PyPI first. MCP Registry metadata is published only after the referenced public package version exists and its README ownership marker can be verified.
10. Record SHA256 hashes for release artifacts.

If PyPI trusted publishing, Registry GitHub login or another first-time authentication step needs a human browser action, stop at that exact step rather than handling or printing credentials.
