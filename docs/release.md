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
10. Record SHA256 hashes for release artifacts. The build sets `SOURCE_DATE_EPOCH` from the release commit to improve reproducibility.

With `SOURCE_DATE_EPOCH` fixed to the release commit, local repeated wheel builds are byte-identical. The current setuptools sdist is not yet byte-for-byte reproducible, so the published `SHA256SUMS` remains the authoritative artifact check and full sdist reproducibility is an open release-engineering limitation.

The release workflow uses PyPI Trusted Publishing and MCP Registry GitHub OIDC, so no long-lived publishing token belongs in GitHub. For a first package publication, configure a PyPI pending Trusted Publisher for owner `HanpuLi`, repository `scoperail`, workflow `release.yml`, environment `pypi`; then enable repository variables `PYPI_PUBLISH_ENABLED=true` and `MCP_REGISTRY_PUBLISH_ENABLED=true`. For recovery after a GitHub Release already exists, dispatch `release.yml` with `publish_pypi=true` and an explicit immutable `release_ref` such as `v0.2.0`. The workflow downloads that release's existing wheel/sdist, verifies them against its published `SHA256SUMS`, uploads those exact bytes to PyPI, and only then publishes the matching `server.json` to the MCP Registry.

If PyPI trusted publishing or another first-time authentication step needs a human browser action, stop at that exact step rather than handling or printing credentials.
