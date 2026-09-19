# Quickstart

The least-privilege path is local stdio with one sandboxed workspace.

1. Install the current release wheel: pipx install "https://github.com/HanpuLi/scoperail/releases/download/v0.2.1/scoperail-0.2.1-py3-none-any.whl"
2. From a project directory: scoperail init "$PWD"
3. Start: scoperail stdio
4. Point an MCP client at the scoperail-stdio executable.
5. Start with read/list operations and a sandboxed command. Add trusted-host, desktop or publish grants only for a concrete need.

For clients that support environment configuration, SCOPERAIL_WORKSPACE_ROOT=/path/to/project with scoperail-stdio combines registration and startup without granting extra capabilities.

The package also exposes scoperail serve for the full OAuth HTTP deployment. That mode is intended for operators who understand the remote security model and is documented separately.
