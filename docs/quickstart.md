# Quickstart

The least-privilege path is local stdio with one sandboxed workspace.

1. Install the current release wheel: pipx install "https://github.com/HanpuLi/cait-local-bridge/releases/download/v0.1.0/cait_local_bridge-0.1.0-py3-none-any.whl"
2. From a project directory: cait-local-bridge init "$PWD"
3. Start: cait-local-bridge stdio
4. Point an MCP client at the cait-local-bridge-stdio executable.
5. Start with read/list operations and a sandboxed command. Add trusted-host, desktop or publish grants only for a concrete need.

For clients that support environment configuration, CLB_WORKSPACE_ROOT=/path/to/project with cait-local-bridge-stdio combines registration and startup without granting extra capabilities.

The package also exposes cait-local-bridge serve for the full OAuth HTTP deployment. That mode is intended for operators who understand the remote security model and is documented separately.
