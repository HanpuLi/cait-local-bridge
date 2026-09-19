# Positioning

Cait Local Bridge is a macOS-first local execution bridge that applies one explicit workspace/grant model across files, processes, persistent shells, browser sessions, Git publication and native Accessibility UI.

The project should not be positioned as the first shell MCP, the first persistent-session MCP, or the first semantic macOS computer-use server. Those categories already contain mature projects.

## Relevant overlap

- fwerkor/local-shell-mcp has substantial overlap in shell, files, browser, persistent sessions, workspaces, audit and remote OAuth. Its documented safety boundary is strongly oriented around container or VM deployment. Cait Local Bridge's useful distinction is native macOS host integration, per-workspace Seatbelt or trusted-host profiles, semantic Accessibility and the same grant/audit model across all execution surfaces.
- The official MCP filesystem reference server is intentionally narrower: approved-directory filesystem access rather than a multi-surface local control plane.
- onixhdz/computer-use-mcp, mediar-ai/mcp-server-macos-use, opensymph/open-computer-use and similar projects already use Accessibility semantics for computer control. Cait Local Bridge therefore treats semantic UI as one integrated surface, not a uniqueness claim by itself.
- Claude/Codex bridge projects generally focus on routing work between agents or models. Cait Local Bridge does not embed a second model; the active MCP client remains the decision maker.

## Product boundary

The public core is useful when a client needs several local surfaces but the operator does not want every capability collapsed into unrestricted shell access. The escalation path is visible:

sandboxed workspace -> optional public network -> optional trusted-host -> parameter-bound grants such as desktop, SSH or Git publish.

That policy path, plus provenance/audit and semantic native UI, is the project's main design thesis.

## What not to claim

Do not claim complete Linux or Windows runtime support, universal client compatibility, sandboxing of trusted-host commands, protection against malicious same-user local processes, or safety of arbitrary desktop/browser actions once the operator has granted them.
