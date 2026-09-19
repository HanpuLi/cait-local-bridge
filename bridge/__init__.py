"""ScopeRail: local MCP runtime for the user's current ChatGPT session.

The server exposes auditable files/process/Git/browser/macOS-UI primitives plus
persistent shells, state and deterministic orchestration. It contains no model API
client: model reasoning remains in the active ChatGPT session or explicit
chatgpt.com sub-conversations.
"""
__version__ = "0.2.1"
