"""Paths and static configuration. Control plane lives under ~/.scoperail (never inside a workspace)."""
from __future__ import annotations
import json, os, socket, secrets
from pathlib import Path

_NEW_STATE = Path.home() / ".scoperail"
_LEGACY_STATE = Path.home() / ".cait-local-bridge"
_DEFAULT_STATE = _LEGACY_STATE if _LEGACY_STATE.exists() and not _NEW_STATE.exists() else _NEW_STATE
STATE_DIR = Path(os.environ.get("SCOPERAIL_STATE_DIR") or os.environ.get("CLB_STATE_DIR") or _DEFAULT_STATE)
INSTALL_DIR = Path(__file__).resolve().parent.parent
SECRETS_DIR = STATE_DIR / "secrets"
JOBS_DIR = STATE_DIR / "jobs"
LOGS_DIR = STATE_DIR / "logs"
BACKUP_DIR = STATE_DIR / "backups"
BROWSER_PROFILE_DIR = STATE_DIR / "browser-profile"
ARTIFACTS_DIR = STATE_DIR / "artifacts"
DB_PATH = STATE_DIR / "bridge.sqlite3"
CONFIG_PATH = STATE_DIR / "config.json"
# Optional activity signal: every authenticated tool call advances this epoch-seconds file.
# External local workflows may watch it; tests can isolate it with CLB_LAST_INTERACTION.
LAST_INTERACTION = Path(os.environ.get("SCOPERAIL_LAST_INTERACTION") or os.environ.get("CLB_LAST_INTERACTION") or str(Path.home() / ".last_interaction"))

DEFAULTS = {
    # New installs start loopback-only.  A remote MCP deployment must explicitly
    # set public_url (for example to a reverse proxy / Tailscale Funnel HTTPS URL).
    "public_url": "http://127.0.0.1:8795",
    "mcp_path": "/mcp",
    "listen_host": "127.0.0.1",
    "listen_port": 8795,
    "admin_host": "127.0.0.1",
    "admin_port": 8796,
    "funnel_port": 443,
    "funnel_path": "/gw",
    # RFC 8414/9728 discovery for a path-based issuer lives at the HOST root; these prefixes are routed to the bridge too.
    "funnel_wellknown_paths": ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration",
                               "/.well-known/oauth-protected-resource"],
    "timezone": os.environ.get("TZ", "UTC"),
    "access_token_ttl": 3600,
    "refresh_token_ttl": 30 * 86400,
    "auth_code_ttl": 300,
    "max_concurrent_jobs": 8,
    "default_job_timeout": 600,
    "max_job_timeout": 6 * 3600,
    "max_job_log_bytes": 50 * 1024 * 1024,
    "max_read_bytes": 2 * 1024 * 1024,
    "max_export_bytes": 8 * 1024 * 1024,
    "max_import_bytes": 200 * 1024 * 1024,
    "rate_limit_per_minute": 240,
    "login_max_attempts": 5,
    "login_lockout_seconds": 900,
    "login_global_max_attempts": 20,      # failures from ALL IPs within the lockout window -> everyone locked
    "refresh_reuse_grace_seconds": 30,    # replay of a rotated refresh token after this -> whole family revoked
    "user_subject": os.environ.get("SCOPERAIL_USER_SUBJECT", os.environ.get("CLB_USER_SUBJECT", os.environ.get("USER", "operator"))),
    # Managed-browser engine. Default: headless Chrome/Chromium with an empty profile.
    # Operators may explicitly point this at a compatible browser executable/profile clone.
    "browser_executable": None,
    "browser_headless": True,
    # Optional executable supervised as a child of the bridge process.  This is deliberately
    # unset in source; machine-specific activity integrations belong in local 0600 config.
    "activity_sidecar": None,
}

# Directories that sandboxed jobs may never read (in addition to the whole home directory,
# which is denied except for the workspace itself and the per-job HOME).
SENSITIVE_HOME_SUBPATHS = [
    ".ssh", ".gnupg", ".aws", ".config/gh", ".git-credentials", ".netrc", ".npmrc", ".pypirc",
    ".scoperail", ".cait-local-bridge", ".claude", ".claude.json", ".codex", ".gmail-mcp", ".mimi",
    "Library/Keychains", "Library/Cookies", "Library/Application Support/Google",
    "Library/Application Support/Firefox", "Library/Application Support/com.apple.sharedfilelist",
    "Library/Mail", "Library/Messages", "Library/Group Containers",
]

# Environment variables that are never passed to any job, in any profile.
BLOCKED_ENV_PREFIXES = ("ANTHROPIC_", "OPENAI_", "CLAUDE", "CODEX", "GH_TOKEN", "GITHUB_TOKEN", "AWS_", "GOOGLE_API",
                        "PAPERLESS", "FORGEJO", "SCOPERAIL_", "CLB_", "SSH_AUTH_SOCK", "GPG_AGENT_INFO", "NPM_TOKEN", "HOMEBREW_GITHUB_API_TOKEN")

# PATH used for jobs and for the bridge's own subprocesses: a shim directory rebuilt at startup that links every
# executable from the user's toolchain dirs EXCEPT Claude Code / Codex, followed by the system dirs.
TOOLPATH_DIR = STATE_DIR / "toolpath"
TOOLCHAIN_SRC = ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin"]
MODEL_RUNTIME_NAMES = ("claude", "claude-code", "codex", "codex-cli", "claude.exe")
JOB_PATH = f"{TOOLPATH_DIR}:/usr/bin:/bin:/usr/sbin:/sbin"
# Sandboxed jobs read PATH from the real toolchain dirs (the shim lives in the denied control plane); Claude Code /
# Codex are blocked inside the sandbox by an explicit process-exec deny, not by PATH.
SANDBOX_PATH = ":".join(TOOLCHAIN_SRC) + ":/usr/bin:/bin:/usr/sbin:/sbin"


def model_runtime_paths() -> list[str]:
    """Real paths of Claude Code / Codex executables present on this Mac (denied inside the sandbox, excluded from PATH)."""
    out = []
    for d in TOOLCHAIN_SRC + [str(Path.home() / ".local/bin"), str(Path.home() / ".claude/local"), str(Path.home() / ".codex/bin")]:
        for n in MODEL_RUNTIME_NAMES:
            p = Path(d) / n
            if p.exists() or p.is_symlink():
                out.append(str(p))
                try:
                    out.append(str(p.resolve()))
                except OSError:
                    pass
    return sorted(set(out))


def rebuild_toolpath() -> dict:
    TOOLPATH_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(TOOLPATH_DIR, 0o755)
    for old in TOOLPATH_DIR.iterdir():
        old.unlink()
    linked, excluded = 0, []
    for d in TOOLCHAIN_SRC:
        dp = Path(d)
        if not dp.is_dir():
            continue
        for exe in dp.iterdir():
            if exe.name in MODEL_RUNTIME_NAMES or exe.name.startswith(("claude", "codex")):
                excluded.append(str(exe)); continue
            dest = TOOLPATH_DIR / exe.name
            if not dest.exists() and not dest.is_symlink() and (exe.is_file() or exe.is_symlink()) and os.access(exe, os.X_OK):
                dest.symlink_to(exe); linked += 1
    return {"linked": linked, "excluded": excluded, "dir": str(TOOLPATH_DIR)}


def fix_path() -> None:
    """Make the bridge process independent of the launching shell: always find the user toolchain, never Claude Code / Codex dirs."""
    os.environ["PATH"] = JOB_PATH + ":" + ":".join(p for p in os.environ.get("PATH", "").split(":") if p and ".claude" not in p and ".codex" not in p)


def ensure_dirs() -> None:
    for d in (STATE_DIR, SECRETS_DIR, JOBS_DIR, LOGS_DIR, BACKUP_DIR, BROWSER_PROFILE_DIR, ARTIFACTS_DIR):
        d.mkdir(parents=True, exist_ok=True)
    os.chmod(SECRETS_DIR, 0o700)
    os.chmod(STATE_DIR, 0o711)   # traversable so the sandbox can reach STATE_DIR/toolpath; contents stay private
    if not TOOLPATH_DIR.exists() or not any(TOOLPATH_DIR.iterdir()):
        rebuild_toolpath()
    fix_path()


def load_config() -> dict:
    ensure_dirs()
    cfg = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        cfg.update(json.loads(CONFIG_PATH.read_text()))
    else:
        cfg["host_id"] = f"{socket.gethostname().split('.')[0]}-{secrets.token_hex(3)}"
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
        os.chmod(CONFIG_PATH, 0o600)
    return cfg


def admin_token() -> str:
    """Loopback admin channel token (file 0600). Created on first use."""
    ensure_dirs()
    p = SECRETS_DIR / "admin.token"
    if not p.exists():
        p.write_text(secrets.token_urlsafe(32))
        os.chmod(p, 0o600)
    return p.read_text().strip()
