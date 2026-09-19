"""Git tools. Read operations run in the workspace; publishing (push) goes through a broker that only honours a
user-created grant and never trusts repository-local config, hooks or helpers for credentials."""
from __future__ import annotations
import os, subprocess, tempfile, time
from pathlib import Path
from . import db
from .config import JOB_PATH, STATE_DIR
from .policy import BridgeError, workspace_get, resolve_in_workspace, grant_find, grant_use

READ_ENV = {"PATH": JOB_PATH, "HOME": str(STATE_DIR / "githome"), "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "LANG": "en_US.UTF-8"}
FORBIDDEN_ARGS = {"--force", "-f", "--force-with-lease", "--hard", "--mirror", "--delete", "-d", "-D", "--prune"}


def _git(ws: dict, args: list[str], cwd: str = ".", timeout: int = 120, env: dict | None = None) -> subprocess.CompletedProcess:
    (STATE_DIR / "githome").mkdir(exist_ok=True)
    path = resolve_in_workspace(ws, cwd)
    safe = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=user"]
    try:
        return subprocess.run(safe + args, cwd=path, capture_output=True, text=True, timeout=timeout, env=env or READ_ENV)
    except FileNotFoundError:
        raise BridgeError("missing_dependency", "git not installed")


def _out(r: subprocess.CompletedProcess, **extra) -> dict:
    return {"ok": r.returncode == 0, "exit_code": r.returncode, "stdout": r.stdout[-200000:], "stderr": r.stderr[-20000:],
            "truncated": len(r.stdout) > 200000, **extra}


def read_cmd(workspace_id: str, subcommand: str, args: list[str] | None = None, cwd: str = ".") -> dict:
    """status / diff / log / show / branch / worktree list / fetch / ls-files / rev-parse / remote -v / blame / stash list / tag."""
    ws = workspace_get(workspace_id)
    allowed = {"status", "diff", "log", "show", "branch", "worktree", "fetch", "ls-files", "rev-parse", "remote", "blame", "stash", "tag",
               "describe", "cat-file", "ls-remote", "shortlog", "grep", "config"}
    args = list(args or [])
    if subcommand not in allowed:
        raise BridgeError("permission_denied", f"git {subcommand} is not a read command here; use git_write for commits, git_push for publishing")
    if subcommand == "worktree" and (not args or args[0] != "list"):
        raise BridgeError("permission_denied", "only 'worktree list' is a read command; use git_write for worktree add")
    if subcommand == "stash" and (not args or args[0] not in ("list", "show")):
        raise BridgeError("permission_denied", "only 'stash list/show' allowed; the bridge never stashes user work")
    if subcommand == "branch" and any(a in FORBIDDEN_ARGS for a in args):
        raise BridgeError("permission_denied", "branch deletion is not a read command")
    if subcommand == "config" and any(a in ("--global", "--system", "--edit", "-e") for a in args):
        raise BridgeError("permission_denied", "global/system git config is off limits")
    if subcommand == "fetch" and any(a in FORBIDDEN_ARGS for a in args):
        raise BridgeError("permission_denied", "fetch --prune/--force not allowed")
    r = _git(ws, [subcommand] + args, cwd, timeout=300 if subcommand in ("fetch", "ls-remote") else 120)
    return _out(r)


def write_cmd(workspace_id: str, subcommand: str, args: list[str] | None = None, cwd: str = ".", subject: str | None = None) -> dict:
    """Local, non-destructive write commands: add, commit, checkout -b / switch -c, branch <new>, worktree add, restore --staged,
    merge --no-ff (fast-forward or merge commit only), rebase is NOT offered. Never reset --hard, clean, stash, force."""
    ws = workspace_get(workspace_id)
    args = list(args or [])
    if any(a in FORBIDDEN_ARGS for a in args) or any(a.startswith("--force") for a in args):
        raise BridgeError("permission_denied", f"destructive flag refused: {args}")
    ok = False
    if subcommand in ("add", "commit", "tag", "mv", "rm", "restore", "cherry-pick", "revert", "merge", "init", "submodule"):
        if subcommand == "rm" and "-r" in args and any(a in (".", "*") for a in args):
            raise BridgeError("permission_denied", "refusing recursive rm of the tree")
        if subcommand == "restore" and "--staged" not in args and "--source" in args:
            raise BridgeError("permission_denied", "restore --source overwrites the working tree; edit files explicitly instead")
        ok = True
    elif subcommand in ("checkout", "switch") and args and args[0] in ("-b", "-c"):
        ok = True
    elif subcommand == "switch" and args and not args[0].startswith("-"):
        ok = True  # switching branches with a dirty tree fails by itself; git refuses
    elif subcommand == "branch" and args and not args[0].startswith("-"):
        ok = True
    elif subcommand == "worktree" and args and args[0] == "add":
        wt = args[1] if len(args) > 1 else ""
        resolve_in_workspace(ws, wt, must_exist=False)
        ok = True
    if not ok:
        raise BridgeError("permission_denied", f"git {subcommand} {args} is not in the allowed local write set")
    env = dict(READ_ENV)
    if subcommand == "commit":
        # identity: use the repo/user identity if configured, else a bridge identity so the commit is attributable
        env.update({"HOME": str(Path.home())})
        env.setdefault("GIT_AUTHOR_NAME", "Local Bridge via ChatGPT"); env.setdefault("GIT_COMMITTER_NAME", "Local Bridge via ChatGPT")
    r = _git(ws, [subcommand] + args, cwd, env=env)
    db.audit("git_write", f"{subcommand} {args[:6]} rc={r.returncode}", subject=subject, workspace_id=workspace_id)
    return _out(r)


def push(workspace_id: str, remote: str, branch: str, cwd: str = ".", set_upstream: bool = False, subject: str | None = None) -> dict:
    """Publish broker. Requires an active grant: bridgectl grant add <ws> git_push remote=<name> branch=<branch>.
    The push runs with repository config ignored for credential/transport keys, hooks disabled, and credentials
    coming only from the user's own credential helpers (never from the project)."""
    ws = workspace_get(workspace_id)
    if branch.startswith("-") or remote.startswith("-"):
        raise BridgeError("invalid_argument", "bad remote/branch")
    url = _git(ws, ["remote", "get-url", remote], cwd)
    if url.returncode != 0:
        raise BridgeError("not_found", f"remote {remote} not found: {url.stderr.strip()}")
    remote_url = url.stdout.strip()
    head = _git(ws, ["rev-parse", "HEAD"], cwd).stdout.strip()
    g = grant_find(workspace_id, "git_push", {"remote": remote, "branch": branch})
    if g["params"].get("remote_url") and g["params"]["remote_url"] != remote_url:
        raise BridgeError("permission_denied", f"remote URL changed since the grant was created: {remote_url}")
    if g["params"].get("commit") and g["params"]["commit"] != head:
        raise BridgeError("permission_denied", f"grant is bound to commit {g['params']['commit']} but HEAD is {head}")
    if not remote_url.startswith(("https://", "ssh://", "git@", "file://", "/")):
        raise BridgeError("permission_denied", f"unsupported remote transport: {remote_url}")
    env = {"PATH": JOB_PATH, "HOME": str(Path.home()), "GIT_TERMINAL_PROMPT": "0", "LANG": "en_US.UTF-8",
           "GIT_SSH_COMMAND": "ssh -o BatchMode=yes"}
    broker = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.sshCommand=ssh -o BatchMode=yes",
              "-c", "protocol.ext.allow=never", "-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential",
              "-c", "credential.helper=store", "push"] + (["-u"] if set_upstream else []) + [remote, f"{branch}:{branch}"]
    path = resolve_in_workspace(ws, cwd)
    r = subprocess.run(broker, cwd=path, capture_output=True, text=True, timeout=600, env=env)
    grant_use(g["id"])
    remote_head = None
    if r.returncode == 0:
        lr = _git(ws, ["ls-remote", remote, f"refs/heads/{branch}"], cwd, env=env)
        remote_head = lr.stdout.split()[0] if lr.stdout.strip() else None
    db.audit("git_push", f"{remote} {branch} rc={r.returncode} head={head} remote_head={remote_head} grant={g['id']}", subject=subject, workspace_id=workspace_id)
    return _out(r, remote=remote, remote_url=remote_url, branch=branch, local_head=head, remote_head=remote_head, grant_id=g["id"],
                published=(r.returncode == 0 and remote_head == head))
