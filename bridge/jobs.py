"""Process execution engine: sandboxed (macOS Seatbelt via sandbox-exec) and trusted-host profiles, PTY support,
process-group cancellation, capped logs on disk, restart recovery without fake success. No model is ever invoked here."""
from __future__ import annotations
import fcntl, json, os, pty, re, shlex, signal, struct, subprocess, termios, threading, time, uuid
from pathlib import Path
from typing import Any
from . import db
from .config import JOBS_DIR, STATE_DIR, JOB_PATH, SANDBOX_PATH, BLOCKED_ENV_PREFIXES, SENSITIVE_HOME_SUBPATHS, load_config, model_runtime_paths
from .policy import BridgeError, workspace_get, require_profile, resolve_in_workspace, grant_find

CFG = load_config()
HOME = str(Path.home())
STATUS_ACTIVE = ("queued", "running", "waiting_input")
_lock = threading.RLock()
_live: dict[str, dict] = {}   # job_id -> {"proc": Popen, "master": fd|None, "stdin": fd|None}


def _wshome(ws_id: str) -> Path:
    p = STATE_DIR / "wshome" / ws_id
    (p / "tmp").mkdir(parents=True, exist_ok=True)
    return p


def _darwin_tmp() -> list[str]:
    out = []
    for var in ("DARWIN_USER_TEMP_DIR", "DARWIN_USER_CACHE_DIR"):
        try:
            v = subprocess.run(["getconf", var], capture_output=True, text=True, timeout=5).stdout.strip()
            if v: out.append(v.rstrip("/"))
        except Exception:
            pass
    return out


def seatbelt_profile(ws_root: str, ws_home: str, network: str, workspace_id: str) -> str:
    """Deny-by-default writes outside the workspace; deny reads of the home directory (except the workspace and
    the per-workspace HOME); network off unless the workspace was registered with network=public.
    Later rules override earlier ones (Seatbelt semantics)."""
    def sp(p): return f'(subpath "{p}")'
    ancestors = []
    p = Path(ws_root)
    while str(p).startswith(HOME) and p != Path(HOME):
        p = p.parent
        ancestors.append(f'(literal "{p}")')
    tmp = " ".join(sp(t) for t in _darwin_tmp())
    rt = model_runtime_paths()
    runtimes = ("(deny file-read* " + " ".join(f'(literal "{p}")' for p in rt) + ")\n(deny process-exec " + " ".join(f'(literal "{p}")' for p in rt) + ")") if rt else ""
    sens = " ".join(sp(str(Path(HOME) / s)) for s in SENSITIVE_HOME_SUBPATHS)
    from .policy import dev_port_allowed  # noqa
    net = "(allow network*)" if network == "public" else (
        '(deny network*)\n(allow network-bind (local ip "localhost:*"))\n(allow network-inbound (local ip "localhost:*"))\n'
        '(allow network-outbound (remote ip "localhost:*"))\n(allow network-outbound (remote unix-socket))')
    return f"""(version 1)
(allow default)
; ---- writes: workspace, per-workspace HOME and temp only
(deny file-write* (subpath "/"))
(allow file-write* {sp(ws_root)} {sp(ws_home)} {tmp} (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom")
  (regex #"^/dev/tty") (regex #"^/dev/pty") (subpath "/dev/fd") (literal "/dev/dtracehelper") (literal "/dev/autofs_nowait"))
; ---- reads: the user's home is off limits except the workspace and the per-workspace HOME
(deny file-read* (subpath "{HOME}"))
(allow file-read-metadata {' '.join(ancestors)})
(allow file-read* {sp(ws_root)} {sp(ws_home)} {tmp})
; explicit second layer for credential stores and the control-plane parent.
; The synthetic per-workspace HOME lives under the control plane, so carve out exactly
; that subtree again *after* the deny rules (Seatbelt uses later-rule precedence).
(deny file-read* {sp(str(STATE_DIR))} {sens})
(deny file-write* {sp(str(STATE_DIR))} {sens})
(allow file-read* {sp(ws_home)})
(allow file-write* {sp(ws_home)})
; ---- no model runtimes inside jobs: Claude Code / Codex binaries can be neither read nor executed
{runtimes}
; ---- network
{net}
"""


def _clean_env(user_env: dict[str, str] | None, profile: str, ws: dict, job_id: str, pty_mode: bool) -> dict[str, str]:
    env = {"PATH": SANDBOX_PATH if profile == "sandboxed" else JOB_PATH, "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TERM": "xterm-256color" if pty_mode else "dumb",
           "SCOPERAIL_JOB_ID": job_id, "SCOPERAIL_WORKSPACE": ws["id"], "SCOPERAIL_PROFILE": profile,
           "CLB_JOB_ID": job_id, "CLB_WORKSPACE": ws["id"], "CLB_PROFILE": profile, "CI": "1" if not pty_mode else "",
           "NO_COLOR": "1" if not pty_mode else "", "GIT_TERMINAL_PROMPT": "0", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    if profile == "sandboxed":
        h = _wshome(ws["id"])
        env.update({"HOME": str(h), "TMPDIR": str(h / "tmp"), "XDG_CACHE_HOME": str(h / ".cache"), "npm_config_cache": str(h / ".npm"),
                    "GIT_CONFIG_NOSYSTEM": "1", "PLAYWRIGHT_BROWSERS_PATH": str(h / ".pw")})
    else:
        env.update({"HOME": HOME, "TMPDIR": os.environ.get("TMPDIR", "/tmp"), "USER": os.environ.get("USER", "")})
    for k, v in (user_env or {}).items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) or k.upper().startswith(BLOCKED_ENV_PREFIXES) or k in ("PATH", "HOME", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD"):
            raise BridgeError("permission_denied", f"environment variable not allowed: {k}")
        env[k] = str(v)
    return env


def _job_dir(job_id: str) -> Path:
    d = JOBS_DIR / job_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _row(job_id: str) -> dict:
    r = db.one("SELECT * FROM jobs WHERE id=?", job_id)
    if not r:
        raise BridgeError("not_found", f"unknown job {job_id}")
    d = dict(r); d["spec"] = json.loads(d["spec"]); d["meta"] = json.loads(d["meta"]); return d


def _set(job_id: str, **fields) -> None:
    cols = ", ".join(f"{k}=?" for k in fields)
    db.q(f"UPDATE jobs SET {cols} WHERE id=?", *fields.values(), job_id)


def _proc_start_time(pid: int) -> str | None:
    try:
        return subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True, timeout=5).stdout.strip() or None
    except Exception:
        return None


def start(workspace_id: str, profile: str, command: list[str] | str, cwd: str = ".", env: dict | None = None,
          timeout: int | None = None, use_pty: bool = False, idem_key: str | None = None, stdin_text: str | None = None,
          cols: int = 120, rows: int = 40, subject: str | None = None, remote_host: str | None = None) -> dict:
    ws = workspace_get(workspace_id)
    require_profile(ws, profile)
    if idem_key:
        r = db.one("SELECT id FROM jobs WHERE workspace_id=? AND idem_key=?", workspace_id, idem_key)
        if r:
            j = info(r["id"]); j["deduplicated"] = True; return j
    running = db.one("SELECT COUNT(*) c FROM jobs WHERE status IN ('queued','running','waiting_input')")["c"]
    if running >= CFG["max_concurrent_jobs"]:
        raise BridgeError("rate_limited", f"max concurrent jobs ({CFG['max_concurrent_jobs']}) reached; cancel or wait")
    timeout = int(timeout or CFG["default_job_timeout"])
    if timeout > CFG["max_job_timeout"]:
        raise BridgeError("invalid_argument", f"timeout above max {CFG['max_job_timeout']}s")
    cwd_path = resolve_in_workspace(ws, cwd)
    if not cwd_path.is_dir():
        raise BridgeError("invalid_argument", f"cwd is not a directory: {cwd}")
    shell_mode = isinstance(command, str)
    if shell_mode:
        argv = ["/bin/zsh", "-lc" if profile == "trusted-host" else "-c", command]
        if profile == "sandboxed":
            argv = ["/bin/zsh", "-c", command]
    else:
        if not command or not all(isinstance(a, str) for a in command):
            raise BridgeError("invalid_argument", "argv must be a non-empty list of strings")
        argv = list(command)
    job_id = "job_" + uuid.uuid4().hex[:12]
    jd = _job_dir(job_id)
    env = _clean_env(env, profile, ws, job_id, use_pty)
    real_argv = argv
    host_label = "local"
    if remote_host:
        # named remote host registered by the user (grant kind ssh_host); keys stay on this Mac, command runs there
        g = grant_find(workspace_id, "ssh_host", {"host": remote_host})
        if profile != "trusted-host":
            raise BridgeError("permission_denied", "remote SSH execution requires the trusted-host profile")
        real_argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", g["params"]["host"], "--",
                     " ".join(shlex.quote(a) for a in argv)]
        host_label = "ssh:" + g["params"]["host"]
    elif profile == "sandboxed":
        prof = seatbelt_profile(ws["root"], str(_wshome(ws["id"])), ws["network"], ws["id"])
        (jd / "sandbox.sb").write_text(prof)
        real_argv = ["/usr/bin/sandbox-exec", "-f", str(jd / "sandbox.sb")] + argv
    spec = {"argv": argv, "shell": shell_mode, "cwd": str(cwd_path), "env_keys": sorted((env or {}).keys()), "timeout": timeout,
            "pty": use_pty, "profile": profile, "host": host_label, "cols": cols, "rows": rows}
    db.q("INSERT INTO jobs(id,workspace_id,profile,kind,spec,status,idem_key,created_at,meta) VALUES(?,?,?,?,?,?,?,?,?)",
         job_id, workspace_id, profile, "exec", json.dumps(spec), "queued", idem_key, time.time(), "{}")
    db.audit("exec_start", f"{profile} {host_label} argv={argv[:6]} cwd={cwd}", subject=subject, workspace_id=workspace_id)
    _launch(job_id, real_argv, str(cwd_path), env, use_pty, stdin_text, cols, rows, timeout)
    return info(job_id)


def _launch(job_id: str, argv: list[str], cwd: str, env: dict, use_pty: bool, stdin_text: str | None, cols: int, rows: int, timeout: int) -> None:
    jd = _job_dir(job_id)
    out_path, err_path = jd / "stdout.log", jd / "stderr.log"
    try:
        if use_pty:
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            def preexec():
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=slave, stdout=slave, stderr=slave, preexec_fn=preexec, close_fds=True)
            os.close(slave)
            err_path.write_bytes(b"")
            with _lock:
                _live[job_id] = {"proc": proc, "master": master, "stdin": None}
            threading.Thread(target=_pty_reader, args=(job_id, master, out_path), daemon=True).start()
        else:
            # The parent (unsandboxed) owns the log files, which live under the control-plane dir the sandbox denies
            # writing to; so we pipe the child's output and write the logs here rather than handing it the fds.
            # stdin stays open (pipe) only when the caller signalled interactive input (stdin_text given, even ""),
            # so plain commands that read stdin get EOF instead of hanging; use_pty=true is the other interactive path.
            stdin_mode = subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=stdin_mode, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    start_new_session=True, close_fds=True)
            out_path.write_bytes(b""); err_path.write_bytes(b"")
            threading.Thread(target=_pipe_reader, args=(job_id, proc.stdout, out_path), daemon=True).start()
            threading.Thread(target=_pipe_reader, args=(job_id, proc.stderr, err_path), daemon=True).start()
            if stdin_text is not None and proc.stdin:
                try:
                    proc.stdin.write(stdin_text.encode()); proc.stdin.flush()
                except BrokenPipeError:
                    pass
            with _lock:
                _live[job_id] = {"proc": proc, "master": None, "stdin": proc.stdin if stdin_text is not None else None}
    except Exception as e:  # spawn failure is a real failure, recorded as such
        _set(job_id, status="failed", end_ts=time.time(), meta=json.dumps({"error": f"spawn failed: {e}"}))
        raise BridgeError("missing_dependency" if isinstance(e, FileNotFoundError) else "internal", f"could not start process: {e}")
    start_ts = time.time()
    _set(job_id, status="running", pid=proc.pid, pgid=proc.pid, start_ts=start_ts,
         meta=json.dumps({"proc_start": _proc_start_time(proc.pid), "timeout": timeout}))
    threading.Thread(target=_waiter, args=(job_id, proc, timeout), daemon=True).start()


def _pipe_reader(job_id: str, pipe, out_path: Path) -> None:
    cap = CFG["max_job_log_bytes"]
    n = 0
    with open(out_path, "ab") as f:
        # BufferedReader.read(65536) may wait for the entire request (or EOF),
        # which makes long-lived pipe jobs appear silent.  Read the fd directly so
        # whatever the child has already produced is flushed into the job log.
        fd = pipe.fileno()
        while True:
            try:
                data = os.read(fd, 65536)
            except (OSError, ValueError):
                break
            if not data:
                break
            if n < cap:
                f.write(data[: cap - n]); f.flush()
            n += len(data)
        if n > cap:
            f.write(f"\n[bridge] log truncated at {cap} bytes\n".encode())
    try:
        pipe.close()
    except OSError:
        pass


def _pty_reader(job_id: str, master: int, out_path: Path) -> None:
    cap = CFG["max_job_log_bytes"]
    with open(out_path, "ab") as f:
        n = 0
        while True:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            if n < cap:
                f.write(data[: cap - n]); f.flush()
            n += len(data)
        if n > cap:
            f.write(f"\n[bridge] log truncated at {cap} bytes\n".encode())
    try:
        os.close(master)
    except OSError:
        pass


def _waiter_body(job_id: str, proc: subprocess.Popen, timeout: int) -> None:
    deadline = time.time() + timeout
    timed_out = False
    while True:
        rc = proc.poll()
        if rc is not None:
            break
        if time.time() > deadline:
            timed_out = True
            _kill_group(proc.pid)
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                pass
            rc = proc.poll()
            break
        # log size cap for file-redirected jobs
        jd = JOBS_DIR / job_id
        try:
            if (jd / "stdout.log").stat().st_size + (jd / "stderr.log").stat().st_size > CFG["max_job_log_bytes"]:
                _kill_group(proc.pid); proc.wait(10); rc = proc.poll()
                with open(jd / "stderr.log", "ab") as f:
                    f.write(b"\n[bridge] killed: log size cap exceeded\n")
                break
        except FileNotFoundError:
            pass
        time.sleep(0.25)
    with _lock:
        live = _live.pop(job_id, None)
    if live and live.get("master") is not None:
        time.sleep(0.2)  # let the pty reader drain
    row = _row(job_id)
    if row["status"] == "cancelled":
        status = "cancelled"
    elif timed_out:
        status = "failed"
    else:
        status = "succeeded" if rc == 0 else "failed"
    sig = -rc if (rc is not None and rc < 0) else None
    meta = row["meta"]; meta.update({"timed_out": timed_out})
    _set(job_id, status=status, end_ts=time.time(), exit_code=(rc if rc is not None and rc >= 0 else None), signal=sig, meta=json.dumps(meta))
    db.q("INSERT INTO inbox(workspace_id,kind,payload,created_at) VALUES(?,?,?,?)", row["workspace_id"], "job_finished",
         json.dumps({"job_id": job_id, "status": status, "exit_code": rc if rc is not None and rc >= 0 else None, "signal": sig,
                     "timed_out": timed_out, "argv": row["spec"]["argv"][:8]}), time.time())



def _waiter(job_id: str, proc: subprocess.Popen, timeout: int) -> None:
    try:
        _waiter_body(job_id, proc, timeout)
    finally:
        # Waiter threads are short-lived; always release their thread-local DB
        # connection, including cancellation/error paths.
        db.close_thread_connection()


def _kill_group(pgid: int, sig: int = signal.SIGTERM) -> bool:
    try:
        os.killpg(pgid, sig)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return False


def cancel(job_id: str, subject: str | None = None) -> dict:
    row = _row(job_id)
    if row["status"] not in STATUS_ACTIVE:
        j = info(job_id); j["killed_signal_sent"] = False; j["surviving_pids"] = []; return j
    _set(job_id, status="cancelled")
    pgid = row["pgid"] or row["pid"]
    with _lock:
        live = _live.get(job_id)
    killed = _kill_group(pgid, signal.SIGTERM) if pgid else False
    if live:
        try:
            live["proc"].wait(3)
        except subprocess.TimeoutExpired:
            _kill_group(pgid, signal.SIGKILL)
    else:  # job adopted from a previous server run: we can only signal it
        time.sleep(1)
        if pgid and _pid_alive(pgid):
            _kill_group(pgid, signal.SIGKILL)
        _set(job_id, end_ts=time.time())
    db.audit("exec_cancel", f"{job_id} pgid={pgid} signalled={killed}", subject=subject, workspace_id=row["workspace_id"])
    # confirm the group is gone
    time.sleep(0.3)
    survivors = _group_members(pgid) if pgid else []
    j = info(job_id); j["killed_signal_sent"] = killed; j["surviving_pids"] = survivors
    return j


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0); return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _group_members(pgid: int) -> list[int]:
    try:
        out = subprocess.run(["ps", "-o", "pid=,pgid=", "-ax"], capture_output=True, text=True, timeout=5).stdout
        return [int(l.split()[0]) for l in out.splitlines() if l.split() and int(l.split()[1]) == pgid]
    except Exception:
        return []


def send_input(job_id: str, text: str | None = None, keys: list[str] | None = None, eof: bool = False, interrupt: bool = False, subject: str | None = None) -> dict:
    row = _row(job_id)
    if row["status"] not in STATUS_ACTIVE:
        raise BridgeError("conflict", f"job {job_id} is {row['status']}; cannot send input")
    with _lock:
        live = _live.get(job_id)
    if not live:
        raise BridgeError("conflict", "job is not attached to this server process (adopted after restart); input impossible")
    proc, master = live["proc"], live["master"]
    KEYS = {"enter": "\r", "tab": "\t", "esc": "\x1b", "up": "\x1b[A", "down": "\x1b[B", "left": "\x1b[D", "right": "\x1b[C",
            "ctrl-c": "\x03", "ctrl-d": "\x04", "ctrl-z": "\x1a", "backspace": "\x7f"}
    payload = (text or "") + "".join(KEYS.get(k.lower(), "") for k in (keys or []))
    if master is not None:
        if interrupt:
            os.write(master, b"\x03")
        if payload:
            os.write(master, payload.encode())
        if eof:
            os.write(master, b"\x04")
    else:
        if interrupt:
            _kill_group(row["pgid"], signal.SIGINT)
        if payload or eof:
            if not proc.stdin:
                raise BridgeError("conflict", "job was started without an open stdin (start it with stdin_text='' or use_pty=true)")
            if payload:
                proc.stdin.write(payload.encode()); proc.stdin.flush()
            if eof:
                proc.stdin.close()
    db.audit("exec_input", f"{job_id} bytes={len(payload)} eof={eof} int={interrupt}", subject=subject, workspace_id=row["workspace_id"])
    return info(job_id)


def logs(job_id: str, stream: str = "stdout", cursor: int = 0, max_bytes: int = 65536) -> dict:
    row = _row(job_id)
    if stream not in ("stdout", "stderr"):
        raise BridgeError("invalid_argument", "stream must be stdout or stderr")
    p = JOBS_DIR / job_id / f"{stream}.log"
    size = p.stat().st_size if p.exists() else 0
    cursor = max(0, min(int(cursor), size))
    max_bytes = max(1, min(int(max_bytes), 1_000_000))
    with open(p, "rb") as f:
        f.seek(cursor); data = f.read(max_bytes)
    nxt = cursor + len(data)
    return {"job_id": job_id, "stream": stream, "cursor": cursor, "next_cursor": nxt, "size": size,
            "text": data.decode("utf-8", "replace"), "eof": row["status"] not in STATUS_ACTIVE and nxt >= size,
            "status": row["status"], "truncated": nxt < size}


def info(job_id: str) -> dict:
    row = _row(job_id)
    jd = JOBS_DIR / job_id
    sizes = {s: (jd / f"{s}.log").stat().st_size if (jd / f"{s}.log").exists() else 0 for s in ("stdout", "stderr")}
    return {"job_id": job_id, "workspace_id": row["workspace_id"], "profile": row["profile"], "status": row["status"],
            "pid": row["pid"], "exit_code": row["exit_code"], "signal": row["signal"], "start_ts": row["start_ts"], "end_ts": row["end_ts"],
            "argv": row["spec"]["argv"], "cwd": row["spec"]["cwd"], "pty": row["spec"]["pty"], "host": row["spec"].get("host", "local"),
            "log_sizes": sizes, "timed_out": row["meta"].get("timed_out", False), "note": row["meta"].get("note"),
            "attached": job_id in _live}


def list_jobs(workspace_id: str | None = None, limit: int = 50) -> list[dict]:
    rows = db.all_("SELECT id FROM jobs WHERE (?1 IS NULL OR workspace_id=?1) ORDER BY created_at DESC LIMIT ?2", workspace_id, limit)
    return [info(r["id"]) for r in rows]


def recover_on_startup() -> list[str]:
    """Called once when the server starts. Jobs left 'running' by a previous server process are never reported as
    succeeded: if the same PID is alive with the same start time we mark it 'interrupted' (orphan alive, exit code
    unobtainable); otherwise 'interrupted' (process gone). Nothing is re-run automatically."""
    notes = []
    for r in db.all_("SELECT id, pid, meta FROM jobs WHERE status IN ('queued','running','waiting_input')"):
        meta = json.loads(r["meta"] or "{}")
        alive = r["pid"] and _pid_alive(r["pid"]) and _proc_start_time(r["pid"]) == meta.get("proc_start")
        meta["note"] = ("bridge restarted while job was running; process still alive but detached, exit code cannot be observed"
                        if alive else "bridge restarted while job was running; process is gone, exit code unknown")
        meta["orphan_alive"] = bool(alive)
        _set(r["id"], status="interrupted", end_ts=None if alive else time.time(), meta=json.dumps(meta))
        notes.append(f"{r['id']}: {'orphan alive' if alive else 'gone'}")
    return notes


def cancel_all(subject: str | None = None) -> list[str]:
    out = []
    for r in db.all_("SELECT id FROM jobs WHERE status IN ('queued','running','waiting_input')"):
        cancel(r["id"], subject); out.append(r["id"])
    return out
