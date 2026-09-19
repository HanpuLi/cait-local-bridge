"""Entry point: `python -m bridge` runs the public MCP app (loopback, proxied by Funnel) and the loopback admin app
in one asyncio loop, plus the plain-process scheduler thread. Managed by launchd (com.cait.local-bridge)."""
from __future__ import annotations
import asyncio, logging, os, signal, subprocess, sys, threading, time
import uvicorn
from .config import load_config, LOGS_DIR, ensure_dirs
from . import jobs, db


def _activity_sidecar_supervisor(stop: threading.Event, executable: str) -> None:
    """Supervise an optional operator-configured sidecar without baking machine paths into source.

    This exists for integrations that need to inherit the bridge process's macOS TCC identity.
    The executable path comes only from local config and is never exposed as an MCP capability.
    """
    path = os.path.abspath(os.path.expanduser(executable))
    if not os.path.isfile(path) or not os.access(path, os.X_OK):
        logging.warning("configured activity sidecar is unavailable: %s", path)
        return

    while not stop.is_set():
        proc = None
        try:
            proc = subprocess.Popen(
                [path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            logging.info("activity sidecar started pid=%s", proc.pid)
            while not stop.wait(1.0):
                rc = proc.poll()
                if rc is not None:
                    logging.warning("activity sidecar exited rc=%s; restarting", rc)
                    break
            if stop.is_set() and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                break
        except Exception:
            logging.exception("activity sidecar supervisor error")
        finally:
            if proc is not None and proc.poll() is None and stop.is_set():
                try:
                    proc.terminate()
                except OSError:
                    pass
        if not stop.wait(5.0):
            continue


def main() -> None:
    ensure_dirs()
    cfg = load_config()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    for note in jobs.recover_on_startup():
        logging.info("recovered job: %s", note)
    from . import agents
    for note in agents.recover_on_startup():
        logging.info("interrupted sub-agent run: %s", note)
    from . import pipelines
    for note in pipelines.recover_on_startup():
        logging.info("interrupted pipeline: %s", note)
    from . import coding
    for note in coding.recover_on_startup():
        logging.info("interrupted coding task: %s", note)
    from .server import build_app, scheduler_loop
    from .admin import build_admin_app
    stop = threading.Event()
    threading.Thread(target=scheduler_loop, args=(stop,), daemon=True).start()
    sidecar_thread = None
    if cfg.get("activity_sidecar"):
        sidecar_thread = threading.Thread(
            target=_activity_sidecar_supervisor,
            args=(stop, str(cfg["activity_sidecar"])),
            daemon=True,
            name="cait-local-bridge-sidecar",
        )
        sidecar_thread.start()
    public = uvicorn.Server(uvicorn.Config(build_app(), host=cfg["listen_host"], port=cfg["listen_port"], log_level="info", proxy_headers=True, access_log=False,
                                           forwarded_allow_ips="127.0.0.1", timeout_keep_alive=75))
    admin = uvicorn.Server(uvicorn.Config(build_admin_app(), host=cfg["admin_host"], port=cfg["admin_port"], log_level="warning", access_log=False))
    db.audit("server", f"start pid={os.getpid()} public={cfg['listen_port']} admin={cfg['admin_port']}")

    async def run():
        await asyncio.gather(public.serve(), admin.serve())

    try:
        asyncio.run(run())
    finally:
        stop.set()
        if sidecar_thread:
            sidecar_thread.join(timeout=4)
        db.audit("server", f"stop pid={os.getpid()}")


if __name__ == "__main__":
    main()
