"""SQLite control-plane store. One connection per thread; WAL mode."""
from __future__ import annotations
import atexit, json, sqlite3, threading, time
from .config import DB_PATH, ensure_dirs

SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth_clients(client_id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS auth_codes(code TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS tokens(token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, client_id TEXT NOT NULL, subject TEXT NOT NULL,
  scopes TEXT NOT NULL, resource TEXT, expires_at REAL, revoked INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, family TEXT);
CREATE TABLE IF NOT EXISTS workspaces(id TEXT PRIMARY KEY, name TEXT NOT NULL, root TEXT NOT NULL, profiles TEXT NOT NULL,
  network TEXT NOT NULL DEFAULT 'off', expires_at REAL, revoked INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, notes TEXT);
CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, kind TEXT NOT NULL, params TEXT NOT NULL,
  expires_at REAL, revoked INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0, max_uses INTEGER);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, profile TEXT NOT NULL, kind TEXT NOT NULL,
  spec TEXT NOT NULL, status TEXT NOT NULL, pid INTEGER, pgid INTEGER, start_ts REAL, end_ts REAL, exit_code INTEGER, signal INTEGER,
  idem_key TEXT, created_at REAL NOT NULL, meta TEXT NOT NULL DEFAULT '{}');
CREATE UNIQUE INDEX IF NOT EXISTS jobs_idem ON jobs(workspace_id, idem_key) WHERE idem_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS state(workspace_id TEXT NOT NULL, key TEXT NOT NULL, revision INTEGER NOT NULL, content TEXT NOT NULL,
  updated_at REAL NOT NULL, PRIMARY KEY(workspace_id, key));
CREATE TABLE IF NOT EXISTS state_history(workspace_id TEXT, key TEXT, revision INTEGER, content TEXT, updated_at REAL);
CREATE TABLE IF NOT EXISTS inbox(id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL,
  created_at REAL NOT NULL, acked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, subject TEXT, tool TEXT NOT NULL,
  workspace_id TEXT, request_id TEXT, summary TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS dev_ports(workspace_id TEXT NOT NULL, port INTEGER NOT NULL, expires_at REAL, PRIMARY KEY(workspace_id, port));
CREATE TABLE IF NOT EXISTS schedules(id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, spec TEXT NOT NULL, next_run REAL, last_run REAL,
  enabled INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS login_attempts(ts REAL NOT NULL, ip TEXT NOT NULL, ok INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS pending_auth(id TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at REAL NOT NULL);
"""

_local = threading.local()


def _migrate(c: sqlite3.Connection) -> None:
    """Additive, idempotent schema changes for databases created by earlier versions."""
    if "revoked_at" not in {row[1] for row in c.execute("PRAGMA table_info(tokens)")}:
        try:
            c.execute("ALTER TABLE tokens ADD COLUMN revoked_at REAL")   # 2026-09-17: refresh-token reuse detection
        except sqlite3.OperationalError as e:  # another thread won the race
            if "duplicate column" not in str(e):
                raise


def conn() -> sqlite3.Connection:
    c = getattr(_local, "conn", None)
    if c is None:
        ensure_dirs()
        c = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=30000")
        c.executescript(SCHEMA)
        _migrate(c)
        _local.conn = c
    return c


def close_thread_connection() -> None:
    """Close and forget the current thread's SQLite connection, if any."""
    c = getattr(_local, "conn", None)
    if c is None:
        return
    try:
        c.close()
    finally:
        try:
            del _local.conn
        except AttributeError:
            pass


atexit.register(close_thread_connection)


def q(sql: str, *args):
    return conn().execute(sql, args)


def one(sql: str, *args):
    return conn().execute(sql, args).fetchone()


def all_(sql: str, *args):
    return conn().execute(sql, args).fetchall()


def audit(tool: str, summary: str, subject: str | None = None, workspace_id: str | None = None, request_id: str | None = None) -> None:
    q("INSERT INTO audit(ts, subject, tool, workspace_id, request_id, summary) VALUES(?,?,?,?,?,?)",
      time.time(), subject, tool, workspace_id, request_id, summary[:2000])


def j(x) -> str:
    return json.dumps(x, ensure_ascii=False, default=str)
