"""
Database access layer.

Design decisions:
  * We use the Python standard-library `sqlite3` module directly rather
    than an ORM. Every single query in this codebase uses parameterized
    placeholders ("?") -- user input is NEVER interpolated into SQL
    strings. This is what actually prevents SQL injection; an ORM is not
    required to achieve that, and using raw parameterized SQL keeps the
    security property easy to audit (grep for "%s" or f-strings near SQL
    and you should find nothing).
  * Foreign keys are turned on for every connection (SQLite disables them
    by default).
  * One connection per request, stored on Flask's `g` object, closed at
    teardown.
"""
import sqlite3
from pathlib import Path

from flask import current_app, g

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT NOT NULL UNIQUE,
    email               TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until        TEXT,
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stored_filename     TEXT NOT NULL UNIQUE,
    original_filename   TEXT NOT NULL,
    mime_type           TEXT NOT NULL,
    size_bytes          INTEGER NOT NULL,
    nonce_b64           TEXT NOT NULL,
    created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action              TEXT NOT NULL,
    ip_address          TEXT,
    timestamp           TEXT NOT NULL,
    success             INTEGER NOT NULL,
    resource_id         TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);

CREATE TABLE IF NOT EXISTS login_attempts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username_attempted  TEXT NOT NULL,
    ip_address          TEXT NOT NULL,
    timestamp           TEXT NOT NULL,
    success             INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address, timestamp);
CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username_attempted, timestamp);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        db_path = current_app.config["DATABASE_PATH"]
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    """Create tables if they don't already exist. Safe to call repeatedly."""
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        db.commit()


def register_teardown(app):
    app.teardown_appcontext(close_db)
