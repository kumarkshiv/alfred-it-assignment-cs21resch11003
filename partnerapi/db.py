"""SQLite access: schema, per-request connections."""
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS partners (
    id                INTEGER PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE COLLATE NOCASE,
    client_id         TEXT NOT NULL UNIQUE,
    client_secret_sha TEXT NOT NULL,
    scopes            TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    created_by        INTEGER REFERENCES admins(id),
    revoked_at        INTEGER
);

CREATE TABLE IF NOT EXISTS tokens (
    token_sha    TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('admin', 'partner')),
    subject_id   INTEGER NOT NULL,
    scopes       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tokens_subject ON tokens(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS tokens_expiry ON tokens(expires_at);

CREATE TABLE IF NOT EXISTS samples (
    id           TEXT PRIMARY KEY,
    partner_id   INTEGER NOT NULL REFERENCES partners(id),
    sample_ref   TEXT NOT NULL,
    sample_type  TEXT,
    collected_at TEXT,
    notes        TEXT,
    created_at   INTEGER NOT NULL,
    UNIQUE (partner_id, sample_ref)
);

CREATE TABLE IF NOT EXISTS results (
    sample_id  TEXT PRIMARY KEY REFERENCES samples(id),
    status     TEXT NOT NULL,
    summary    TEXT,
    data       TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by INTEGER REFERENCES admins(id)
);

CREATE TABLE IF NOT EXISTS auth_failures (
    bucket TEXT NOT NULL,
    ts     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_failures_bucket ON auth_failures(bucket, ts);

CREATE TABLE IF NOT EXISTS audit_events (
    id         INTEGER PRIMARY KEY,
    ts         INTEGER NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id   INTEGER,
    action     TEXT NOT NULL,
    target     TEXT
);
"""

REQUIRED_TABLES = {"admins", "partners", "tokens", "samples", "results"}


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def init_db(path: str) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE_PATH"])
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()
