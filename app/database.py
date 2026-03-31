"""
database.py
═══════════════════════════════════════════════════════════════════
SOLID → S (Single Responsibility)
  One job: manage SQLite connections and bootstrap the schema.
  Knows nothing about users, tokens, roles, or HTTP.

WHY NO HARDCODED SEED ADMIN?
──────────────────────────────
Previously this file seeded "admin@app.com / Admin@1234" on first
boot. That is a serious security problem:

  1. The password is in the source code — anyone who reads the repo
     (or the git history) knows it forever.
  2. It cannot be changed without editing code and redeploying.
  3. It ends up in git history even after it's "removed".
  4. It violates the Twelve-Factor App principle: config ≠ code.

The correct approach is a CLI tool (cli.py) that prompts a human
operator for credentials interactively at deploy time, validates
them with the same rules as the API, and inserts them once.
The app itself never touches first-user creation.
═══════════════════════════════════════════════════════════════════
"""

import sqlite3
from flask import g

DATABASE = "rbac"


def get_db() -> sqlite3.Connection:
    """
    Return (or create) the DB connection for the current request.

    Flask's  g  bag lives for one HTTP request.
    Every function in that request gets the SAME connection — not a new one each call.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row   # row["email"] instead of row[0]
        g.db.execute("PRAGMA journal_mode=WAL")   # safer concurrent writes
        g.db.execute("PRAGMA foreign_keys=ON")    # enforce FK constraints
    return g.db


def close_db(error=None) -> None:
    """Close the connection at the end of every request."""
    db = g.pop("db", None)
    if db:
        db.close()


def open_direct() -> sqlite3.Connection:
    """
    Open a raw SQLite connection WITHOUT Flask's request context.

    Used by cli.py which runs outside a web request — there is no  g,
    no  request, no  app  object. We talk to the database directly.

    The caller is responsible for closing this connection.
    """
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def init_db() -> None:
    """
    Create tables on first run. Safe to call repeatedly (IF NOT EXISTS).

    TABLE: users
    ─────────────────────────────────────────────────────────────
    id         — auto-assigned integer primary key
    email      — unique login identifier
    username   — display name
    password   — PBKDF2 hash (never plain text)
    role       — 'guest' | 'user' | 'admin'
    is_active  — soft-disable an account without deleting it
    created_at — ISO timestamp of registration
    """
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT    NOT NULL UNIQUE,
            username   TEXT    NOT NULL,
            password   TEXT    NOT NULL,
            role       TEXT    NOT NULL DEFAULT 'user',
            is_active  INTEGER NOT NULL DEFAULT 1,
            created_at TEXT    NOT NULL
        )
    """)
    db.commit()
    # No seed data. Run  python cli.py create-admin  to create the first admin.
    