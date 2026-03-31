"""
═══════════════════════════════════════════════════════════════════
SOLID → S + D + L (Single Responsibility, Dependency Inversion,
                    Liskov Substitution)

  One job: all SQL that touches the  users  table.
  Routes and middleware never write SQL — they call this class.

  Receives its DB connection via injection (not sqlite3.connect() here).
  Returns plain Python dicts — no Flask, no HTTP, no JSON.

  Swap this for  PostgresUserRepository  later:
  same method names, routes don't notice.
═══════════════════════════════════════════════════════════════════
"""

import sqlite3
from datetime import datetime
from app.authentication.utils.cryptographic_operations.security import hash_password, verify_password


class UserRepository:
    """All database operations for the  users  table."""

    def __init__(self, db: sqlite3.Connection):
        # SOLID (Dependancy injection): the connection is injected — not created here.
        self._db = db

    # ── READ ──────────────────────────────────────────────────────

    def find_by_email(self, email: str) -> dict | None:
        """
        Look up a user by email address.
        Returns a plain dict or None if not found.
        Used during login to find who's logging in.
        """
        row = self._db.execute(
            "SELECT * FROM users WHERE email = ?", (email.lower(),)
        ).fetchone()
        return dict(row) if row else None

    def find_by_id(self, user_id: int) -> dict | None:
        """Look up a user by their numeric ID."""
        row = self._db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return dict(row) if row else None

    def email_exists(self, email: str) -> bool:
        """
        Check if an email is already registered.
        Called during registration to prevent duplicates.
        Returns True / False — the route decides what HTTP response to give.
        """
        count = self._db.execute(
            "SELECT COUNT(*) FROM users WHERE email = ?", (email.lower(),)
        ).fetchone()[0]
        return count > 0

    def find_all(self) -> list[dict]:
        """
        Return every user (admin-only use).
        Excludes the password hash from the response — never expose it.
        """
        rows = self._db.execute(
            "SELECT id, email, username, role, is_active, created_at FROM users ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]

    # ── WRITE ─────────────────────────────────────────────────────

    def create(self, data: dict) -> dict:
        """
        Insert a new user and return the created record (without password).

        data must contain: email, username, password (plain), role
        The plain password is hashed HERE — the validator never hashes,
        the route never hashes. Only the repository touches security.

        Returns the new user dict (without the password hash).
        """
        hashed = hash_password(data["password"])
        now    = datetime.utcnow().isoformat()

        cursor = self._db.execute(
            "INSERT INTO users (email, username, password, role, created_at) VALUES (?,?,?,?,?)",
            (data["email"], data["username"], hashed, data["role"], now),
        )
        self._db.commit()

        # Return the new user without the password field
        return self._safe(self.find_by_id(cursor.lastrowid))

    def verify_credentials(self, email: str, plain_password: str) -> dict | None:
        """
        Verify email + password and return the user if correct.

        Returns the user dict (without password) on success.
        Returns None if email doesn't exist or password is wrong.

        Note: we return the SAME None for both "no such email" and
        "wrong password". This is intentional — telling attackers
        which one failed would let them enumerate valid emails.
        """
        user = self.find_by_email(email)

        if user is None:
            return None

        if not user.get("is_active"):
            return None   # Account disabled

        if not verify_password(plain_password, user["password"]):
            return None   # Wrong password

        return self._safe(user)

    def update_role(self, user_id: int, new_role: str) -> dict | None:
        """
        Change a user's role (admin-only operation).
        Returns the updated user or None if user doesn't exist.
        """
        if self.find_by_id(user_id) is None:
            return None
        self._db.execute(
            "UPDATE users SET role = ? WHERE id = ?", (new_role, user_id)
        )
        self._db.commit()
        return self._safe(self.find_by_id(user_id))

    def deactivate(self, user_id: int) -> bool:
        """
        Soft-delete: set is_active = 0.
        Returns True on success, False if user doesn't exist.
        """
        if self.find_by_id(user_id) is None:
            return False
        self._db.execute(
            "UPDATE users SET is_active = 0 WHERE id = ?", (user_id,)
        )
        self._db.commit()
        return True

    # ── HELPERS ───────────────────────────────────────────────────

    @staticmethod
    def _safe(user: dict | None) -> dict | None:
        """
        Remove the  password  field before returning to caller.

        The password hash should NEVER leave the repository layer.
        Not to the route, not to the response, not anywhere.
        """
        if user is None:
            return None
        return {k: v for k, v in user.items() if k != "password"}
