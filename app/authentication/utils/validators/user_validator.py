"""
═══════════════════════════════════════════════════════════════════
SOLID → S + I (Single Responsibility + Interface Segregation)

  One job: validate user input for registration and login.

  Returns  list[str]  — a list of error messages.
  Empty list = valid.  Non-empty = reject with 400.

  Zero Flask imports. Zero HTTP. Zero SQL.
  This is pure Python logic — testable with one function call.
═══════════════════════════════════════════════════════════════════
"""

import re

# Valid roles a user can self-assign at registration.
# Admins can only be created by another admin (enforced in the route).
VALID_ROLES = {"guest", "user", "admin"}

# Email regex — simple but covers 99.9% of real addresses
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Password rules — clear, enforceable, human-readable
_PASSWORD_RULES = [
    (lambda p: len(p) >= 8,               "at least 8 characters"),
    (lambda p: re.search(r"[A-Z]", p),    "at least one uppercase letter"),
    (lambda p: re.search(r"[a-z]", p),    "at least one lowercase letter"),
    (lambda p: re.search(r"\d", p),       "at least one number"),
    (lambda p: re.search(r"[!@#$%^&*]",p),"at least one special character (!@#$%^&*)"),
]


def validate_register(body: dict) -> list[str]:
    """
    Validate registration payload.

    Required fields:  email, username, password
    Optional fields:  role (defaults to 'user')

    Returns a list of human-readable errors.
    """
    errors: list[str] = []

    if not isinstance(body, dict):
        return ["Request body must be a JSON object"]

    # ── email ──────────────────────────────────────────
    email = body.get("email", "").strip()
    if not email:
        errors.append("'email' is required")
    elif not EMAIL_RE.match(email):
        errors.append("'email' must be a valid email address (e.g. user@example.com)")

    # ── username ───────────────────────────────────────
    username = str(body.get("username", "")).strip()
    if not username:
        errors.append("'username' is required")
    elif len(username) < 2:
        errors.append("'username' must be at least 2 characters")
    elif len(username) > 50:
        errors.append("'username' must be 50 characters or fewer")

    # ── password ───────────────────────────────────────
    password = body.get("password", "")
    if not password:
        errors.append("'password' is required")
    else:
        failed = [msg for check, msg in _PASSWORD_RULES if not check(password)]
        for rule in failed:
            errors.append(f"Password must contain {rule}")

    # ── role (optional) ────────────────────────────────
    role = body.get("role", "user")
    if role not in VALID_ROLES:
        errors.append(f"'role' must be one of: {', '.join(sorted(VALID_ROLES))}")

    return errors


def validate_login(body: dict) -> list[str]:
    """
    Validate login payload.

    Required fields: email, password
    We do minimal validation here — just presence.
    Strong validation happens in the repository (wrong password = 401).
    """
    errors: list[str] = []

    if not isinstance(body, dict):
        return ["Request body must be a JSON object"]

    if not body.get("email", "").strip():
        errors.append("'email' is required")

    if not body.get("password", ""):
        errors.append("'password' is required")

    return errors


def sanitize_register(body: dict) -> dict:
    """
    Return a clean dict with only the fields we trust.
    Strips unknown keys so nothing unexpected reaches the DB.
    """
    return {
        "email":    body.get("email", "").strip().lower(),
        "username": body.get("username", "").strip(),
        "password": body.get("password", ""),          # raw — hashed in repo
        "role":     body.get("role", "user"),
    }
