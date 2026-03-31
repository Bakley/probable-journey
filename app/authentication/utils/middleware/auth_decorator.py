"""
app/middleware/auth_middleware.py
═══════════════════════════════════════════════════════════════════
SOLID → S (Single Responsibility)
  One job: read, verify, and enforce tokens on protected routes.

  This is RBAC in its simplest, clearest form:
  1. Extract the token from the Authorization header
  2. Verify the signature and expiry (via security.py)
  3. Check that the user's role is in the allowed set
  4. If all checks pass → let the request through
  5. If any check fails → stop it with 401 or 403

WHAT IS A DECORATOR?
─────────────────────
A decorator is a function that wraps another function.
  @require_role("admin")
  def admin_dashboard():
      ...

Is equivalent to:
  def admin_dashboard():
      ...
  admin_dashboard = require_role("admin")(admin_dashboard)

Every time a client calls  GET /api/admin/users, Flask runs the
wrapper first. The wrapper checks the token. If it passes, it
calls the original function. If not, it returns an error.

ROLE HIERARCHY:
  guest  → can only access guest-level routes
  user   → can access user + guest routes
  admin  → can access everything

We implement this with an explicit "allowed roles" set per route,
not inheritance, because explicit > implicit.

STATUS CODES USED:
  401 Unauthorized  → no token / invalid / expired
  403 Forbidden     → valid token, but your role isn't allowed
═══════════════════════════════════════════════════════════════════
"""

import functools
from flask import request, g
from app.security import decode_token
from app import responses


def _extract_token() -> str | None:
    """
    Pull the JWT out of the Authorization header.

    HTTP convention for bearer tokens:
      Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOj...

    We split on the first space and take the second part.
    Returns None if the header is absent or malformed.
    """
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def require_role(*allowed_roles: str):
    """
    Route decorator that enforces role-based access control.

    Usage:
        @app.route("/api/admin/users")
        @require_role("admin")
        def list_users():
            ...

        @app.route("/api/dashboard")
        @require_role("user", "admin")     ← multiple roles allowed
        def dashboard():
            ...

    After passing, the decoded token payload is available on  g.current_user
    inside the route:
        user_id  = g.current_user["sub"]
        username = g.current_user["username"]
        role     = g.current_user["role"]

    Parameters
    ──────────
    *allowed_roles — one or more role strings that may access this route
    """
    def decorator(func):
        @functools.wraps(func)      # preserves the original function's name/docstring
        def wrapper(*args, **kwargs):

            # ── Step 1: Extract the token ──────────────────────────
            token = _extract_token()
            if not token:
                return responses.error(
                    "Authentication required — provide a Bearer token in the Authorization header",
                    status=401,
                )

            # ── Step 2: Verify signature and expiry ────────────────
            try:
                payload = decode_token(token)
            except ValueError as e:
                return responses.error(str(e), status=401)

            # ── Step 3: Check role ─────────────────────────────────
            user_role = payload.get("role", "guest")
            if user_role not in allowed_roles:
                return responses.error(
                    f"Access denied — this endpoint requires role: {' or '.join(allowed_roles)}. "
                    f"Your role is: {user_role}",
                    status=403,
                )

            # ── Step 4: Attach user info to g for use in route ─────
            # g.current_user is available inside the wrapped function:
            #   user_id = g.current_user["sub"]
            g.current_user = payload

            # ── Step 5: Call the actual route function ─────────────
            return func(*args, **kwargs)

        return wrapper
    return decorator
