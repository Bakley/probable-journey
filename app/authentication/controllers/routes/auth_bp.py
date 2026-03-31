"""
app/routes/auth.py
═══════════════════════════════════════════════════════════════════
SOLID → S + D (Single Responsibility, Dependency Inversion)

  Two routes and nothing else:
    POST /api/auth/register  — create a new account
    POST /api/auth/login     — verify credentials → issue JWT

  Routes are thin orchestrators:
    1. Parse JSON body
    2. Call validator  (get errors back as list[str])
    3. Call repository (get data back as dict)
    4. Call security   (get a token back as string)
    5. Return response

  No SQL here. No hashing here. No password logic here.
═══════════════════════════════════════════════════════════════════
"""

from flask import Blueprint, request, g
from app.database import get_db
from app.authentication.model.repository.user_repository import UserRepository
from app.authentication.model.repository.in_memory import UserObj
from app.authentication.utils.validators import user_validator
from app.authentication.utils.cryptographic_operations.security import create_token
from app.authentication.view import api_response

auth_bps = Blueprint("auth", __name__, url_prefix="/api/auth")


def get_repo():
    """Inject DB into UserRepository — routes never call sqlite3 directly."""
    return UserRepository(get_db())


# ── POST /api/auth/register ───────────────────────────────────────
@auth_bps.route("/register", methods=["POST"])
def sign_up():
    """
    Register a new user account.

    Request body (JSON):
    ─────────────────────
    {
      "email":    "alice@example.com",   ← required, must be unique
      "username": "Alice",               ← required, 2–50 chars
      "password": "Secret@99",           ← required, strong password rules
      "role":     "user"                 ← optional, default "user"
    }

    Password rules:
      • At least 8 characters
      • At least one uppercase letter
      • At least one lowercase letter
      • At least one number
      • At least one special character  !@#$%^&*

    Roles allowed at self-registration:  guest, user, admin
    (In a real app you'd restrict admin creation to existing admins.)

    api_response:
      201 Created  → { ok: true,  data: { user: {...}, token: "..." } }
      400          → { ok: false, details: ["error 1", "error 2"] }
      409 Conflict → { ok: false, message: "Email already registered" }
    """

    # import pdb
    # pdb.set_trace()
    body = request.get_json()
    print(body)
    if not body:
        return api_response.error("Request body must be JSON")

    # Validate input — returns plain list[str], no HTTP knowledge
    errors = user_validator.validate_register(body)
    if errors:
        return api_response.error("Validation failed", status=400, details=errors)

    # Clean the data — strip unknown keys, normalise email to lowercase
    clean = user_validator.sanitize_register(body)

    repo = get_repo()

    # Check uniqueness before trying to insert (cleaner error than a DB exception)
    if repo.email_exists(clean["email"]):
        return api_response.error(
            f"Email '{clean['email']}' is already registered. "
            "Please use a different email or log in.",
            status=409,
        )

    # Create the user — repository hashes the password internally
    user = repo.create(clean)

    # Issue a token immediately so the user is logged in right after registration
    token = create_token(
        user_id  = user["id"],
        role     = user["role"],
        username = user["username"],
    )

    return api_response.success(
        data    = {"user": user, "token": token},
        message = f"Welcome, {user['username']}! Your account has been created.",
        status  = 201,
    )


# ── POST /api/auth/login ──────────────────────────────────────────
@auth_bps.route("/login", methods=["POST"])
def login():
    """
    Authenticate and receive a JWT token.

    Request body (JSON):
    ─────────────────────
    {
      "email":    "alice@example.com",
      "password": "Secret@99"
    }

    How authentication works:
    1. Find the user by email
    2. Re-hash the submitted password using the stored salt
    3. Compare hashes (timing-safe, prevents brute-force timing attacks)
    4. If match → issue a JWT signed with the server's SECRET_KEY
    5. Client stores the token and sends it on every subsequent request:
         Authorization: Bearer <token>

    Why we don't say "wrong password" vs "user not found":
    ────────────────────────────────────────────────────────
    Saying "wrong password" confirms that the email exists,
    letting attackers enumerate valid accounts.
    We return the same "Invalid credentials" for both failures.

    api_response:
      200 → { ok: true,  data: { user: {...}, token: "..." } }
      400 → { ok: false, details: [...] }    ← missing fields
      401 → { ok: false, message: "Invalid credentials" }
    """
    body = request.get_json()
    if not body:
        return api_response.error("Request body must be JSON")

    errors = user_validator.validate_login(body)
    if errors:
        return api_response.error("Validation failed", status=400, details=errors)

    repo = get_repo()

    # verify_credentials handles both "no such email" and "wrong password"
    # and returns None for either failure — intentionally ambiguous.
    user = repo.verify_credentials(
        email          = body["email"].strip().lower(),
        plain_password = body["password"],
    )

    if user is None:
        return api_response.error(
            "Invalid credentials — email or password is incorrect",
            status=401,
        )

    token = create_token(
        user_id  = user["id"],
        role     = user["role"],
        username = user["username"],
    )

    return api_response.success(
        data    = {"user": user, "token": token},
        message = f"Welcome back, {user['username']}!",
    )
