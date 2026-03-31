"""
app/security.py
═══════════════════════════════════════════════════════════════════
SOLID → S (Single Responsibility)
  One job: cryptographic operations — hashing passwords and
  signing / verifying JWT tokens.
  Knows nothing about Flask, HTTP, databases, or routes.

WHY HAND-ROLL JWT INSTEAD OF PyJWT?
─────────────────────────────────────
So you can see every byte of how it works.
JWT is just three base64url-encoded JSON blobs joined by dots:
  HEADER.PAYLOAD.SIGNATURE

  Header   → {"alg": "HS256", "typ": "JWT"}
  Payload  → {"sub": 1, "role": "admin", "exp": 1234567890}
  Signature→ HMAC-SHA256(secret, "header.payload")

Anyone can decode header + payload (they're not encrypted).
The signature proves they haven't been tampered with.
Only the server knows the secret key, so only the server can
produce a valid signature.
═══════════════════════════════════════════════════════════════════
"""

import hashlib
import hmac
import base64
import json
import os
from datetime import datetime, timezone

# ── Secret key ────────────────────────────────────────────────────
# In production this comes from an environment variable (never hardcoded).
# We generate a random one at import time for development.
# Every server restart invalidates all existing tokens (fine for learning).
SECRET_KEY: str = os.environ.get("SECRET_KEY", os.urandom(32).hex())

# How long (in seconds) a token stays valid after it's issued.
TOKEN_EXPIRY_SECONDS: int = int(os.environ.get("TOKEN_EXPIRY", 3600))  # 1 hour


# ── Password hashing ──────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """
    Hash a plain-text password using PBKDF2-HMAC-SHA256.

    PBKDF2 is a "key stretching" function — it runs SHA256 many thousands
    of times deliberately, making brute-force attacks expensive.

    Format stored in DB:  "salt$hash"
    The salt is random per-user, so two users with the same password
    produce completely different hashes.

    Parameters
    ──────────
    plain — the raw password the user typed

    Returns
    ───────
    "hex_salt$hex_hash"  — both parts stored as one string
    """
    salt = os.urandom(16)                        # 16 random bytes, unique per user
    digest = hashlib.pbkdf2_hmac(
        hash_name   = "sha256",
        password    = plain.encode("utf-8"),
        salt        = salt,
        iterations  = 260_000,                   # NIST recommended minimum 2023
    )
    return salt.hex() + "$" + digest.hex()


def verify_password(plain: str, stored: str) -> bool:
    """
    Verify a plain-text password against a stored hash.

    We re-hash  plain  using the SAME salt that was used originally,
    then compare with  hmac.compare_digest  which is timing-safe
    (prevents timing attacks where an attacker measures how long
    comparison takes to guess characters one by one).

    Parameters
    ──────────
    plain  — what the user typed at login
    stored — the "salt$hash" string from the database

    Returns
    ───────
    True if the password matches, False otherwise.
    """
    try:
        salt_hex, hash_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False   # Malformed stored hash — treat as failure

    candidate = hashlib.pbkdf2_hmac(
        hash_name   = "sha256",
        password    = plain.encode("utf-8"),
        salt        = salt,
        iterations  = 260_000,
    )
    return hmac.compare_digest(candidate, expected)   # timing-safe comparison


# ── JWT ───────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    """Base64url-encode bytes → string (no padding, URL-safe)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url-decode string → bytes (add back padding as needed)."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _sign(message: str) -> str:
    """
    HMAC-SHA256 sign a string and return base64url-encoded digest.

    HMAC = Hash-based Message Authentication Code.
    It produces a fixed-length "fingerprint" of  message  that can
    only be reproduced by someone who knows SECRET_KEY.
    """
    sig = hmac.new(
        SECRET_KEY.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(sig)


def create_token(user_id: int, role: str, username: str) -> str:
    """
    Issue a signed JWT containing the user's identity and role.

    Structure:  HEADER.PAYLOAD.SIGNATURE

    Header  — algorithm declaration (always HS256 here)
    Payload — the claims (who you are, your role, when this expires)
    Signature — HMAC-SHA256 over "header.payload" using SECRET_KEY

    Parameters
    ──────────
    user_id  — the user's database ID
    role     — 'guest' | 'user' | 'admin'
    username — display name (convenience, not security-critical)

    Returns
    ───────
    A compact JWT string:  "eyJ....eyJ....abc123"
    """
    now = int(datetime.now(timezone.utc).timestamp())

    header = _b64url_encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    payload = _b64url_encode(
        json.dumps(
            {
                "sub":      user_id,          # subject — who this token is for
                "username": username,
                "role":     role,
                "iat":      now,              # issued-at
                "exp":      now + TOKEN_EXPIRY_SECONDS,  # expiry
            },
            separators=(",", ":"),
        ).encode()
    )

    signature = _sign(f"{header}.{payload}")
    return f"{header}.{payload}.{signature}"


def decode_token(token: str) -> dict:
    """
    Verify and decode a JWT.

    Steps:
    1. Split into header, payload, signature
    2. Re-compute what the signature SHOULD be from header + payload
    3. Compare with the provided signature (timing-safe)
    4. Decode the payload JSON
    5. Check the expiry timestamp

    Parameters
    ──────────
    token — the JWT string from the Authorization header

    Returns
    ───────
    The payload dict on success:
      {"sub": 1, "username": "Alice", "role": "admin", "iat": ..., "exp": ...}

    Raises
    ──────
    ValueError with a descriptive message on any failure.
    The middleware catches this and returns 401.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed token — expected 3 parts")

        header_b64, payload_b64, provided_sig = parts

        # Step 1: re-compute expected signature
        expected_sig = _sign(f"{header_b64}.{payload_b64}")

        # Step 2: constant-time compare (prevents timing attacks)
        if not hmac.compare_digest(provided_sig, expected_sig):
            raise ValueError("Invalid signature — token was tampered with")

        # Step 3: decode payload
        payload = json.loads(_b64url_decode(payload_b64))

        # Step 4: check expiry
        now = int(datetime.now(timezone.utc).timestamp())
        if payload.get("exp", 0) < now:
            raise ValueError("Token expired — please log in again")

        return payload

    except (ValueError, KeyError, json.JSONDecodeError) as e:
        raise ValueError(str(e)) from e
    