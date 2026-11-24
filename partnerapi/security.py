"""Credentials, tokens, throttling and the auth decorators."""
import hashlib
import hmac
import secrets
from functools import wraps

from flask import current_app, g, request
from werkzeug.security import check_password_hash, generate_password_hash

from . import clock
from .db import get_db
from .errors import ApiError

ALLOWED_SCOPES = ("samples:write", "results:read")

# A real scrypt hash of a random value; checked when the username is unknown so
# that response time does not reveal which usernames exist.
_DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_hex(16))
_DUMMY_SECRET_SHA = hashlib.sha256(b"dummy").hexdigest()

MAX_FAILURES = 5
FAILURE_WINDOW = 300  # seconds


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    ok = check_password_hash(stored_hash or _DUMMY_PASSWORD_HASH, password)
    return ok and stored_hash is not None


def new_client_credentials() -> tuple[str, str]:
    """Return (client_id, client_secret). The secret is 256 bits of randomness,
    so a fast hash is adequate for storage (unlike a human password)."""
    return "pl_" + secrets.token_hex(8), "pls_" + secrets.token_urlsafe(32)


def verify_client_secret(stored_sha: str | None, secret: str) -> bool:
    candidate = sha256_hex(secret)
    ok = hmac.compare_digest(candidate, stored_sha or _DUMMY_SECRET_SHA)
    return ok and stored_sha is not None


# ---------------------------------------------------------------- tokens ---

def issue_token(subject_type: str, subject_id: int, scopes: list[str], ttl: int) -> str:
    token = secrets.token_urlsafe(32)
    db = get_db()
    now = clock.now()
    db.execute("DELETE FROM tokens WHERE expires_at <= ?", (now,))
    db.execute(
        "INSERT INTO tokens (token_sha, subject_type, subject_id, scopes, created_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (sha256_hex(token), subject_type, subject_id, " ".join(scopes), now, now + ttl),
    )
    return token


def _bearer_token() -> str | None:
    header = request.headers.get("Authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def _unauthorized(message="Missing, invalid or expired access token."):
    return ApiError(401, "invalid_token", message, headers={"WWW-Authenticate": "Bearer"})


def _authenticate(subject_type: str):
    token = _bearer_token()
    if token is None:
        raise _unauthorized()
    db = get_db()
    row = db.execute(
        "SELECT * FROM tokens WHERE token_sha = ? AND subject_type = ?",
        (sha256_hex(token), subject_type),
    ).fetchone()
    if row is None or row["expires_at"] <= clock.now():
        raise _unauthorized()
    if subject_type == "partner":
        # Revocation takes effect on the very next request: the partner row is
        # consulted every time, not only when the token was issued.
        partner = db.execute(
            "SELECT * FROM partners WHERE id = ? AND revoked_at IS NULL", (row["subject_id"],)
        ).fetchone()
        if partner is None:
            raise _unauthorized()
        g.partner = partner
        g.actor = f"partner:{partner['id']}"
    else:
        admin = db.execute("SELECT * FROM admins WHERE id = ?", (row["subject_id"],)).fetchone()
        if admin is None:
            raise _unauthorized()
        g.admin = admin
        g.actor = f"admin:{admin['id']}"
    g.token_scopes = set(row["scopes"].split())
    g.token_sha = row["token_sha"]


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        _authenticate("admin")
        return view(*args, **kwargs)
    return wrapper


def partner_scope_required(scope: str):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            _authenticate("partner")
            if scope not in g.token_scopes:
                raise ApiError(403, "insufficient_scope",
                               f"This token does not carry the '{scope}' scope.",
                               headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{scope}"'})
            return view(*args, **kwargs)
        return wrapper
    return decorator


# ------------------------------------------------------------ throttling ---

def client_ip() -> str:
    # The app is only reachable through the reverse proxy, which sets
    # X-Forwarded-For to the real peer address.
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.remote_addr or "unknown"


def _bucket(kind: str, identifier: str) -> str:
    return f"{kind}|{identifier.lower()}|{client_ip()}"


def check_not_locked(kind: str, identifier: str) -> None:
    db = get_db()
    now = clock.now()
    rows = db.execute(
        "SELECT ts FROM auth_failures WHERE bucket = ? AND ts > ? ORDER BY ts",
        (_bucket(kind, identifier), now - FAILURE_WINDOW),
    ).fetchall()
    if len(rows) >= MAX_FAILURES:
        retry = max(1, rows[0]["ts"] + FAILURE_WINDOW - now)
        raise ApiError(429, "too_many_attempts", "Too many failed attempts. Try again later.",
                       headers={"Retry-After": str(retry)})


def record_failure(kind: str, identifier: str) -> None:
    db = get_db()
    now = clock.now()
    db.execute("DELETE FROM auth_failures WHERE ts <= ?", (now - FAILURE_WINDOW,))
    db.execute("INSERT INTO auth_failures (bucket, ts) VALUES (?, ?)", (_bucket(kind, identifier), now))


def clear_failures(kind: str, identifier: str) -> None:
    get_db().execute("DELETE FROM auth_failures WHERE bucket = ?", (_bucket(kind, identifier),))


def audit(action: str, target: str | None = None) -> None:
    actor_type, _, actor_id = (g.get("actor") or "system:").partition(":")
    get_db().execute(
        "INSERT INTO audit_events (ts, actor_type, actor_id, action, target) VALUES (?, ?, ?, ?, ?)",
        (clock.now(), actor_type, int(actor_id) if actor_id else None, action, target),
    )


def token_ttl(kind: str) -> int:
    return current_app.config["PARTNER_TOKEN_TTL" if kind == "partner" else "ADMIN_TOKEN_TTL"]
