"""All HTTP routes."""
import json
import sqlite3
import uuid
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request

from . import clock
from .db import get_db
from .errors import ApiError
from .security import (ALLOWED_SCOPES, admin_required, audit, check_not_locked, clear_failures,
                       hash_password, issue_token, new_client_credentials, partner_scope_required,
                       record_failure, sha256_hex, token_ttl, verify_client_secret, verify_password)

bp = Blueprint("api", __name__)

RESULT_STATUSES = ("preliminary", "final", "rejected")
MAX_DATA_BYTES = 16 * 1024


# --------------------------------------------------------------- helpers ---

def iso(ts: int | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


def json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "invalid_request", "Request body must be a JSON object.")
    return data


def text_field(data: dict, name: str, *, required=False, max_len=200) -> str | None:
    value = data.get(name)
    if value is None:
        if required:
            raise ApiError(400, "invalid_request", f"'{name}' is required.")
        return None
    if not isinstance(value, str):
        raise ApiError(400, "invalid_request", f"'{name}' must be a string.")
    value = value.strip()
    if required and not value:
        raise ApiError(400, "invalid_request", f"'{name}' must not be empty.")
    if len(value) > max_len:
        raise ApiError(400, "invalid_request", f"'{name}' must be at most {max_len} characters.")
    return value or None


def page_params() -> tuple[int, int]:
    try:
        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        raise ApiError(400, "invalid_request", "'limit' and 'offset' must be integers.")
    if not 1 <= limit <= 200 or offset < 0:
        raise ApiError(400, "invalid_request", "'limit' must be 1-200 and 'offset' must be >= 0.")
    return limit, offset


def partner_json(row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "client_id": row["client_id"],
        "scopes": row["scopes"].split(),
        "status": "revoked" if row["revoked_at"] else "active",
        "created_at": iso(row["created_at"]),
        "revoked_at": iso(row["revoked_at"]),
    }


def sample_json(row) -> dict:
    return {
        "id": row["id"],
        "sample_ref": row["sample_ref"],
        "sample_type": row["sample_type"],
        "collected_at": row["collected_at"],
        "notes": row["notes"],
        "received_at": iso(row["created_at"]),
    }


def result_json(row) -> dict | None:
    if row["result_status"] is None:
        return None
    return {
        "status": row["result_status"],
        "summary": row["result_summary"],
        "data": json.loads(row["result_data"]) if row["result_data"] else None,
        "updated_at": iso(row["result_updated_at"]),
    }


RESULT_JOIN = (
    "SELECT s.*, r.status AS result_status, r.summary AS result_summary, r.data AS result_data,"
    " r.updated_at AS result_updated_at FROM samples s LEFT JOIN results r ON r.sample_id = s.id"
)


def sample_with_result_json(row) -> dict:
    result = result_json(row)
    return {
        "sample_id": row["id"],
        "sample_ref": row["sample_ref"],
        "received_at": iso(row["created_at"]),
        "state": "available" if result else "pending",
        "result": result,
    }


def parse_scopes(raw) -> list[str]:
    if not isinstance(raw, list) or not raw or not all(isinstance(s, str) for s in raw):
        raise ApiError(400, "invalid_request", "'scopes' must be a non-empty list of strings.")
    unknown = sorted(set(raw) - set(ALLOWED_SCOPES))
    if unknown:
        raise ApiError(400, "invalid_scope",
                       f"Unknown scope(s): {', '.join(unknown)}. Allowed: {', '.join(ALLOWED_SCOPES)}.")
    return sorted(set(raw))


# ---------------------------------------------------------------- health ---

@bp.get("/health")
def health():
    try:
        get_db().execute("SELECT 1").fetchone()
    except sqlite3.Error:
        return jsonify({"status": "unavailable"}), 503
    return jsonify({"status": "ok"})


# ----------------------------------------------------------- admin login ---

@bp.post("/admin/login")
def admin_login():
    data = json_body()
    username = text_field(data, "username", required=True, max_len=100)
    password = data.get("password")
    if not isinstance(password, str) or not password or len(password) > 1024:
        raise ApiError(400, "invalid_request", "'password' is required.")
    check_not_locked("admin", username)
    db = get_db()
    admin = db.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
    if not verify_password(admin["password_hash"] if admin else None, password):
        record_failure("admin", username)
        raise ApiError(401, "invalid_credentials", "Invalid username or password.")
    clear_failures("admin", username)
    ttl = token_ttl("admin")
    token = issue_token("admin", admin["id"], ["admin"], ttl)
    g.actor = f"admin:{admin['id']}"
    return jsonify({"access_token": token, "token_type": "Bearer", "expires_in": ttl})


@bp.post("/admin/logout")
@admin_required
def admin_logout():
    get_db().execute("DELETE FROM tokens WHERE token_sha = ?", (g.token_sha,))
    return "", 204


# ------------------------------------------------------ admin: partners ---

@bp.post("/admin/partners")
@admin_required
def create_partner():
    data = json_body()
    name = text_field(data, "name", required=True, max_len=100)
    scopes = parse_scopes(data.get("scopes"))
    client_id, client_secret = new_client_credentials()
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO partners (name, client_id, client_secret_sha, scopes, created_at, created_by)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (name, client_id, sha256_hex(client_secret), " ".join(scopes), clock.now(), g.admin["id"]),
        )
    except sqlite3.IntegrityError:
        raise ApiError(409, "conflict", "A partner with this name already exists.")
    audit("partner.create", f"partner:{cur.lastrowid}")
    row = db.execute("SELECT * FROM partners WHERE id = ?", (cur.lastrowid,)).fetchone()
    body = partner_json(row)
    body["client_secret"] = client_secret  # shown exactly once
    return jsonify(body), 201


@bp.get("/admin/partners")
@admin_required
def list_partners():
    limit, offset = page_params()
    rows = get_db().execute(
        "SELECT * FROM partners ORDER BY id LIMIT ? OFFSET ?", (limit, offset)
    ).fetchall()
    return jsonify({"items": [partner_json(r) for r in rows], "limit": limit, "offset": offset})


def _partner_or_404(partner_id: int):
    row = get_db().execute("SELECT * FROM partners WHERE id = ?", (partner_id,)).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "Partner not found.")
    return row


@bp.get("/admin/partners/<int:partner_id>")
@admin_required
def get_partner(partner_id):
    return jsonify(partner_json(_partner_or_404(partner_id)))


@bp.post("/admin/partners/<int:partner_id>/revoke")
@admin_required
def revoke_partner(partner_id):
    partner = _partner_or_404(partner_id)
    db = get_db()
    if partner["revoked_at"] is None:
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("UPDATE partners SET revoked_at = ? WHERE id = ?", (clock.now(), partner_id))
            db.execute("DELETE FROM tokens WHERE subject_type = 'partner' AND subject_id = ?", (partner_id,))
            audit("partner.revoke", f"partner:{partner_id}")
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise
    return jsonify(partner_json(_partner_or_404(partner_id)))


@bp.post("/admin/partners/<int:partner_id>/rotate-secret")
@admin_required
def rotate_secret(partner_id):
    partner = _partner_or_404(partner_id)
    if partner["revoked_at"] is not None:
        raise ApiError(409, "conflict", "Partner is revoked.")
    _, client_secret = new_client_credentials()
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("UPDATE partners SET client_secret_sha = ? WHERE id = ?",
                   (sha256_hex(client_secret), partner_id))
        db.execute("DELETE FROM tokens WHERE subject_type = 'partner' AND subject_id = ?", (partner_id,))
        audit("partner.rotate_secret", f"partner:{partner_id}")
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    body = partner_json(_partner_or_404(partner_id))
    body["client_secret"] = client_secret
    return jsonify(body)


# ------------------------------------------------------- admin: samples ---

@bp.get("/admin/samples")
@admin_required
def admin_list_samples():
    limit, offset = page_params()
    sql, args = RESULT_JOIN, []
    partner_id = request.args.get("partner_id")
    if partner_id is not None:
        if not partner_id.isdigit():
            raise ApiError(400, "invalid_request", "'partner_id' must be an integer.")
        sql += " WHERE s.partner_id = ?"
        args.append(int(partner_id))
    rows = get_db().execute(sql + " ORDER BY s.created_at, s.id LIMIT ? OFFSET ?",
                            (*args, limit, offset)).fetchall()
    items = []
    for r in rows:
        item = sample_with_result_json(r)
        item["partner_id"] = r["partner_id"]
        items.append(item)
    return jsonify({"items": items, "limit": limit, "offset": offset})


@bp.put("/admin/samples/<sample_id>/result")
@admin_required
def admin_put_result(sample_id):
    data = json_body()
    status = data.get("status")
    if status not in RESULT_STATUSES:
        raise ApiError(400, "invalid_request", f"'status' must be one of: {', '.join(RESULT_STATUSES)}.")
    summary = text_field(data, "summary", max_len=2000)
    payload = data.get("data")
    if payload is not None and not isinstance(payload, dict):
        raise ApiError(400, "invalid_request", "'data' must be a JSON object.")
    encoded = json.dumps(payload) if payload is not None else None
    if encoded and len(encoded.encode()) > MAX_DATA_BYTES:
        raise ApiError(400, "invalid_request", f"'data' must be at most {MAX_DATA_BYTES} bytes.")
    db = get_db()
    if db.execute("SELECT 1 FROM samples WHERE id = ?", (sample_id,)).fetchone() is None:
        raise ApiError(404, "not_found", "Sample not found.")
    now = clock.now()
    db.execute(
        "INSERT INTO results (sample_id, status, summary, data, created_at, updated_at, updated_by)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(sample_id) DO UPDATE SET status = excluded.status, summary = excluded.summary,"
        " data = excluded.data, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
        (sample_id, status, summary, encoded, now, now, g.admin["id"]),
    )
    audit("result.put", f"sample:{sample_id}")
    row = db.execute(RESULT_JOIN + " WHERE s.id = ?", (sample_id,)).fetchone()
    return jsonify(sample_with_result_json(row))


# ---------------------------------------------------------------- tokens ---

def _token_request_data():
    """Form-encoded (OAuth standard) or JSON body, always dict-like."""
    if request.is_json:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}
    return request.form


def _client_credentials_from_request():
    data = _token_request_data()
    auth = request.authorization
    if auth and auth.type == "basic":
        return auth.username, auth.password, data
    return data.get("client_id"), data.get("client_secret"), data


@bp.post("/oauth/token")
def token():
    client_id, client_secret, data = _client_credentials_from_request()
    if data.get("grant_type") != "client_credentials":
        raise ApiError(400, "unsupported_grant_type", "grant_type must be 'client_credentials'.")
    if not isinstance(client_id, str) or not isinstance(client_secret, str) or not client_id or not client_secret:
        raise ApiError(401, "invalid_client", "Client authentication failed.",
                       headers={"WWW-Authenticate": 'Basic realm="token"'})
    check_not_locked("client", client_id)
    partner = get_db().execute("SELECT * FROM partners WHERE client_id = ?", (client_id,)).fetchone()
    secret_ok = verify_client_secret(partner["client_secret_sha"] if partner else None, client_secret)
    if not secret_ok or partner["revoked_at"] is not None:
        record_failure("client", client_id)
        raise ApiError(401, "invalid_client", "Client authentication failed.",
                       headers={"WWW-Authenticate": 'Basic realm="token"'})
    clear_failures("client", client_id)

    allowed = partner["scopes"].split()
    requested = data.get("scope")
    if requested is None or requested == "":
        granted = allowed
    elif isinstance(requested, str):
        granted = sorted(set(requested.split()))
        if not set(granted) <= set(allowed):
            raise ApiError(400, "invalid_scope", "Requested scope exceeds what this partner is allowed.")
    else:
        raise ApiError(400, "invalid_request", "'scope' must be a space-separated string.")

    ttl = token_ttl("partner")
    access_token = issue_token("partner", partner["id"], granted, ttl)
    g.actor = f"partner:{partner['id']}"
    return jsonify({"access_token": access_token, "token_type": "Bearer",
                    "expires_in": ttl, "scope": " ".join(granted)})


# --------------------------------------------------------------- samples ---

@bp.post("/samples")
@partner_scope_required("samples:write")
def submit_sample():
    data = json_body()
    sample_ref = text_field(data, "sample_ref", required=True, max_len=100)
    sample_type = text_field(data, "sample_type", max_len=50)
    notes = text_field(data, "notes", max_len=2000)
    collected_at = text_field(data, "collected_at", max_len=40)
    if collected_at is not None:
        try:
            datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
        except ValueError:
            raise ApiError(400, "invalid_request", "'collected_at' must be an ISO 8601 date or date-time.")
    db = get_db()
    partner_id = g.partner["id"]
    existing = db.execute("SELECT id FROM samples WHERE partner_id = ? AND sample_ref = ?",
                          (partner_id, sample_ref)).fetchone()
    if existing:
        raise ApiError(409, "duplicate_sample", f"sample_ref already submitted as sample {existing['id']}.")
    sample_id = str(uuid.uuid4())
    try:
        db.execute(
            "INSERT INTO samples (id, partner_id, sample_ref, sample_type, collected_at, notes, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sample_id, partner_id, sample_ref, sample_type, collected_at, notes, clock.now()),
        )
    except sqlite3.IntegrityError:
        raise ApiError(409, "duplicate_sample", "sample_ref already submitted.")
    row = db.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone()
    return jsonify(sample_json(row)), 201


# --------------------------------------------------------------- results ---

@bp.get("/results")
@partner_scope_required("results:read")
def list_results():
    limit, offset = page_params()
    rows = get_db().execute(
        RESULT_JOIN + " WHERE s.partner_id = ? ORDER BY s.created_at, s.id LIMIT ? OFFSET ?",
        (g.partner["id"], limit, offset),
    ).fetchall()
    return jsonify({"items": [sample_with_result_json(r) for r in rows], "limit": limit, "offset": offset})


@bp.get("/results/<sample_id>")
@partner_scope_required("results:read")
def get_result(sample_id):
    # Someone else's sample looks exactly like a sample that does not exist.
    row = get_db().execute(RESULT_JOIN + " WHERE s.id = ? AND s.partner_id = ?",
                           (sample_id, g.partner["id"])).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "Sample not found.")
    return jsonify(sample_with_result_json(row))
