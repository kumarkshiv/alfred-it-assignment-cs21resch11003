"""Create the sample users at start-up.

Roles: one admin (a person) and one demo partner lab (an API client).
Passwords and secrets are random unless ADMIN_PASSWORD is set, and they are
written to a 0600 file on the data volume rather than to the logs or the repo.
"""
import os
import secrets
import uuid

from . import clock
from .db import connect, init_db
from .security import hash_password, new_client_credentials, sha256_hex

DEMO_PARTNER = "Demo Lab"


def seed(db_path: str, credentials_path: str, admin_username="admin", admin_password=None) -> list[str]:
    """Idempotent. Returns the names of the accounts it created."""
    init_db(db_path)
    conn = connect(db_path)
    created, lines = [], []
    try:
        conn.execute("BEGIN IMMEDIATE")
        now = clock.now()

        admin = conn.execute("SELECT id FROM admins WHERE username = ?", (admin_username,)).fetchone()
        if admin is None:
            password = admin_password or secrets.token_urlsafe(18)
            cur = conn.execute("INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
                               (admin_username, hash_password(password), now))
            admin_id = cur.lastrowid
            created.append(f"admin:{admin_username}")
            lines += [f"admin username: {admin_username}",
                      f"admin password: {password}" + ("  (from ADMIN_PASSWORD)" if admin_password else "")]
        else:
            admin_id = admin["id"]

        if conn.execute("SELECT 1 FROM partners WHERE name = ?", (DEMO_PARTNER,)).fetchone() is None:
            client_id, client_secret = new_client_credentials()
            cur = conn.execute(
                "INSERT INTO partners (name, client_id, client_secret_sha, scopes, created_at, created_by)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (DEMO_PARTNER, client_id, sha256_hex(client_secret), "results:read samples:write", now, admin_id))
            sample_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO samples (id, partner_id, sample_ref, sample_type, collected_at, notes, created_at)"
                " VALUES (?, ?, 'DEMO-0001', 'blood', NULL, 'Seeded demo sample', ?)",
                (sample_id, cur.lastrowid, now))
            conn.execute(
                "INSERT INTO results (sample_id, status, summary, data, created_at, updated_at, updated_by)"
                " VALUES (?, 'final', 'Demo result', '{\"example\": true}', ?, ?, ?)",
                (sample_id, now, now, admin_id))
            created.append(f"partner:{DEMO_PARTNER}")
            lines += [f"demo partner client_id: {client_id}", f"demo partner client_secret: {client_secret}"]

        if lines:
            # Written inside the transaction so a crash cannot lose the only copy
            # of a secret that was already committed.
            fd = os.open(credentials_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as handle:
                handle.write("\n".join(lines) + "\n")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    return created


def main() -> None:
    if os.environ.get("SEED_SAMPLE_USERS", "1") != "1":
        print("sample users disabled (SEED_SAMPLE_USERS != 1)", flush=True)
        return
    db_path = os.environ.get("DATABASE_PATH", "/data/partnerapi.db")
    credentials_path = os.environ.get("CREDENTIALS_FILE",
                                      os.path.join(os.path.dirname(db_path), "initial-credentials.txt"))
    created = seed(db_path, credentials_path,
                   admin_username=os.environ.get("ADMIN_USERNAME", "admin"),
                   admin_password=os.environ.get("ADMIN_PASSWORD") or None)
    if created:
        print(f"created sample accounts {created}; sign-in details are in {credentials_path}", flush=True)
    else:
        print("sample accounts already exist", flush=True)


if __name__ == "__main__":
    main()
