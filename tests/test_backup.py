import io
import sqlite3

import pytest

from conftest import ADMIN_PASSWORD, get_token

from partnerapi import create_app, dbtool


def test_backup_then_restore_roundtrip(db_path, client, make_partner, token_for, admin_headers):
    partner = make_partner(name="Before backup")
    headers = token_for(partner)
    client.post("/samples", headers=headers, json={"sample_ref": "KEEP-ME"})

    buffer = io.BytesIO()
    dbtool.backup(db_path, buffer)
    assert buffer.getvalue().startswith(b"SQLite format 3")

    # Damage the live data after the backup was taken.
    client.post(f"/admin/partners/{partner['id']}/revoke", headers=admin_headers)
    client.post("/admin/partners", headers=admin_headers, json={"name": "After backup", "scopes": ["results:read"]})

    dbtool.restore(db_path, io.BytesIO(buffer.getvalue()))

    restored = create_app({"DATABASE_PATH": db_path}).test_client()
    login = restored.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    admin = {"Authorization": "Bearer " + login.get_json()["access_token"]}
    names = [p["name"] for p in restored.get("/admin/partners", headers=admin).get_json()["items"]]
    assert "Before backup" in names and "After backup" not in names
    # The partner was active when the backup was made, so it is active again, with its sample.
    assert get_token(restored, partner).status_code == 200
    samples = restored.get("/admin/samples", headers=admin).get_json()["items"]
    assert "KEEP-ME" in [s["sample_ref"] for s in samples]


def test_restore_keeps_previous_database_as_a_safety_copy(db_path, app):
    buffer = io.BytesIO()
    dbtool.backup(db_path, buffer)
    dbtool.restore(db_path, io.BytesIO(buffer.getvalue()))
    assert sqlite3.connect(db_path + ".pre-restore").execute("SELECT count(*) FROM admins").fetchone()[0] == 1


def test_restore_refuses_garbage_and_leaves_data_untouched(db_path, app):
    with pytest.raises(Exception):
        dbtool.restore(db_path, io.BytesIO(b"this is not a database" * 100))
    assert sqlite3.connect(db_path).execute("SELECT count(*) FROM admins").fetchone()[0] == 1


def test_restore_refuses_a_foreign_sqlite_database(db_path, tmp_path, app):
    other = tmp_path / "other.db"
    conn = sqlite3.connect(other)
    conn.execute("CREATE TABLE unrelated (x)")
    conn.commit()
    conn.close()
    with pytest.raises(SystemExit):
        dbtool.restore(db_path, open(other, "rb"))
    assert sqlite3.connect(db_path).execute("SELECT count(*) FROM admins").fetchone()[0] == 1
