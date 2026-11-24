import json
import sqlite3

from conftest import ADMIN_PASSWORD, get_token

from partnerapi import create_app
from partnerapi.seed import seed


# ----------------------------------------------------------------- health ---

def test_health_needs_no_login(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok"}


# ------------------------------------------------------------ admin login ---

def test_admin_login_and_bad_password(client):
    assert client.post("/admin/login", json={"username": "admin", "password": "nope"}).status_code == 401
    assert client.post("/admin/login", json={"username": "ghost", "password": "nope"}).status_code == 401
    ok = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert ok.status_code == 200 and ok.get_json()["token_type"] == "Bearer"


def test_admin_login_locks_after_repeated_failures(client):
    for _ in range(5):
        assert client.post("/admin/login", json={"username": "admin", "password": "x"}).status_code == 401
    locked = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert locked.status_code == 429 and "Retry-After" in locked.headers


def test_admin_endpoints_require_admin_token(client, make_partner, token_for):
    assert client.get("/admin/partners").status_code == 401
    partner = make_partner()
    # A partner's access token must never open admin endpoints.
    assert client.get("/admin/partners", headers=token_for(partner)).status_code == 401


def test_logout_invalidates_admin_token(client, admin_headers):
    assert client.post("/admin/logout", headers=admin_headers).status_code == 204
    assert client.get("/admin/partners", headers=admin_headers).status_code == 401


# --------------------------------------------------------- partner admin ---

def test_register_partner_returns_secret_once(client, admin_headers):
    r = client.post("/admin/partners", headers=admin_headers,
                    json={"name": "Acme Labs", "scopes": ["samples:write"]})
    assert r.status_code == 201
    body = r.get_json()
    assert body["client_id"].startswith("pl_") and body["client_secret"].startswith("pls_")
    assert body["scopes"] == ["samples:write"] and body["status"] == "active"

    for url in ("/admin/partners", f"/admin/partners/{body['id']}"):
        listing = json.dumps(client.get(url, headers=admin_headers).get_json())
        assert body["client_secret"] not in listing


def test_register_partner_validation(client, admin_headers):
    post = lambda payload: client.post("/admin/partners", headers=admin_headers, json=payload)  # noqa: E731
    assert post({"scopes": ["samples:write"]}).status_code == 400            # no name
    assert post({"name": "A", "scopes": []}).status_code == 400              # empty scopes
    assert post({"name": "A", "scopes": ["admin:all"]}).status_code == 400   # unknown scope
    assert post({"name": "A", "scopes": "samples:write"}).status_code == 400
    assert post({"name": "Dup", "scopes": ["samples:write"]}).status_code == 201
    assert post({"name": "dup", "scopes": ["samples:write"]}).status_code == 409  # case-insensitive


def test_secrets_and_tokens_are_not_stored_in_plaintext(client, db_path, make_partner, token_for):
    partner = make_partner()
    headers = token_for(partner)
    raw = sqlite3.connect(db_path).execute(
        "SELECT group_concat(client_secret_sha) FROM partners").fetchone()[0]
    stored_tokens = " ".join(r[0] for r in sqlite3.connect(db_path).execute("SELECT token_sha FROM tokens"))
    assert partner["client_secret"] not in raw
    assert headers["Authorization"].split()[1] not in stored_tokens
    pw_hash = sqlite3.connect(db_path).execute("SELECT password_hash FROM admins").fetchone()[0]
    assert ADMIN_PASSWORD not in pw_hash


# ------------------------------------------------------------------ tokens ---

def test_token_exchange_and_fifteen_minute_expiry(client, make_partner, fake_clock):
    partner = make_partner()
    r = get_token(client, partner)
    assert r.status_code == 200
    body = r.get_json()
    assert body["expires_in"] == 900 and body["token_type"] == "Bearer"
    headers = {"Authorization": f"Bearer {body['access_token']}"}

    fake_clock.advance(899)
    assert client.get("/results", headers=headers).status_code == 200
    fake_clock.advance(2)  # 901 s after issue
    expired = client.get("/results", headers=headers)
    assert expired.status_code == 401
    assert "Bearer" in expired.headers["WWW-Authenticate"]


def test_token_accepts_basic_auth_and_json(client, make_partner):
    import base64
    partner = make_partner()
    basic = base64.b64encode(f"{partner['client_id']}:{partner['client_secret']}".encode()).decode()
    r = client.post("/oauth/token", data={"grant_type": "client_credentials"},
                    headers={"Authorization": f"Basic {basic}"})
    assert r.status_code == 200
    r = client.post("/oauth/token", json={"grant_type": "client_credentials",
                                          "client_id": partner["client_id"],
                                          "client_secret": partner["client_secret"]})
    assert r.status_code == 200


def test_token_rejects_bad_credentials_and_grant(client, make_partner):
    partner = make_partner()
    bad = dict(partner, client_secret="pls_wrong")
    assert get_token(client, bad).status_code == 401
    assert get_token(client, dict(partner, client_id="pl_unknown")).status_code == 401
    r = client.post("/oauth/token", data={"grant_type": "password", "client_id": "x", "client_secret": "y"})
    assert r.status_code == 400 and r.get_json()["error"] == "unsupported_grant_type"


def test_token_scope_is_limited_to_what_partner_may_have(client, make_partner):
    partner = make_partner(scopes=["results:read"])
    assert get_token(client, partner, scope="samples:write").status_code == 400
    r = get_token(client, partner, scope="results:read")
    assert r.status_code == 200 and r.get_json()["scope"] == "results:read"
    assert get_token(client, partner).get_json()["scope"] == "results:read"


def test_token_endpoint_locks_after_repeated_failures(client, make_partner):
    partner = make_partner()
    bad = dict(partner, client_secret="pls_wrong")
    for _ in range(5):
        assert get_token(client, bad).status_code == 401
    assert get_token(client, partner).status_code == 429


# ------------------------------------------------------- samples & results ---

def submit(client, headers, ref="S-1", **extra):
    return client.post("/samples", headers=headers, json={"sample_ref": ref, **extra})


def test_partner_submits_sample(client, make_partner, token_for):
    headers = token_for(make_partner())
    r = submit(client, headers, sample_type="blood", collected_at="2026-11-20T09:30:00Z", notes="fasting")
    assert r.status_code == 201
    body = r.get_json()
    assert body["sample_ref"] == "S-1" and body["sample_type"] == "blood" and body["id"]


def test_sample_validation_and_duplicates(client, make_partner, token_for):
    headers = token_for(make_partner())
    assert client.post("/samples", headers=headers, json={}).status_code == 400
    assert client.post("/samples", headers=headers, data="not json").status_code == 400
    assert submit(client, headers, collected_at="yesterday-ish").status_code == 400
    assert submit(client, headers, ref="x" * 101).status_code == 400
    assert submit(client, headers, ref="S-1").status_code == 201
    assert submit(client, headers, ref="S-1").status_code == 409


def test_oversized_body_is_rejected(client, make_partner, token_for):
    headers = token_for(make_partner())
    assert submit(client, headers, notes="x" * 100_000).status_code == 413


def test_same_sample_ref_is_allowed_for_different_partners(client, make_partner, token_for):
    a, b = token_for(make_partner()), token_for(make_partner())
    assert submit(client, a, ref="SAME").status_code == 201
    assert submit(client, b, ref="SAME").status_code == 201


def test_scopes_are_enforced(client, make_partner, token_for):
    writer = token_for(make_partner(scopes=["samples:write"]))
    reader = token_for(make_partner(scopes=["results:read"]))
    assert submit(client, reader).status_code == 403
    assert client.get("/results", headers=writer).status_code == 403
    assert submit(client, writer).status_code == 201
    assert client.get("/results", headers=reader).status_code == 200


def test_endpoints_need_a_token(client):
    assert client.post("/samples", json={"sample_ref": "x"}).status_code == 401
    assert client.get("/results").status_code == 401
    assert client.get("/results", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_partner_reads_results_of_own_samples_only(client, make_partner, token_for, admin_headers):
    alice, bob = token_for(make_partner()), token_for(make_partner())
    sample = submit(client, alice, ref="A-1").get_json()

    # Pending until a lab admin records a result.
    pending = client.get(f"/results/{sample['id']}", headers=alice).get_json()
    assert pending["state"] == "pending" and pending["result"] is None

    r = client.put(f"/admin/samples/{sample['id']}/result", headers=admin_headers,
                   json={"status": "final", "summary": "Negative", "data": {"value": 0.2}})
    assert r.status_code == 200

    done = client.get(f"/results/{sample['id']}", headers=alice).get_json()
    assert done["state"] == "available"
    assert done["result"]["status"] == "final" and done["result"]["data"] == {"value": 0.2}

    listed = client.get("/results", headers=alice).get_json()["items"]
    assert [i["sample_ref"] for i in listed] == ["A-1"]

    # Bob can neither see nor tell apart Alice's sample.
    assert client.get(f"/results/{sample['id']}", headers=bob).status_code == 404
    assert client.get("/results/does-not-exist", headers=bob).status_code == 404
    assert client.get("/results", headers=bob).get_json()["items"] == []


def test_admin_result_validation(client, make_partner, token_for, admin_headers):
    sample = submit(client, token_for(make_partner())).get_json()
    url = f"/admin/samples/{sample['id']}/result"
    assert client.put(url, headers=admin_headers, json={"status": "maybe"}).status_code == 400
    assert client.put(url, headers=admin_headers, json={"status": "final", "data": [1]}).status_code == 400
    assert client.put("/admin/samples/nope/result", headers=admin_headers,
                      json={"status": "final"}).status_code == 404


def test_admin_can_list_samples_by_partner(client, make_partner, token_for, admin_headers):
    p1, p2 = make_partner(), make_partner()
    submit(client, token_for(p1), ref="one")
    submit(client, token_for(p2), ref="two")
    items = client.get(f"/admin/samples?partner_id={p1['id']}", headers=admin_headers).get_json()["items"]
    assert [i["sample_ref"] for i in items] == ["one"]


def test_pagination_limits(client, admin_headers):
    assert client.get("/admin/partners?limit=0", headers=admin_headers).status_code == 400
    assert client.get("/admin/partners?limit=abc", headers=admin_headers).status_code == 400
    assert client.get("/admin/partners?limit=1", headers=admin_headers).status_code == 200


# ------------------------------------------------------------- revocation ---

def test_revoking_a_partner_cuts_access_at_once(client, make_partner, token_for, admin_headers):
    partner = make_partner()
    headers = token_for(partner)
    assert submit(client, headers).status_code == 201  # works before revocation

    r = client.post(f"/admin/partners/{partner['id']}/revoke", headers=admin_headers)
    assert r.status_code == 200 and r.get_json()["status"] == "revoked"

    # The token issued earlier is dead immediately, with no waiting for its 15 minutes.
    assert submit(client, headers, ref="S-2").status_code == 401
    assert client.get("/results", headers=headers).status_code == 401
    # And the credentials can no longer be exchanged for a new one.
    assert get_token(client, partner).status_code == 401
    # Revoking twice is harmless.
    assert client.post(f"/admin/partners/{partner['id']}/revoke", headers=admin_headers).status_code == 200


def test_revoking_one_partner_leaves_others_working(client, make_partner, token_for, admin_headers):
    a, b = make_partner(), make_partner()
    headers_b = token_for(b)
    client.post(f"/admin/partners/{a['id']}/revoke", headers=admin_headers)
    assert client.get("/results", headers=headers_b).status_code == 200


def test_revoke_unknown_partner_is_404(client, admin_headers):
    assert client.post("/admin/partners/9999/revoke", headers=admin_headers).status_code == 404


def test_rotating_secret_replaces_old_credentials(client, make_partner, token_for, admin_headers):
    partner = make_partner()
    old_headers = token_for(partner)
    r = client.post(f"/admin/partners/{partner['id']}/rotate-secret", headers=admin_headers)
    new_secret = r.get_json()["client_secret"]
    assert new_secret != partner["client_secret"]
    assert client.get("/results", headers=old_headers).status_code == 401
    assert get_token(client, partner).status_code == 401
    assert get_token(client, dict(partner, client_secret=new_secret)).status_code == 200


# ---------------------------------------------------------------- logging ---

def test_one_log_line_per_request_without_secrets(client, make_partner, capsys):
    partner = make_partner()
    capsys.readouterr()  # drop lines from setup
    get_token(client, partner)
    client.get("/health")
    client.get("/nope?client_secret=abc")
    lines = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
    assert [(l["method"], l["path"], l["status"]) for l in lines] == [
        ("POST", "/oauth/token", 200), ("GET", "/health", 200), ("GET", "/nope", 404)]
    assert lines[0]["actor"].startswith("partner:")
    out = json.dumps(lines)
    assert partner["client_secret"] not in out and "abc" not in out


# ------------------------------------------------------------ persistence ---

def test_data_survives_a_restart(db_path, tmp_path, app):
    app1 = create_app({"DATABASE_PATH": db_path})
    c1 = app1.test_client()
    admin = {"Authorization": "Bearer " + c1.post(
        "/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD}).get_json()["access_token"]}
    partner = c1.post("/admin/partners", headers=admin,
                      json={"name": "Persistent", "scopes": ["samples:write"]}).get_json()
    token = get_token(c1, partner).get_json()["access_token"]
    assert c1.post("/samples", headers={"Authorization": f"Bearer {token}"},
                   json={"sample_ref": "P-1"}).status_code == 201

    # "Restart": new app object on the same file; seeding again must not duplicate or reset anything.
    seed(db_path, str(tmp_path / "creds2.txt"), admin_password="a different password")
    app2 = create_app({"DATABASE_PATH": db_path})
    c2 = app2.test_client()
    assert not (tmp_path / "creds2.txt").exists()
    assert c2.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 200
    assert c2.post("/samples", headers={"Authorization": f"Bearer {token}"},
                   json={"sample_ref": "P-1"}).status_code == 409  # token and sample both survived


# ------------------------------------------------------------ sample users ---

def test_sample_users_exist_and_credentials_file_is_private(tmp_path):
    import os
    import stat
    db = str(tmp_path / "fresh.db")
    creds = tmp_path / "initial-credentials.txt"
    created = seed(db, str(creds))  # no password given: random
    assert created == ["admin:admin", "partner:Demo Lab"]
    assert stat.S_IMODE(os.stat(creds).st_mode) == 0o600
    values = dict(line.split(": ", 1) for line in creds.read_text().splitlines())

    c = create_app({"DATABASE_PATH": db}).test_client()
    login = c.post("/admin/login", json={"username": values["admin username"],
                                         "password": values["admin password"]})
    assert login.status_code == 200
    partner = {"client_id": values["demo partner client_id"],
               "client_secret": values["demo partner client_secret"]}
    token = get_token(c, partner).get_json()["access_token"]
    items = c.get("/results", headers={"Authorization": f"Bearer {token}"}).get_json()["items"]
    assert items and items[0]["state"] == "available"
