import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from partnerapi import clock, create_app  # noqa: E402
from partnerapi.seed import seed  # noqa: E402

ADMIN_PASSWORD = "correct horse battery staple"


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture
def app(db_path, tmp_path):
    seed(db_path, str(tmp_path / "creds.txt"), admin_password=ADMIN_PASSWORD)
    return create_app({"DATABASE_PATH": db_path, "TESTING": True})


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def fake_clock(monkeypatch):
    """Movable clock: fake_clock.advance(seconds)."""
    class Clock:
        t = clock.now()

        def advance(self, seconds):
            self.t += seconds

    c = Clock()
    monkeypatch.setattr(clock, "now", lambda: c.t)
    return c


@pytest.fixture
def admin_headers(client):
    r = client.post("/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.get_json()['access_token']}"}


@pytest.fixture
def make_partner(client, admin_headers):
    counter = iter(range(1000))

    def _make(scopes=("samples:write", "results:read"), name=None):
        r = client.post("/admin/partners", headers=admin_headers,
                        json={"name": name or f"Lab {next(counter)}", "scopes": list(scopes)})
        assert r.status_code == 201, r.get_json()
        return r.get_json()

    return _make


def get_token(client, partner, scope=None):
    body = {"grant_type": "client_credentials", "client_id": partner["client_id"],
            "client_secret": partner["client_secret"]}
    if scope:
        body["scope"] = scope
    return client.post("/oauth/token", data=body)


@pytest.fixture
def token_for(client):
    def _token(partner, scope=None):
        r = get_token(client, partner, scope)
        assert r.status_code == 200, r.get_json()
        return {"Authorization": f"Bearer {r.get_json()['access_token']}"}
    return _token


@pytest.fixture
def stdout_buffer():
    return io.StringIO()
