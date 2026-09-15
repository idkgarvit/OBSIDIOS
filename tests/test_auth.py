"""Tests for hardened auth: short-lived access, refresh rotation, logout, RBAC."""
import json
import os
import pytest

from dashboard import app as appmod
from dashboard.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key-for-auth-hardening-32+"
    with app.test_client() as c:
        yield c


def _login(client, user="admin", pw="obsidios123"):
    rv = client.post("/api/v2/login", json={"username": user, "password": pw})
    assert rv.status_code == 200, rv.data[:200]
    return json.loads(rv.data)


class TestV2Login:
    def test_returns_access_and_refresh(self, client):
        data = _login(client)
        assert "token" in data and "refresh_token" in data
        assert data["expires_in"] == 900
        assert data["role"] == "operator"

    def test_legacy_login_compat(self, client):
        rv = client.post("/api/login", json={"username": "admin", "password": "obsidios123"})
        assert rv.status_code == 200
        assert "token" in json.loads(rv.data)

    def test_wrong_creds(self, client):
        rv = client.post("/api/v2/login", json={"username": "admin", "password": "nope"})
        assert rv.status_code == 401


class TestRefreshLogout:
    def test_refresh_rotates(self, client):
        data = _login(client)
        rv = client.post("/api/v2/refresh", json={"refresh_token": data["refresh_token"]})
        assert rv.status_code == 200
        data2 = json.loads(rv.data)
        assert data2["token"] != data["token"]
        # old refresh must be revoked (rotation)
        rv2 = client.post("/api/v2/refresh", json={"refresh_token": data["refresh_token"]})
        assert rv2.status_code == 401

    def test_refresh_rejects_access_token(self, client):
        data = _login(client)
        rv = client.post("/api/v2/refresh", json={"refresh_token": data["token"]})
        assert rv.status_code == 401

    def test_logout_revokes(self, client):
        data = _login(client)
        h = {"Authorization": f"Bearer {data['token']}"}
        rv = client.post("/api/v2/logout", headers=h, json={})
        assert rv.status_code == 200
        rv2 = client.get("/api/v2/stats", headers=h)
        assert rv2.status_code == 401


class TestRBAC:
    def test_viewer_cannot_deploy(self, client, monkeypatch):
        monkeypatch.setenv("VIEWER_USER", "viewer")
        monkeypatch.setenv("VIEWER_PASS", "viewer-pass-123")
        rv = client.post("/api/v2/login", json={"username": "viewer", "password": "viewer-pass-123"})
        assert rv.status_code == 200
        vtok = json.loads(rv.data)["token"]
        vh = {"Authorization": f"Bearer {vtok}"}
        # read OK
        assert client.get("/api/v2/forge/suggestions", headers=vh).status_code in (200, 500)
        # mutate blocked
        assert client.post("/api/v2/forge/deploy/1", headers=vh).status_code == 403
        assert client.post("/api/v2/shield/revert/1", headers=vh).status_code == 403
        rv3 = client.post("/api/v2/forge/feedback", headers=vh,
                          json={"rule_id": 1, "verdict": "tp", "auto_apply": True})
        assert rv3.status_code == 403

    def test_operator_can_deploy_route_exists(self, client):
        data = _login(client)
        h = {"Authorization": f"Bearer {data['token']}"}
        rv = client.post("/api/v2/forge/deploy/999999", headers=h)
        # 404 = passed RBAC, rule missing; 403 would mean RBAC mis-wired
        assert rv.status_code in (404, 500)


class TestProdGuards:
    def test_prod_rejects_default_pass(self, monkeypatch):
        from config.settings import validate_prod_config
        monkeypatch.setenv("OBSIDIOS_ENV", "production")
        monkeypatch.setenv("OBSIDIOS_SECRET", "x" * 48)
        monkeypatch.setenv("DASHBOARD_PASS", "obsidios123")
        monkeypatch.setenv("OBSIDIOS_TARGET", "192.168.10.0/24")
        errs = validate_prod_config()
        assert any("DASHBOARD_PASS" in e for e in errs)

    def test_check_auth_fails_closed_in_prod(self, monkeypatch):
        from dashboard.app import check_auth
        monkeypatch.setenv("OBSIDIOS_ENV", "production")
        monkeypatch.setenv("DASHBOARD_USER", "admin")
        monkeypatch.setenv("DASHBOARD_PASS", "obsidios123")
        assert check_auth("admin", "obsidios123") is None
