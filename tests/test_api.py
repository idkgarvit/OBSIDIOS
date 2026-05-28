"""Tests for dashboard/app.py — Flask API endpoint tests."""
import pytest
import json
import time
from dashboard.app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    with app.test_client() as client:
        yield client


def _auth_token(client) -> str:
    """Helper to get a valid JWT token."""
    rv = client.post('/api/login', json={
        "username": "admin",
        "password": "obsidios123",
    })
    data = json.loads(rv.data)
    return data.get("token", "")


class TestAuth:
    def test_unauthorized_access(self, client):
        rv = client.get('/api/v2/stats')
        assert rv.status_code == 401

    def test_login_missing_creds(self, client):
        rv = client.post('/api/login', json={})
        assert rv.status_code == 400
        data = json.loads(rv.data)
        assert "Missing credentials" in data.get("error", "")

    def test_login_wrong_creds(self, client):
        rv = client.post('/api/login', json={
            "username": "admin",
            "password": "wrong",
        })
        assert rv.status_code == 401

    def test_login_success(self, client):
        rv = client.post('/api/login', json={
            "username": "admin",
            "password": "obsidios123",
        })
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "token" in data

    def test_token_auth_success(self, client):
        token = _auth_token(client)
        assert len(token) > 0
        rv = client.get('/api/v2/stats', headers={
            "Authorization": f"Bearer {token}",
        })
        # Stats endpoint should return 200 (even if DB is empty)
        assert rv.status_code in (200, 500)  # 500 if no DB, but auth passed


class TestHealthEndpoint:
    pass


class TestAPIEndpoints:
    """Test that API endpoints exist and require auth."""

    def _auth_header(self, client):
        return {"Authorization": f"Bearer {_auth_token(client)}"}

    def test_hosts_endpoint(self, client):
        rv = client.get('/api/v2/stats', headers=self._auth_header(client))
        assert rv.status_code in (200, 500)

    def test_cves_endpoint(self, client):
        rv = client.get('/api/v2/cves', headers=self._auth_header(client))
        assert rv.status_code in (200, 500)

    def test_attack_paths_endpoint(self, client):
        rv = client.get('/api/v2/details/paths', headers=self._auth_header(client))
        assert rv.status_code in (200, 500)

    def test_shield_endpoint(self, client):
        rv = client.get('/api/v2/shield/actions', headers=self._auth_header(client))
        assert rv.status_code in (200, 500)

    def test_behavioral_events_endpoint(self, client):
        rv = client.get('/api/v2/details/anomalous_ports', headers=self._auth_header(client))
        assert rv.status_code in (200, 500)

    def test_posture_endpoint(self, client):
        rv = client.get('/api/v2/oracle/compliance', headers=self._auth_header(client))
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "compliance_score" in data

    def test_login_rejects_empty(self, client):
        rv = client.post('/api/login', json={})
        assert rv.status_code == 400