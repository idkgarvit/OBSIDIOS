"""Tests for observability endpoints + schema versioning."""
import pytest

from dashboard.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key-32-chars-minimum-ok!"
    with app.test_client() as c:
        yield c


class TestProbes:
    def test_health_no_auth(self, client):
        rv = client.get("/api/health")
        assert rv.status_code == 200
        assert rv.get_json()["status"] == "ok"

    def test_readyz_no_auth(self, client):
        rv = client.get("/api/readyz")
        assert rv.status_code in (200, 503)
        assert "status" in rv.get_json()

    def test_metrics_requires_token(self, client, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_METRICS_PUBLIC", "0")
        monkeypatch.setenv("OBSIDIOS_METRICS_TOKEN", "metrics-test-token")
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers={
            "Authorization": "Bearer wrong-token"}).status_code == 401
        rv = client.get("/metrics", headers={
            "Authorization": "Bearer metrics-test-token"})
        assert rv.status_code in (200, 503)
        body = rv.data.decode()
        assert "obsidios_hosts_active" in body or body.startswith("# error")

    def test_metrics_public_opt_in(self, client, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_METRICS_PUBLIC", "1")
        rv = client.get("/metrics")
        assert rv.status_code in (200, 503)
        body = rv.data.decode()
        assert "obsidios_hosts_active" in body or body.startswith("# error")


class TestSchemaVersion:
    def test_version_constant(self):
        from chronicle.schema import SCHEMA_SQL, SCHEMA_VERSION
        assert SCHEMA_VERSION >= 1
        assert "schema_version" in SCHEMA_SQL

    def test_backup_module_present(self):
        import chronicle.backup as b
        assert callable(b.backup_db) and callable(b.restore_db)
