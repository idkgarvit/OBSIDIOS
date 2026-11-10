"""Tests for the operator audit trail (schema v4 + /api/v2/audit/log).

The audit trail answers "who changed what, when and from where". It must be
append-only, must never break the operation it records, and must be readable
only by operators.
"""
import json

import pytest

from dashboard.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key-for-auth-hardening-32+"
    with app.test_client() as c:
        yield c


def _auth(client):
    rv = client.post("/api/v2/login", json={"username": "admin", "password": "obsidios123"})
    assert rv.status_code == 200, rv.data[:200]
    return {"Authorization": f"Bearer {json.loads(rv.data)['token']}"}


class TestAuditWriter:
    def _capture(self, monkeypatch):
        import dashboard.app as dash
        captured = []

        def fake_execute(sql, params=()):
            captured.append((sql, params))

        monkeypatch.setattr(dash.db, "execute", fake_execute)
        # Avoid the 1-in-200 probabilistic retention delete making counts flaky.
        monkeypatch.setattr(dash.secrets, "randbelow", lambda n: 1)
        monkeypatch.delenv("OBSIDIOS_TRUST_PROXY", raising=False)
        return captured

    def test_records_actor_role_action_and_client_ip(self, monkeypatch):
        from flask import g

        import dashboard.app as dash

        captured = self._capture(monkeypatch)
        with dash.app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.1.2.3"}):
            g.user = "alice"
            g.role = "operator"
            dash._audit("TARGET_UPDATE", target="10.0.0.0/24", detail="profile=FAST")

        sql, params = captured[0]
        assert "INSERT INTO audit_log" in sql
        assert params == (
            "alice", "operator", "TARGET_UPDATE", "10.0.0.0/24",
            "profile=FAST", "10.1.2.3", "success",
        )

    def test_explicit_actor_is_used_for_pre_auth_events(self, monkeypatch):
        """Failed logins must be recorded even though no session exists yet."""
        from flask import g

        import dashboard.app as dash

        captured = self._capture(monkeypatch)
        with dash.app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.9.9.9"}):
            g.user = ""
            g.role = ""
            dash._audit("AUTH_LOGIN_FAILED", target="mallory",
                        outcome="failure", actor="mallory", role="")

        assert captured[0][1][:3] == ("mallory", "", "AUTH_LOGIN_FAILED")
        assert captured[0][1][5] == "10.9.9.9"
        assert captured[0][1][6] == "failure"

    def test_truncates_untrusted_fields(self, monkeypatch):
        from flask import g

        import dashboard.app as dash

        captured = self._capture(monkeypatch)
        with dash.app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.0.0.1"}):
            g.user = "op"
            g.role = "operator"
            dash._audit("X" * 200, target="T" * 500, detail="D" * 5000)

        _, params = captured[0]
        assert len(params[2]) == 64
        assert len(params[3]) == 256
        assert len(params[4]) == 2000

    def test_audit_failure_never_breaks_the_operation(self, monkeypatch):
        from flask import g

        import dashboard.app as dash

        def boom(*a, **k):
            raise RuntimeError("disk on fire")

        monkeypatch.setattr(dash.db, "execute", boom)
        with dash.app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.0.0.1"}):
            g.user = "op"
            g.role = "operator"
            # Must not raise: the audited operation already succeeded.
            dash._audit("SCAN_TRIGGER")

    def test_retention_prune_runs_occasionally(self, monkeypatch):
        from flask import g

        import dashboard.app as dash

        captured = self._capture(monkeypatch)
        monkeypatch.setattr(dash.secrets, "randbelow", lambda n: 0)
        with dash.app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.0.0.1"}):
            g.user = "op"
            g.role = "operator"
            dash._audit("SCAN_TRIGGER")

        assert any("DELETE FROM audit_log" in sql for sql, _ in captured)
        # The retention window is a real cutoff (~365 days ago), not "everything".
        import time as _time
        assert captured[1][1][0] < _time.time() - 300 * 86400


class TestAuditEventsAreRecorded:
    def test_login_success_and_failure_are_audited(self, client, monkeypatch):
        import dashboard.app as dash

        captured = []
        monkeypatch.setattr(dash.db, "execute",
                            lambda sql, params=(): captured.append((sql, params)))
        monkeypatch.setattr(dash.secrets, "randbelow", lambda n: 1)

        assert client.post("/api/v2/login", json={
            "username": "admin", "password": "obsidios123"}).status_code == 200
        assert client.post("/api/v2/login", json={
            "username": "admin", "password": "wrong"}).status_code == 401

        actions = [p[2] for sql, p in captured if "audit_log" in sql]
        assert actions == ["AUTH_LOGIN", "AUTH_LOGIN_FAILED"]

    def test_target_update_is_audited(self, client, monkeypatch):
        import dashboard.app as dash

        h = _auth(client)
        captured = []
        monkeypatch.setattr(dash.db, "execute",
                            lambda sql, params=(): captured.append((sql, params)))
        monkeypatch.setattr(dash.secrets, "randbelow", lambda n: 1)

        rv = client.post("/api/v2/config/target",
                         json={"target": "10.10.0.0/24", "profile": "FAST"},
                         headers=h)
        assert rv.status_code == 200

        entries = [p for sql, p in captured if "audit_log" in sql]
        assert len(entries) == 1
        assert entries[0][2] == "TARGET_UPDATE"
        assert entries[0][3] == "10.10.0.0/24"
        assert entries[0][0] == "admin"
        assert entries[0][1] == "operator"

    def test_report_export_is_audited(self, client, monkeypatch):
        import weasyprint

        import dashboard.app as dash

        h = _auth(client)
        monkeypatch.setattr(dash.db, "fetch_all", lambda *a, **k: [])
        monkeypatch.setattr(dash.db, "fetch_val", lambda *a, **k: 0)
        captured = []
        monkeypatch.setattr(dash.db, "execute",
                            lambda sql, params=(): captured.append((sql, params)))
        monkeypatch.setattr(dash.secrets, "randbelow", lambda n: 1)
        monkeypatch.setattr(
            weasyprint, "HTML",
            lambda **kw: type("FakeHTML", (), {
                "write_pdf": lambda self: b"%PDF-1.4 test"})(),
        )

        rv = client.post("/api/v2/export/pdf", headers=h)
        assert rv.status_code == 200, rv.data[:200]
        assert any("audit_log" in sql and "EXPORT_REPORT" in p
                   for sql, p in captured)


class TestAuditLogEndpoint:
    def test_requires_auth(self, client):
        assert client.get("/api/v2/audit/log").status_code == 401

    def test_viewer_is_forbidden(self, client, monkeypatch):
        monkeypatch.setenv("VIEWER_USER", "viewer")
        monkeypatch.setenv("VIEWER_PASS", "viewer-pass-123")
        rv = client.post("/api/v2/login",
                         json={"username": "viewer", "password": "viewer-pass-123"})
        vh = {"Authorization": f"Bearer {json.loads(rv.data)['token']}"}
        assert client.get("/api/v2/audit/log", headers=vh).status_code == 403

    def _fake_fetch_all(self, rows, captured):
        def fake(sql, params=()):
            if "DISTINCT action" in sql:
                return [{"action": "AUTH_LOGIN"}, {"action": "TARGET_UPDATE"}]
            captured.append((sql, params))
            return rows

        return fake

    def test_returns_rows_newest_first(self, client, monkeypatch):
        import dashboard.app as dash

        h = _auth(client)
        rows = [
            {"id": 2, "ts": 200.0, "actor": "admin", "role": "operator",
             "action": "TARGET_UPDATE", "target": "10.0.0.0/24",
             "detail": "profile=FAST", "ip": "127.0.0.1", "outcome": "success"},
            {"id": 1, "ts": 100.0, "actor": "admin", "role": "operator",
             "action": "AUTH_LOGIN", "target": "admin", "detail": "role=operator",
             "ip": "127.0.0.1", "outcome": "success"},
        ]
        captured = []
        monkeypatch.setattr(dash.db, "fetch_all",
                            self._fake_fetch_all(rows, captured))
        rv = client.get("/api/v2/audit/log", headers=h)
        assert rv.status_code == 200
        body = rv.get_json()
        assert [r["id"] for r in body["data"]] == [2, 1]
        assert body["count"] == 2
        assert "ORDER BY ts DESC" in captured[0][0]
        assert "actions" in body and "TARGET_UPDATE" in body["actions"]

    @pytest.mark.parametrize("raw,expected", [
        ("0", 200),      # falsy -> default
        ("-5", 1),       # clamp low
        ("99999", 500),  # clamp high
        ("bogus", 200),  # non-numeric -> default
    ])
    def test_limit_is_clamped(self, client, monkeypatch, raw, expected):
        import dashboard.app as dash

        h = _auth(client)
        captured = []
        monkeypatch.setattr(dash.db, "fetch_all",
                            self._fake_fetch_all([], captured))
        rv = client.get(f"/api/v2/audit/log?limit={raw}", headers=h)
        assert rv.status_code == 200
        assert captured[0][1][-1] == expected

    def test_action_and_actor_filters_are_parameterised(self, client, monkeypatch):
        import dashboard.app as dash

        h = _auth(client)
        captured = []
        monkeypatch.setattr(dash.db, "fetch_all",
                            self._fake_fetch_all([], captured))
        rv = client.get("/api/v2/audit/log?action=AUTH_LOGIN&actor=admin", headers=h)
        assert rv.status_code == 200
        sql, params = captured[0]
        assert "action = ?" in sql
        assert "actor = ?" in sql
        assert params == ("AUTH_LOGIN", "AUTH_LOGIN", "admin", "admin", 200)
        # The filter values must never be interpolated into the SQL text.
        assert "AUTH_LOGIN" not in sql
        assert "admin" not in sql


class TestSchemaV4:
    def test_schema_constant_bumps_to_current_version(self):
        from chronicle.schema import SCHEMA_SQL, SCHEMA_VERSION
        assert SCHEMA_VERSION >= 4
        assert "CREATE TABLE IF NOT EXISTS audit_log" in SCHEMA_SQL
        assert "idx_audit_ts" in SCHEMA_SQL
        assert "idx_audit_actor" in SCHEMA_SQL

    def test_forward_migration_creates_table_and_indexes(self, tmp_path):
        import asyncio

        import aiosqlite

        from chronicle.db import FORWARD_MIGRATIONS_SQL, _apply_forward_migrations

        assert any("audit_log" in sql for sql in FORWARD_MIGRATIONS_SQL)

        async def run():
            db_file = tmp_path / "v3.db"
            conn = await aiosqlite.connect(db_file)
            try:
                # Simulate a pre-v4 database (schema v3 had no audit_log).
                await conn.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY)")
                await conn.execute(
                    "CREATE TABLE forge_rules (id INTEGER PRIMARY KEY, rule_sid INTEGER)")
                await _apply_forward_migrations(conn)
                await conn.commit()

                cur = await conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
                )
                assert await cur.fetchone()

                cur = await conn.execute("PRAGMA table_info(audit_log)")
                cols = {row[1] for row in await cur.fetchall()}
                assert {
                    "id", "ts", "actor", "role", "action", "target",
                    "detail", "ip", "outcome",
                } <= cols

                cur = await conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' "
                    "AND name IN ('idx_audit_ts', 'idx_audit_actor')"
                )
                assert {row[0] for row in await cur.fetchall()} == {
                    "idx_audit_ts", "idx_audit_actor"}

                # Forward migrations are idempotent; init() replays them.
                await _apply_forward_migrations(conn)
                await conn.commit()
            finally:
                await conn.close()

        asyncio.run(run())
