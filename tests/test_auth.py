"""Tests for hardened auth: short-lived access, refresh rotation, logout, RBAC."""
import json
import time

import pytest

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
    def test_returns_access_token_and_refresh_cookie(self, client):
        rv = client.post("/api/v2/login", json={"username": "admin", "password": "obsidios123"})
        assert rv.status_code == 200
        data = json.loads(rv.data)
        assert "token" in data
        assert "refresh_token" not in data   # refresh token must never be readable by JS
        assert data["expires_in"] == 900
        assert data["role"] == "operator"
        cookies = rv.headers.getlist("Set-Cookie")
        assert any(
            "obsidios_refresh=" in c and "HttpOnly" in c and "SameSite=Strict" in c
            for c in cookies
        ), cookies

    def test_legacy_login_compat(self, client):
        rv = client.post("/api/login", json={"username": "admin", "password": "obsidios123"})
        assert rv.status_code == 200
        assert "token" in json.loads(rv.data)

    def test_wrong_creds(self, client):
        rv = client.post("/api/v2/login", json={"username": "admin", "password": "nope"})
        assert rv.status_code == 401


class TestRefreshLogout:
    def test_refresh_rotates(self, client):
        _login(client)
        old = client.get_cookie("obsidios_refresh", path="/api/v2").value
        rv = client.post("/api/v2/refresh", json={})
        assert rv.status_code == 200
        new = client.get_cookie("obsidios_refresh", path="/api/v2").value
        assert new != old
        # old refresh must be revoked (rotation) — replay it explicitly
        client.delete_cookie("obsidios_refresh", path="/api/v2")
        client.set_cookie("obsidios_refresh", old, path="/api/v2")
        rv2 = client.post("/api/v2/refresh", json={})
        assert rv2.status_code == 401

    def test_single_use_refresh_token_cannot_be_consumed_twice(self):
        """Two racing refreshes must not both mint sessions."""
        from dashboard import app as dash

        exp = __import__("time").time() + 60
        first = dash._consume_jti("race-jti", exp)
        second = dash._consume_jti("race-jti", exp)
        assert first is True
        assert second is False
        with dash._REVOKED_LOCK:
            dash._REVOKED_JTIS.pop("race-jti", None)

    def test_refresh_token_replay_is_rejected(self, client):
        _login(client)
        old = client.get_cookie("obsidios_refresh", path="/api/v2").value
        assert client.post("/api/v2/refresh", json={}).status_code == 200

        client.delete_cookie("obsidios_refresh", path="/api/v2")
        client.set_cookie("obsidios_refresh", old, path="/api/v2")
        rv = client.post("/api/v2/refresh", json={})
        assert rv.status_code == 401
        assert "already used" in rv.get_data(as_text=True) or "invalid" in rv.get_data(as_text=True).lower()

    def test_refresh_rejects_access_token(self, client):
        data = _login(client)
        client.delete_cookie("obsidios_refresh", path="/api/v2")
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


class TestClientIp:
    def test_proxy_header_uses_rightmost_entry(self, monkeypatch):
        from dashboard.app import _client_ip
        monkeypatch.setenv("OBSIDIOS_TRUST_PROXY", "1")
        with app.test_request_context(
            "/", headers={"X-Forwarded-For": "1.2.3.4, 203.0.113.9"}
        ):
            assert _client_ip() == "203.0.113.9"

    def test_proxy_header_ignored_by_default(self, monkeypatch):
        from dashboard.app import _client_ip
        monkeypatch.delenv("OBSIDIOS_TRUST_PROXY", raising=False)
        with app.test_request_context(
            "/", headers={"X-Forwarded-For": "203.0.113.9"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        ):
            assert _client_ip() == "127.0.0.1"


class TestShieldRevertFailClosed:
    def test_missing_action_returns_404(self, client, monkeypatch):
        data = _login(client)
        h = {"Authorization": f"Bearer {data['token']}"}
        monkeypatch.setattr("dashboard.app.db.fetch_one", lambda *a, **k: None)
        rv = client.post("/api/v2/shield/revert/999999", headers=h)
        assert rv.status_code == 404

    def test_failed_rollback_keeps_row_active(self, client, monkeypatch):
        data = _login(client)
        h = {"Authorization": f"Bearer {data['token']}"}
        monkeypatch.setattr("dashboard.app.db.fetch_one", lambda *a, **k: {"id": 1})
        calls = []

        def fake_run_async(coro, timeout=120.0):
            coro.close()  # avoid an un-awaited coroutine warning
            return False

        monkeypatch.setattr("dashboard.app.run_async", fake_run_async)
        monkeypatch.setattr("dashboard.app.db.execute", lambda *a, **k: calls.append(a))
        rv = client.post("/api/v2/shield/revert/1", headers=h)
        assert rv.status_code == 500
        # The DB row must not be marked inactive; only the audit trail is written.
        assert not [c for c in calls if "shield_actions" in c[0]]
        assert any("audit_log" in c[0] and "SHIELD_REVERT" in c[1] for c in calls)


class TestPortStateFilter:
    def test_filtered_state_is_queryable(self, client, monkeypatch):
        data = _login(client)
        h = {"Authorization": f"Bearer {data['token']}"}
        captured = {}

        def fake_fetch_all(sql, params=()):
            captured["sql"] = sql
            captured["params"] = params
            return []

        monkeypatch.setattr("dashboard.app.db.fetch_all", fake_fetch_all)
        rv = client.get("/api/v2/details/ports?state=filtered", headers=h)
        assert rv.status_code == 200
        assert "p.state = ?" in captured["sql"]
        assert captured["params"] == ("filtered",)

        rv = client.get("/api/v2/details/ports?state=bogus", headers=h)
        assert rv.status_code == 400


class TestOperationalContext:
    def test_requires_auth(self, client):
        assert client.get("/api/v2/context").status_code == 401

    def test_returns_banner_and_identity_fields(self, client, monkeypatch):
        data = _login(client)
        h = {"Authorization": f"Bearer {data['token']}"}

        def fake_fetch_val(sql, params=(), default=None):
            if "target_network" in sql:
                return "10.0.0.0/24"
            if "scan_profile" in sql:
                return "DEEP"
            if "scanner_enabled" in sql:
                return "1"
            if "status='RUNNING'" in sql:
                return 1
            if "sentinel_alerts" in sql:
                return 4
            if "shield_actions" in sql:
                return 2
            return default

        monkeypatch.setattr("dashboard.app.db.fetch_val", fake_fetch_val)
        monkeypatch.setattr(
            "dashboard.app._actionable_unacked_alerts_sync",
            lambda: [{}, {}, {}, {}],
        )
        monkeypatch.setattr(
            "dashboard.app.db.fetch_one",
            lambda *a, **k: {
                "scan_type": "NMAP", "started_at": 1.0,
                "finished_at": 2.0, "status": "DONE",
            },
        )
        rv = client.get("/api/v2/context", headers=h)
        assert rv.status_code == 200
        d = json.loads(rv.data)
        assert d["target"] == "10.0.0.0/24"
        assert d["profile"] == "DEEP"
        assert d["scanner_enabled"] is True
        assert d["is_scanning"] is True
        assert d["unacknowledged_alerts"] == 4
        assert d["active_blocks"] == 2
        assert d["last_scan"]["status"] == "DONE"
        assert d["user"] == "admin"
        assert d["role"] == "operator"
        assert isinstance(d["shield_dry_run"], bool)
        assert isinstance(d["shield_auto_quarantine"], bool)
        assert d["server_time"] > 0


class TestSentinelAck:
    def test_ack_requires_auth(self, client):
        assert client.post("/api/v2/sentinel/alerts/1/ack").status_code == 401
        assert client.post("/api/v2/sentinel/alerts/ack_all").status_code == 401

    def test_viewer_cannot_ack(self, client, monkeypatch):
        monkeypatch.setenv("VIEWER_USER", "viewer")
        monkeypatch.setenv("VIEWER_PASS", "viewer-pass-123")
        rv = client.post(
            "/api/v2/login",
            json={"username": "viewer", "password": "viewer-pass-123"},
        )
        assert rv.status_code == 200
        vh = {"Authorization": f"Bearer {json.loads(rv.data)['token']}"}
        assert client.post("/api/v2/sentinel/alerts/1/ack", headers=vh).status_code == 403
        assert client.post("/api/v2/sentinel/alerts/ack_all", headers=vh).status_code == 403

    def test_single_ack_missing_alert_returns_404(self, client, monkeypatch):
        data = _login(client)
        h = {"Authorization": f"Bearer {data['token']}"}
        monkeypatch.setattr("dashboard.app.db.fetch_one", lambda *a, **k: None)
        rv = client.post("/api/v2/sentinel/alerts/999999/ack", headers=h)
        assert rv.status_code == 404

    def test_single_ack_updates_only_that_row(self, client, monkeypatch):
        data = _login(client)
        h = {"Authorization": f"Bearer {data['token']}"}
        monkeypatch.setattr("dashboard.app.db.fetch_one", lambda *a, **k: {"id": 7})
        captured = []
        monkeypatch.setattr(
            "dashboard.app.db.execute",
            lambda sql, params=(): captured.append((sql, params)),
        )
        rv = client.post("/api/v2/sentinel/alerts/7/ack", headers=h)
        assert rv.status_code == 200
        updates = [c for c in captured if "sentinel_alerts" in c[0]]
        assert len(updates) == 1
        assert "acknowledged=1" in updates[0][0]
        assert updates[0][1] == (7,)
        # The ack is also recorded in the operator audit trail.
        assert any("audit_log" in c[0] and "SENTINEL_ACK" in c[1] for c in captured)

    def test_ack_all_updates_unacknowledged(self, client, monkeypatch):
        data = _login(client)
        h = {"Authorization": f"Bearer {data['token']}"}
        captured = []
        monkeypatch.setattr(
            "dashboard.app.db.execute",
            lambda sql, params=(): captured.append((sql, params)),
        )
        rv = client.post("/api/v2/sentinel/alerts/ack_all", headers=h)
        assert rv.status_code == 200
        updates = [c for c in captured if "sentinel_alerts" in c[0]]
        assert len(updates) == 1
        assert "SET acknowledged=1" in updates[0][0]
        assert "acknowledged=0" in updates[0][0]
        assert any("audit_log" in c[0] and "SENTINEL_ACK_ALL" in c[1] for c in captured)


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


class TestMutationRbacMatrix:
    """Every mutating route must deny a viewer, now and in the future.

    Enumerating the URL map means a new POST endpoint cannot ship without an
    operator guard: the test fails without anyone remembering to add a case.
    """

    # Login/refresh are how a viewer becomes authenticated at all; logout must
    # work for every role so a shared workstation can always be cleared.
    PUBLIC = {"/api/login", "/api/v2/login", "/api/v2/refresh", "/api/v2/logout"}
    # POST only because it carries a JSON body; generating a report does not
    # change state, so viewers are allowed to download one.
    READ_ONLY_POST = {"/api/v2/export/pdf"}
    CONVERTERS = ("<int:aid>", "<int:port_id>", "<int:cve_id>", "<int:rid>", "<int:tid>")

    @staticmethod
    def _viewer(client, monkeypatch):
        monkeypatch.setenv("VIEWER_USER", "viewer")
        monkeypatch.setenv("VIEWER_PASS", "V1ewer!-obsidios-2026")
        rv = client.post(
            "/api/v2/login",
            json={"username": "viewer", "password": "V1ewer!-obsidios-2026"},
        )
        assert rv.status_code == 200, rv.data[:200]
        return {"Authorization": f"Bearer {json.loads(rv.data)['token']}"}

    def _routes(self):
        from dashboard.app import app

        rules = set()
        for rule in app.url_map.iter_rules():
            if not (rule.methods & {"POST", "PUT", "DELETE", "PATCH"}):
                continue
            path = rule.rule
            for conv in self.CONVERTERS:
                path = path.replace(conv, "1")
            if path not in self.PUBLIC:
                rules.add(path)
        return sorted(rules)

    def test_enumeration_finds_the_known_mutations(self):
        routes = self._routes()
        assert "/api/v2/forge/rewrite" in routes
        assert "/api/v2/shield/revert/1" in routes
        assert len(routes) >= 15

    def test_viewer_is_denied_every_mutation(self, client, monkeypatch):
        headers = self._viewer(client, monkeypatch)
        denied = []
        for path in self._routes():
            if path in self.READ_ONLY_POST:
                continue
            rv = client.post(path, json={}, headers=headers)
            if rv.status_code < 400:
                denied.append((path, rv.status_code))
        assert denied == [], f"viewer was allowed to mutate: {denied}"

    def test_operator_is_not_role_denied(self, client, monkeypatch):
        data = _login(client)
        headers = {"Authorization": f"Bearer {data['token']}"}

        # This test is about the RBAC gate, not the work behind it: stub every
        # real side effect so it cannot rewrite the ruleset, probe the network
        # or touch the repository while asserting the role check.
        async def noop_async(*_args, **_kwargs):
            return 0

        class FakeDelivery:
            ok = True
            rule_count = 0
            error = None
            state = "EMPTY"

            def as_dict(self):
                return {"ok": True, "rule_count": 0}

        async def fake_write_rules():
            return FakeDelivery()

        monkeypatch.setattr("dashboard.app.db.execute", lambda *a, **k: None)
        monkeypatch.setattr("dashboard.app.socketio.emit", lambda *a, **k: None)
        monkeypatch.setattr("iris.cve_mapper.verify_all_cves", noop_async)
        monkeypatch.setattr("iris.wired_scanner.run_wireless_scan", noop_async)
        monkeypatch.setattr("forge.rule_generator.write_rules_file", fake_write_rules)

        blocked = []
        for path in self._routes():
            rv = client.post(path, json={}, headers=headers)
            if rv.status_code in (401, 403):
                blocked.append((path, rv.status_code))
        assert blocked == [], f"operator was role-denied: {blocked}"


class TestRevokedTokenRehydration:
    def test_one_malformed_row_does_not_drop_valid_tokens(self, monkeypatch):
        """A revoked token must stay revoked across a restart."""
        import dashboard.app as dash

        class Cursor:
            def __init__(self, rows):
                self._rows = rows

            def fetchall(self):
                return self._rows

        class Conn:
            def __init__(self):
                self.closed = False

            def execute(self, sql, params=()):
                if "SELECT" in sql:
                    return Cursor([
                        {"jti": "valid-jti", "expires_at": time.time() + 600},
                        {"jti": "bad-exp", "expires_at": "not-a-number"},
                        {"jti": None, "expires_at": 123},
                    ])
                return Cursor([])

            def commit(self):
                pass

            def close(self):
                self.closed = True

        conn = Conn()
        monkeypatch.setattr(dash.db, "get_db_conn", lambda: conn)
        dash._REVOKED_JTIS.pop("valid-jti", None)
        try:
            dash._load_revoked_tokens()
            assert "valid-jti" in dash._REVOKED_JTIS
            assert "bad-exp" not in dash._REVOKED_JTIS
        finally:
            dash._REVOKED_JTIS.pop("valid-jti", None)

        assert conn.closed is True
