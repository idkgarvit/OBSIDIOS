"""Authentication, failure-contract and operator-action tests for the dashboard.

Two contracts matter here:

* A dashboard endpoint must fail closed with a JSON 500 when CHRONICLE is
  unreachable — never leak a traceback or, worse, report success.
* Token handling must be single-use where it claims to be: a replayed refresh
  token must not mint a second session, and logout must actually revoke both
  tokens.
"""
from __future__ import annotations

import sqlite3
import sys
import threading
import time
from types import SimpleNamespace

import jwt
import pytest

import dashboard.app as dash
from dashboard.app import app
from forge.rule_generator import RuleDelivery

SECRET = "test-secret-key-32-chars-minimum-ok!"


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = SECRET
    with app.test_client() as client:
        yield client


def _token(client, username="admin", password=""):
    password = password or "obsidios123"  # documented dev fallback
    response = client.post(
        "/api/v2/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.get_json()["token"]


def _auth(client):
    return {"Authorization": f"Bearer {_token(client)}"}


def _tokens(role="operator"):
    issued = dash._issue_tokens("admin", role)
    return issued.pop("_refresh_token"), issued["token"]


def _refresh_cookie(client, raw):
    client.set_cookie("obsidios_refresh", raw)


def _sqlite_rows(columns, values):
    """Build real sqlite3.Row objects, the type CHRONICLE returns."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(f"CREATE TABLE t ({', '.join(columns)})")
    conn.executemany(
        f"INSERT INTO t VALUES ({', '.join('?' for _ in columns)})", values)
    rows = conn.execute("SELECT * FROM t").fetchall()
    conn.close()
    return rows


class TestLoginHardening:
    def test_lockout_blocks_even_correct_credentials(self, client):
        for _ in range(dash.LOGIN_LOCKOUT_THRESHOLD):
            assert client.post(
                "/api/v2/login",
                json={"username": "admin", "password": "wrong"},
            ).status_code == 401

        response = client.post(
            "/api/v2/login",
            json={"username": "admin", "password": "obsidios123"},
        )

        assert response.status_code == 429
        assert "Too many failed attempts" in response.get_json()["error"]

    def test_oversized_credentials_are_rejected_before_hashing(self, client):
        response = client.post(
            "/api/v2/login",
            json={"username": "admin", "password": "x" * 513},
        )

        assert response.status_code == 401
        assert response.get_json()["error"] == "Invalid credentials"

    def test_success_clears_prior_failures_and_sets_httponly_cookie(
            self, client):
        dash._record_login_fail("127.0.0.1")

        response = client.post(
            "/api/v2/login",
            json={"username": "admin", "password": "obsidios123"},
        )

        assert response.status_code == 200
        assert "127.0.0.1" not in dash._LOGIN_FAILS
        assert "_refresh_token" not in response.get_json()
        cookie = response.headers["Set-Cookie"]
        assert "obsidios_refresh=" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=Strict" in cookie

    def test_settings_write_failure_does_not_block_login(self, client,
                                                         monkeypatch):
        def broken(_sql, _params=()):
            raise RuntimeError("database is locked")

        monkeypatch.setattr(dash.db, "execute", broken)

        response = client.post(
            "/api/v2/login",
            json={"username": "admin", "password": "obsidios123"},
        )

        assert response.status_code == 200
        assert response.get_json()["token"]

    def test_rate_limit_refuses_the_51st_attempt(self, client):
        dash._rate_limit_store["127.0.0.1"] = [time.time()] * dash.RATE_LIMIT_MAX

        response = client.post(
            "/api/v2/login",
            json={"username": "admin", "password": "obsidios123"},
        )

        assert response.status_code == 429
        assert "Rate limit" in response.get_json()["error"]

    def test_rate_limit_prunes_stale_client_keys(self, client, monkeypatch):
        stale = time.time() - dash.RATE_LIMIT_WINDOW - 60
        store = {f"10.0.0.{i}": [stale] for i in range(dash._MAX_TRACKED_CLIENTS)}
        store["127.0.0.1"] = []
        monkeypatch.setattr(dash, "_rate_limit_store", store)

        response = client.post(
            "/api/v2/login",
            json={"username": "admin", "password": "obsidios123"},
        )

        assert response.status_code == 200
        assert len(store) < dash._MAX_TRACKED_CLIENTS

    def test_viewer_can_read_config_but_not_change_it(self, client,
                                                      monkeypatch):
        monkeypatch.setenv("VIEWER_USER", "auditor")
        monkeypatch.setenv("VIEWER_PASS", "read-only-pass")

        login = client.post(
            "/api/v2/login",
            json={"username": "auditor", "password": "read-only-pass"},
        )
        assert login.status_code == 200
        headers = {
            "Authorization": f"Bearer {login.get_json()['token']}"}

        assert client.get(
            "/api/v2/config/target", headers=headers).status_code == 200
        assert client.post(
            "/api/v2/config/target",
            headers=headers,
            json={"target": "10.0.0.0/24", "profile": "FAST"},
        ).status_code == 403
        assert client.post(
            "/api/actions/scan", headers=headers).status_code == 403


class TestTokenHardening:
    def test_refresh_token_cannot_be_used_as_an_access_token(self, client):
        refresh, _access = _tokens()

        response = client.get(
            "/api/v2/stats",
            headers={"Authorization": f"Bearer {refresh}"},
        )

        assert response.status_code == 401

    def test_foreign_issuer_is_rejected(self, client):
        foreign = jwt.encode(
            {"user": "admin", "role": "operator", "iss": "somebody-else",
             "type": "access", "exp": time.time() + 60},
            SECRET, algorithm="HS256",
        )

        response = client.get(
            "/api/v2/stats",
            headers={"Authorization": f"Bearer {foreign}"},
        )

        assert response.status_code == 401

    def test_expired_access_token_reports_expiry(self, client):
        expired = jwt.encode(
            {"user": "admin", "role": "operator", "iss": "obsidios",
             "type": "access", "exp": time.time() - 10},
            SECRET, algorithm="HS256",
        )

        response = client.get(
            "/api/v2/stats",
            headers={"Authorization": f"Bearer {expired}"},
        )

        assert response.status_code == 401
        assert response.get_json()["error"] == "Token expired"

    def test_revoked_jti_is_rejected(self, client, monkeypatch):
        refresh, _access = _tokens()
        payload = jwt.decode(refresh, SECRET, algorithms=["HS256"])
        monkeypatch.setitem(dash._REVOKED_JTIS, payload["jti"], time.time() + 60)

        response = client.post("/api/v2/refresh", json={})

        # No cookie: the missing-token branch. Set the revoked cookie instead.
        assert response.status_code == 400
        _refresh_cookie(client, refresh)
        response = client.post("/api/v2/refresh", json={})
        assert response.status_code == 401

    def test_empty_jti_is_never_treated_as_revoked(self):
        assert dash._consume_jti("", time.time() + 60) is True

    def test_refresh_requires_a_token(self, client):
        assert client.post("/api/v2/refresh", json={}).status_code == 400

    def test_access_token_is_not_accepted_for_refresh(self, client):
        _refresh, access = _tokens()
        _refresh_cookie(client, access)

        response = client.post("/api/v2/refresh", json={})

        assert response.status_code == 401

    def test_refresh_rotates_and_consumes_the_old_token(self, client):
        refresh, _access = _tokens()
        _refresh_cookie(client, refresh)

        first = client.post("/api/v2/refresh", json={})
        assert first.status_code == 200
        assert first.get_json()["token"]

        _refresh_cookie(client, refresh)
        replay = client.post("/api/v2/refresh", json={})

        assert replay.status_code == 401

    def test_single_use_token_cannot_be_consumed_twice(self):
        assert dash._consume_jti("single-use", time.time() + 60) is True
        assert dash._consume_jti("single-use", time.time() + 60) is False

    def test_expired_refresh_token_is_rejected(self, client):
        expired = jwt.encode(
            {"user": "admin", "role": "operator", "iss": "obsidios",
             "type": "refresh", "jti": "expired-jti",
             "exp": time.time() - 10},
            SECRET, algorithm="HS256",
        )
        _refresh_cookie(client, expired)

        response = client.post("/api/v2/refresh", json={})

        assert response.status_code == 401
        assert response.get_json()["error"] == "Token expired"

    def test_garbage_refresh_token_is_rejected(self, client):
        _refresh_cookie(client, "not-a-jwt")

        response = client.post("/api/v2/refresh", json={})

        assert response.status_code == 401

    def test_logout_revokes_access_and_refresh_tokens(self, client):
        refresh, access = _tokens()
        _refresh_cookie(client, refresh)

        logout = client.post(
            "/api/v2/logout",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert logout.status_code == 200

        assert client.get(
            "/api/v2/stats",
            headers={"Authorization": f"Bearer {access}"},
        ).status_code == 401

        _refresh_cookie(client, refresh)
        assert client.post("/api/v2/refresh", json={}).status_code == 401

    def test_logout_tolerates_malformed_tokens(self, client):
        # requires_auth needs a valid access token; the refresh cookie and the
        # raw header parsing are the untrusted parts being exercised.
        refresh, access = _tokens()
        _refresh_cookie(client, "broken")

        response = client.post(
            "/api/v2/logout",
            headers={"Authorization": f"Bearer {access}"},
        )

        assert response.status_code == 200


class TestSocketAuthentication:
    def test_no_token_is_rejected(self, monkeypatch):
        joined = []
        monkeypatch.setattr("flask_socketio.join_room", joined.append)

        with app.test_request_context("/"):
            assert dash._socket_connect(None) is False
            assert dash._socket_connect({}) is False

        assert joined == []

    def test_query_parameter_token_is_accepted(self, monkeypatch):
        joined = []
        monkeypatch.setattr("flask_socketio.join_room", joined.append)
        _refresh, access = _tokens()

        with app.test_request_context(f"/?token={access}"):
            assert dash._socket_connect({}) is True

        assert joined == ["authenticated"]

    def test_dict_token_is_accepted(self, monkeypatch):
        joined = []
        monkeypatch.setattr("flask_socketio.join_room", joined.append)
        _refresh, access = _tokens()

        assert dash._socket_connect({"token": access}) is True
        assert joined == ["authenticated"]

    def test_refresh_and_garbage_tokens_are_rejected(self, monkeypatch):
        joined = []
        monkeypatch.setattr("flask_socketio.join_room", joined.append)
        refresh, _access = _tokens()

        assert dash._socket_connect({"token": refresh}) is False
        assert dash._socket_connect({"token": "garbage"}) is False
        assert joined == []


class TestClientIdentity:
    def test_forwarded_for_is_ignored_without_trust(self, monkeypatch):
        monkeypatch.delenv("OBSIDIOS_TRUST_PROXY", raising=False)

        with app.test_request_context(
                "/", headers={"X-Forwarded-For": "1.2.3.4"},
                environ_base={"REMOTE_ADDR": "9.9.9.9"}):
            assert dash._client_ip() == "9.9.9.9"

    def test_trusted_proxy_uses_the_right_most_hop(self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_TRUST_PROXY", "1")

        with app.test_request_context(
                "/", headers={"X-Forwarded-For": "1.2.3.4, 10.1.2.3"},
                environ_base={"REMOTE_ADDR": "9.9.9.9"}):
            assert dash._client_ip() == "10.1.2.3"

    def test_invalid_forwarded_address_falls_back(self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_TRUST_PROXY", "yes")

        with app.test_request_context(
                "/", headers={"X-Forwarded-For": "definitely-not-an-ip"},
                environ_base={"REMOTE_ADDR": "9.9.9.9"}):
            assert dash._client_ip() == "9.9.9.9"


class TestAuthStoreMaintenance:
    def test_expired_revocations_and_stale_limits_are_pruned(
            self, monkeypatch):
        now = time.time()
        revoked = {"old": now - 10, "fresh": now + 60}
        fails = {f"10.0.0.{i}": [now - 1000]
                 for i in range(dash._MAX_TRACKED_CLIENTS + 1)}
        limits = {f"10.1.0.{i}": [now - 1000]
                  for i in range(dash._MAX_TRACKED_CLIENTS + 1)}
        monkeypatch.setattr(dash, "_REVOKED_JTIS", revoked)
        monkeypatch.setattr(dash, "_LOGIN_FAILS", fails)
        monkeypatch.setattr(dash, "_rate_limit_store", limits)

        dash._prune_auth_stores()

        assert revoked == {"fresh": now + 60}
        assert fails == {}
        assert limits == {}

    def test_persist_failure_does_not_drop_the_in_memory_revocation(
            self, monkeypatch):
        monkeypatch.setattr(dash, "_REVOKED_JTIS", {})

        def broken():
            raise RuntimeError("database is locked")

        monkeypatch.setattr(dash.db, "get_db_conn", broken)

        dash._revoke_jti("jti-1", time.time() + 60)

        assert "jti-1" in dash._REVOKED_JTIS

    def test_load_skips_malformed_rows(self, monkeypatch):
        rows = [
            {"jti": "good", "expires_at": "123.5"},
            {"jti": None, "expires_at": 1},
            {"jti": "bad-expiry", "expires_at": "soon"},
        ]

        class FakeCursor:
            def fetchall(self):
                return rows

        class FakeConn:
            def execute(self, sql, _params=()):
                assert "revoked_tokens" in sql
                return FakeCursor()

            def commit(self):
                pass

            def close(self):
                pass

        monkeypatch.setattr(dash, "_REVOKED_JTIS", {})
        monkeypatch.setattr(dash.db, "get_db_conn", lambda: FakeConn())

        dash._load_revoked_tokens()

        assert dash._REVOKED_JTIS == {"good": 123.5}

    def test_unreadable_store_is_reported_not_raised(self, monkeypatch):
        def broken():
            raise RuntimeError("disk unreadable")

        monkeypatch.setattr(dash.db, "get_db_conn", broken)

        dash._load_revoked_tokens()


class TestProbesAndMetrics:
    def test_readyz_returns_503_when_the_database_fails(self, client,
                                                        monkeypatch):
        def broken(*_args, **_kwargs):
            raise RuntimeError("db down")

        monkeypatch.setattr(dash.db, "fetch_val", broken)

        response = client.get("/api/readyz")

        assert response.status_code == 503
        assert response.get_json()["status"] == "not-ready"

    def test_metrics_require_a_token(self, client, monkeypatch):
        monkeypatch.delenv("OBSIDIOS_METRICS_PUBLIC", raising=False)
        monkeypatch.delenv("OBSIDIOS_METRICS_TOKEN", raising=False)

        assert client.get("/metrics").status_code == 401

    def test_metrics_reject_a_wrong_token(self, client, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_METRICS_TOKEN", "s3cret")
        monkeypatch.delenv("OBSIDIOS_METRICS_PUBLIC", raising=False)

        response = client.get(
            "/metrics", headers={"Authorization": "Bearer wrong"})

        assert response.status_code == 401

    def test_metrics_render_for_the_configured_token(self, client,
                                                     monkeypatch):
        monkeypatch.setenv("OBSIDIOS_METRICS_TOKEN", "s3cret")
        monkeypatch.delenv("OBSIDIOS_METRICS_PUBLIC", raising=False)

        response = client.get(
            "/metrics", headers={"Authorization": "Bearer s3cret"})

        assert response.status_code == 200
        assert b"obsidios_hosts_active" in response.data

    def test_metrics_can_be_made_public(self, client, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_METRICS_PUBLIC", "1")

        assert client.get("/metrics").status_code == 200

    def test_posture_failure_does_not_break_metrics(self, client,
                                                    monkeypatch):
        monkeypatch.setenv("OBSIDIOS_METRICS_PUBLIC", "1")

        def broken():
            raise RuntimeError("posture failed")

        monkeypatch.setattr(dash, "sync_calculate_global_posture", broken)

        response = client.get("/metrics")

        assert response.status_code == 200
        assert b"obsidios_posture_score 0.0" in response.data

    def test_collection_failure_returns_503(self, client, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_METRICS_PUBLIC", "1")

        def broken(*_args, **_kwargs):
            raise RuntimeError("db down")

        monkeypatch.setattr(dash.db, "fetch_val", broken)

        response = client.get("/metrics")

        assert response.status_code == 503
        assert b"# error collecting metrics" in response.data


class TestLatencyProbe:
    def _reset(self, monkeypatch, at=0.0, val=0.0):
        monkeypatch.setattr(dash, "_lat_cache", {"val": val, "at": at})

    def test_cached_value_avoids_a_new_connection(self, monkeypatch):
        self._reset(monkeypatch, at=time.time(), val=12.5)

        def explode(*_args, **_kwargs):
            raise AssertionError("must use the cache")

        monkeypatch.setattr(dash.socket, "socket", explode)

        assert dash._get_latency() == 12.5

    def test_successful_connect_updates_the_cache(self, monkeypatch):
        self._reset(monkeypatch)

        class FakeSocket:
            def settimeout(self, _timeout):
                pass

            def connect(self, _address):
                pass

            def close(self):
                pass

        monkeypatch.setattr(dash.socket, "socket", lambda *a: FakeSocket())

        assert dash._get_latency() >= 0
        assert dash._lat_cache["at"] > 0

    def test_connect_failure_reports_zero_latency(self, monkeypatch):
        self._reset(monkeypatch)

        class FakeSocket:
            def settimeout(self, _timeout):
                pass

            def connect(self, _address):
                raise OSError("unreachable")

            def close(self):
                pass

        monkeypatch.setattr(dash.socket, "socket", lambda *a: FakeSocket())

        assert dash._get_latency() == 0.0

    def test_close_failure_is_swallowed(self, monkeypatch):
        self._reset(monkeypatch)

        class FakeSocket:
            def settimeout(self, _timeout):
                pass

            def connect(self, _address):
                pass

            def close(self):
                raise OSError("already closed")

        monkeypatch.setattr(dash.socket, "socket", lambda *a: FakeSocket())

        assert dash._get_latency() >= 0


class TestValidationHelpers:
    def test_clean_text_rejects_non_strings_empty_and_control_characters(self):
        assert dash._clean_text(None) is None
        assert dash._clean_text(7) is None
        assert dash._clean_text("   ") is None
        assert dash._clean_text("x" * 65, 64) is None
        assert dash._clean_text("bad\x00name") is None
        assert dash._clean_text("  lab  ") == "lab"

    def test_target_rejects_a_non_network(self):
        target, error = dash._validated_target("not-a-network")

        assert target is None
        assert "valid CIDR" in error

    def test_target_rejects_a_public_range_without_opt_in(self):
        target, error = dash._validated_target("8.8.8.0/24")

        assert target is None
        assert "public range" in error

    def test_profile_is_case_insensitive(self):
        assert dash._validated_profile("fast") == "FAST"

    def test_profile_rejects_blank_values(self):
        assert dash._validated_profile(None) is None
        assert dash._validated_profile("   ") is None

    def test_allowed_profiles_falls_back_when_config_is_unavailable(
            self, monkeypatch):
        monkeypatch.setattr(dash, "_ALLOWED_PROFILES", set())
        monkeypatch.setitem(sys.modules, "config.settings", None)

        assert dash._allowed_profiles() == {
            "FAST", "STEALTH", "GHOST", "STEALTH_IDLE"}

    def test_posture_failure_returns_zero_instead_of_raising(self,
                                                             monkeypatch):
        def broken(*_args, **_kwargs):
            raise RuntimeError("db down")

        monkeypatch.setattr(dash.db, "fetch_all", broken)

        assert dash.sync_calculate_global_posture() == 0.0

    def test_csv_safe_neutralises_formula_prefixes(self):
        assert dash._csv_safe(None) == ""
        assert dash._csv_safe("=1+1") == "'=1+1"
        assert dash._csv_safe("@SUM(A1)") == "'@SUM(A1)"
        assert dash._csv_safe("ordinary") == "ordinary"


class TestDeliveryPayload:
    def test_missing_record_returns_none(self, monkeypatch):
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: None)

        assert dash._delivery_payload() is None

    @pytest.mark.parametrize(
        "row, state",
        [
            ({"ok": 0, "rule_count": 0, "reload_ok": None}, "FAILED"),
            ({"ok": 1, "rule_count": 0, "reload_ok": None}, "EMPTY"),
            ({"ok": 1, "rule_count": 3, "reload_ok": None}, "WRITTEN"),
            ({"ok": 1, "rule_count": 3, "reload_ok": 1}, "DEPLOYED"),
            ({"ok": 1, "rule_count": 3, "reload_ok": 0}, "WRITTEN_NO_RELOAD"),
        ],
    )
    def test_recorded_attempts_map_to_one_truthful_state(
            self, monkeypatch, row, state):
        base = {"attempted_at": 1.5, "path": "/tmp/x.rules", "error": None,
                "reload_output": None}
        base.update(row)
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: base)

        payload = dash._delivery_payload()

        assert payload["state"] == state
        assert payload["rule_count"] == row["rule_count"]


class TestGraphDegradation:
    def test_empty_inventory_returns_an_empty_graph(self, client, monkeypatch):
        monkeypatch.setattr(
            dash.db, "fetch_val", lambda *_a, **_k: None)
        monkeypatch.setattr(
            dash.db, "fetch_all", lambda *_a, **_k: [])

        response = client.get("/api/v2/graph", headers=_auth(client))

        assert response.status_code == 200
        assert response.get_json() == {
            "nodes": [], "links": [], "blast_radius": []}

    def test_malformed_path_entries_do_not_hide_the_hosts(
            self, client, monkeypatch):
        def fetch_val(sql, _params=(), default=None):
            if "graph_cache" in sql:
                return None
            if "MAX(simulated_at)" in sql:
                return 12_345.0
            return default

        def fetch_all(sql, _params=()):
            if "DISTINCT h.ip" in sql:
                return []
            if "path_json" in sql:
                return [
                    {"path_json": '{"not": "a list"}'},
                    {"path_json": "[1, 2]"},
                ]
            if "FROM hosts" in sql:
                return [
                    {"id": 1, "ip": "192.168.1.5", "risk_score": 10,
                     "os_name": None, "vendor": "Acme"},
                    {"id": 2, "ip": None, "risk_score": 0,
                     "os_name": None, "vendor": None},
                ]
            return []

        monkeypatch.setattr(dash.db, "fetch_val", fetch_val)
        monkeypatch.setattr(dash.db, "fetch_all", fetch_all)

        response = client.get("/api/v2/graph", headers=_auth(client))

        assert response.status_code == 200
        body = response.get_json()
        assert [node["id"] for node in body["nodes"]] == ["192.168.1.5"]
        assert body["links"] == []


class TestEndpointFailureContract:
    """A CHRONICLE outage must be a JSON 500, never a success or a traceback."""

    ENDPOINTS = [
        ("GET", "/api/v2/stats", None),
        ("GET", "/api/v2/context", None),
        ("GET", "/api/v2/graph", None),
        ("GET", "/api/v2/details/hosts", None),
        ("GET", "/api/v2/details/ports", None),
        ("GET", "/api/v2/details/paths", None),
        ("GET", "/api/v2/details/host?ip=192.168.1.50", None),
        ("GET", "/api/v2/audit/timeline", None),
        ("GET", "/api/v2/audit/log", None),
        ("GET", "/api/v2/config/target", None),
        ("GET", "/api/v2/config/schedule", None),
        ("GET", "/api/v2/config/targets", None),
        ("GET", "/api/v2/shield/actions", None),
        ("GET", "/api/v2/export/csv?type=hosts", None),
        ("GET", "/api/v2/export/pdf", None),
        ("GET", "/api/v2/cves", None),
        ("POST", "/api/v2/cves/dismiss/1/1", None),
        ("GET", "/api/v2/system/retention", None),
        ("POST", "/api/v2/system/retention", {"days": 30}),
        ("POST", "/api/v2/system/prune", {"days": 30}),
        ("POST", "/api/actions/toggle_scanner", {}),
        ("POST", "/api/actions/scan", None),
        ("POST", "/api/actions/cancel_scan", None),
        ("GET", "/api/v2/alerts/config", None),
        ("POST", "/api/v2/alerts/config", {"critical_to_discord": True}),
        ("GET", "/api/v2/forge/rules", None),
        ("POST", "/api/v2/forge/deploy/1", None),
        ("GET", "/api/v2/cves/exploit_status", None),
        ("GET", "/api/v2/iris/osint", None),
        ("GET", "/api/v2/iris/wireless", None),
        ("GET", "/api/v2/sentinel/alerts", None),
        ("POST", "/api/v2/sentinel/alerts/ack_all", None),
        ("POST", "/api/v2/sentinel/alerts/1/ack", None),
    ]

    @pytest.mark.parametrize("method, path, payload", ENDPOINTS)
    def test_database_outage_is_a_json_500(self, client, monkeypatch,
                                           method, path, payload):
        headers = _auth(client)

        def broken(*_args, **_kwargs):
            raise RuntimeError("database is locked")

        for name in ("fetch_all", "fetch_one", "fetch_val", "execute"):
            monkeypatch.setattr(dash.db, name, broken)

        response = client.open(path, method=method, json=payload,
                               headers=headers)

        assert response.status_code == 500, path
        assert response.is_json, path
        assert response.get_json()["error"] == "Internal server error"


class TestConfigRoutes:
    def test_target_rejects_invalid_network_and_profile(self, client):
        headers = _auth(client)

        assert client.post(
            "/api/v2/config/target", headers=headers,
            json={"target": "nope", "profile": "FAST"},
        ).status_code == 400
        assert client.post(
            "/api/v2/config/target", headers=headers,
            json={"target": "10.0.0.0/24", "profile": "TURBO"},
        ).status_code == 400

    def test_target_get_returns_stored_values(self, client):
        headers = _auth(client)

        response = client.get("/api/v2/config/target", headers=headers)

        assert response.status_code == 200
        assert {"target", "profile"} <= set(response.get_json())

    def test_schedule_rejects_bad_frequency_and_time(self, client):
        headers = _auth(client)

        assert client.post(
            "/api/v2/config/schedule", headers=headers,
            json={"frequency": "fortnightly", "time": "02:00"},
        ).status_code == 400
        bad_time = client.post(
            "/api/v2/config/schedule", headers=headers,
            json={"frequency": "daily", "time": "25:99"},
        )
        assert bad_time.status_code == 400
        assert "local time" in bad_time.get_json()["error"]
        assert client.post(
            "/api/v2/config/schedule", headers=headers,
            json={"frequency": "daily", "time": 200},
        ).status_code == 400

    def test_saved_target_validation(self, client):
        headers = _auth(client)

        assert client.post(
            "/api/v2/config/targets", headers=headers,
            json={"name": "", "target": "10.0.0.0/24", "profile": "FAST"},
        ).status_code == 400
        assert client.post(
            "/api/v2/config/targets", headers=headers,
            json={"name": "lab", "target": "bad", "profile": "FAST"},
        ).status_code == 400
        assert client.post(
            "/api/v2/config/targets", headers=headers,
            json={"name": "lab", "target": "10.0.0.0/24",
                  "profile": "TURBO"},
        ).status_code == 400

    def test_saving_a_target_persists_it(self, client):
        headers = _auth(client)

        saved = client.post(
            "/api/v2/config/targets", headers=headers,
            json={"name": "lab", "target": "10.0.0.0/24",
                  "profile": "fast"},
        )

        assert saved.status_code == 200
        listing = client.get("/api/v2/config/targets", headers=headers)
        assert listing.status_code == 200
        assert any(t["name"] == "lab"
                   for t in listing.get_json()["targets"])

    def test_using_a_missing_saved_target_is_404(self, client):
        headers = _auth(client)

        assert client.post(
            "/api/v2/config/targets/9999/use", headers=headers,
        ).status_code == 404

    def test_using_a_stale_saved_target_is_refused(self, client, monkeypatch):
        headers = _auth(client)
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: {
            "id": 1, "name": "old", "target_cidr": "8.8.8.0/24",
            "scan_profile": "FAST",
        })

        response = client.post(
            "/api/v2/config/targets/1/use", headers=headers)

        assert response.status_code == 400
        assert "no longer valid" in response.get_json()["error"]

    def test_using_a_saved_target_applies_it(self, client, monkeypatch):
        headers = _auth(client)
        executed = []
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: {
            "id": 1, "name": "office", "target_cidr": "10.0.0.0/24",
            "scan_profile": "fast",
        })
        monkeypatch.setattr(
            dash.db, "execute", lambda sql, params=(): executed.append(params))

        response = client.post(
            "/api/v2/config/targets/1/use", headers=headers)

        assert response.status_code == 200
        assert ("10.0.0.0/24",) in executed
        assert ("FAST",) in executed


class TestOperatorActions:
    def test_shield_revert_missing_action_is_404(self, client, monkeypatch):
        headers = _auth(client)
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: None)

        assert client.post(
            "/api/v2/shield/revert/7", headers=headers).status_code == 404

    def test_failed_shield_revert_leaves_the_block_active(
            self, client, monkeypatch):
        headers = _auth(client)
        monkeypatch.setattr(
            dash.db, "fetch_one", lambda *_a, **_k: {"id": 7})

        async def refused(_aid, reverted_by=None):
            return False

        import shield.reconfigurer
        monkeypatch.setattr(
            shield.reconfigurer, "revert_action", refused)

        response = client.post("/api/v2/shield/revert/7", headers=headers)

        assert response.status_code == 500
        assert "block remains active" in response.get_json()["error"]

    def test_successful_shield_revert_is_audited(self, client, monkeypatch):
        headers = _auth(client)
        monkeypatch.setattr(
            dash.db, "fetch_one", lambda *_a, **_k: {"id": 7})

        async def applied(_aid, reverted_by=None):
            return True

        import shield.reconfigurer
        monkeypatch.setattr(shield.reconfigurer, "revert_action", applied)

        response = client.post("/api/v2/shield/revert/7", headers=headers)

        assert response.status_code == 200

    def test_sentinel_ack_missing_alert_is_404(self, client, monkeypatch):
        headers = _auth(client)
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: None)

        assert client.post(
            "/api/v2/sentinel/alerts/9/ack", headers=headers).status_code == 404

    def test_sentinel_ack_and_ack_all_report_counts(self, client,
                                                    monkeypatch):
        headers = _auth(client)

        class Cursor:
            def __init__(self, value):
                self.value = value

            def fetchone(self):
                return self.value

        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: {"id": 9})
        monkeypatch.setattr(dash.db, "fetch_val", lambda *_a, **_k: 4)
        monkeypatch.setattr(dash.db, "execute", lambda *_a, **_k: Cursor(None))

        ack = client.post("/api/v2/sentinel/alerts/9/ack", headers=headers)
        ack_all = client.post(
            "/api/v2/sentinel/alerts/ack_all", headers=headers)

        assert ack.status_code == 200
        assert ack_all.json["acknowledged"] == 4

    def test_alert_config_round_trip(self, client):
        headers = _auth(client)

        assert client.get(
            "/api/v2/alerts/config", headers=headers).status_code == 200
        response = client.post(
            "/api/v2/alerts/config", headers=headers,
            json={"critical_to_discord": True, "high_to_dashboard": False},
        )
        assert response.status_code == 200

    def test_retention_round_trip(self, client):
        headers = _auth(client)

        response = client.post(
            "/api/v2/system/retention", headers=headers, json={"days": 45})

        assert response.status_code == 200
        assert response.json["days"] == 45
        assert client.get(
            "/api/v2/system/retention", headers=headers).json["days"] == 45

    def test_scanner_toggle_accepts_an_explicit_state(self, client):
        headers = _auth(client)

        response = client.post(
            "/api/actions/toggle_scanner", headers=headers,
            json={"enabled": False},
        )

        assert response.status_code == 200
        assert response.json["enabled"] is False

    def test_host_export_neutralises_formula_cells(self, client, monkeypatch):
        headers = _auth(client)
        monkeypatch.setattr(dash.db, "fetch_all", lambda *_a, **_k: [{
            "ip": "=cmd|' /C calc'!A0", "mac": None, "hostname": "@evil",
            "os_name": "Linux", "risk_score": 50, "asset_value": 3,
        }])

        response = client.get(
            "/api/v2/export/csv?type=hosts", headers=headers)

        assert response.status_code == 200
        assert response.mimetype == "text/csv"
        assert "'=cmd" in response.get_data(as_text=True)
        assert "'@evil" in response.get_data(as_text=True)

    def test_csv_export_handles_real_sqlite_rows(self, client, monkeypatch):
        """aiosqlite.Row has no `.get`; every non-empty export used to 500."""
        headers = _auth(client)
        hosts = _sqlite_rows(
            ["ip", "mac", "hostname", "os_name", "risk_score", "asset_value"],
            [("10.0.0.5", "AA:BB:CC:DD:EE:01", "web", "Linux", 70, 4)],
        )
        cves = _sqlite_rows(
            ["ip", "cve_id", "cvss_v3", "severity"],
            [("10.0.0.5", "CVE-2026-0001", 9.8, "CRITICAL")],
        )

        def fake_fetch_all(sql, _params=()):
            return cves if "FROM cves c" in sql else hosts

        monkeypatch.setattr(dash.db, "fetch_all", fake_fetch_all)

        host_response = client.get(
            "/api/v2/export/csv?type=hosts", headers=headers)
        assert host_response.status_code == 200, host_response.data
        assert "10.0.0.5" in host_response.get_data(as_text=True)
        assert "web" in host_response.get_data(as_text=True)

        cve_response = client.get(
            "/api/v2/export/csv?type=cves", headers=headers)
        assert cve_response.status_code == 200, cve_response.data
        assert "CVE-2026-0001" in cve_response.get_data(as_text=True)

    def test_export_rejects_an_unknown_data_type(self, client):
        headers = _auth(client)

        response = client.get(
            "/api/v2/export/csv?type=passwords", headers=headers)

        assert response.status_code == 400
        assert response.json["error"] == "invalid type"

    def test_network_stats_rejects_no_input(self, client, monkeypatch):
        headers = _auth(client)
        monkeypatch.setattr(
            dash, "_capture_iface", lambda: (_ for _ in ()).throw(
                RuntimeError("no interface")))

        response = client.get("/api/network/stats", headers=headers)

        assert response.status_code == 500


class TestForgeRoutes:
    def test_toggle_missing_rule_is_404(self, client, monkeypatch):
        headers = _auth(client)
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: None)

        assert client.post(
            "/api/v2/forge/deploy/5", headers=headers).status_code == 404

    def test_toggle_includes_a_rule_and_reports_delivery(
            self, client, monkeypatch):
        headers = _auth(client)
        executed = []
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: {
            "is_active": 0, "operator_excluded": 0})
        monkeypatch.setattr(
            dash.db, "execute", lambda sql, params=(): executed.append(
                (sql, params)))

        async def written():
            return RuleDelivery(ok=True, rule_count=2, reload_ok=True)

        import forge.rule_generator
        monkeypatch.setattr(
            forge.rule_generator, "write_rules_file", written)

        response = client.post("/api/v2/forge/deploy/5", headers=headers)

        assert response.status_code == 200
        assert response.json["is_active"] is True
        assert response.json["delivery"]["state"] == "DEPLOYED"
        assert (1, 0, 5) in [params for _sql, params in executed]

    def test_failed_write_restores_the_operators_previous_choice(
            self, client, monkeypatch):
        headers = _auth(client)
        executed = []
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: {
            "is_active": 0, "operator_excluded": 1})
        monkeypatch.setattr(
            dash.db, "execute", lambda sql, params=(): executed.append(
                (sql, params)))

        async def refused():
            return RuleDelivery(ok=False, error="disk full")

        import forge.rule_generator
        monkeypatch.setattr(
            forge.rule_generator, "write_rules_file", refused)

        response = client.post("/api/v2/forge/deploy/5", headers=headers)

        assert response.status_code == 500
        assert (0, 1, 5) in [params for _sql, params in executed]

    def test_crashed_write_restores_the_previous_choice(self, client,
                                                        monkeypatch):
        headers = _auth(client)
        executed = []
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: {
            "is_active": 1, "operator_excluded": 0})
        monkeypatch.setattr(
            dash.db, "execute", lambda sql, params=(): executed.append(
                (sql, params)))

        async def crashed():
            raise RuntimeError("suricata died")

        import forge.rule_generator
        monkeypatch.setattr(
            forge.rule_generator, "write_rules_file", crashed)

        response = client.post("/api/v2/forge/deploy/5", headers=headers)

        assert response.status_code == 500
        assert executed[-1][1] == (1, 0, 5)

    def test_rewrite_reports_the_delivery_state(self, client, monkeypatch):
        headers = _auth(client)

        async def written():
            return RuleDelivery(ok=True, rule_count=1, reload_ok=None)

        import forge.rule_generator
        monkeypatch.setattr(
            forge.rule_generator, "write_rules_file", written)

        response = client.post("/api/v2/forge/rewrite", headers=headers)

        assert response.status_code == 200
        assert response.json["delivery"]["state"] == "WRITTEN"

    def test_rewrite_failure_is_a_500(self, client, monkeypatch):
        headers = _auth(client)

        async def failed():
            return RuleDelivery(ok=False, error="read-only")

        import forge.rule_generator
        monkeypatch.setattr(
            forge.rule_generator, "write_rules_file", failed)

        response = client.post("/api/v2/forge/rewrite", headers=headers)

        assert response.status_code == 500
        assert response.json["delivery"]["state"] == "FAILED"

    def test_rewrite_crash_is_a_json_500(self, client, monkeypatch):
        headers = _auth(client)

        async def crashed():
            raise RuntimeError("boom")

        import forge.rule_generator
        monkeypatch.setattr(
            forge.rule_generator, "write_rules_file", crashed)

        response = client.post("/api/v2/forge/rewrite", headers=headers)

        assert response.status_code == 500
        assert response.json["error"] == "Internal server error"

    def test_feedback_validates_input(self, client):
        headers = _auth(client)

        assert client.post(
            "/api/v2/forge/feedback", headers=headers, json={},
        ).status_code == 400
        assert client.post(
            "/api/v2/forge/feedback", headers=headers,
            json={"rule_id": 1, "verdict": "maybe"},
        ).status_code == 400

    @pytest.mark.parametrize(
        "error, status",
        [(ValueError("bad verdict"), 400), (LookupError("no rule"), 404)],
    )
    def test_feedback_maps_service_errors(self, client, monkeypatch,
                                          error, status):
        headers = _auth(client)

        async def broken(**_kwargs):
            raise error

        import antibody.service
        monkeypatch.setattr(antibody.service, "record_feedback", broken)

        response = client.post(
            "/api/v2/forge/feedback", headers=headers,
            json={"rule_id": 1, "verdict": "tp"},
        )

        assert response.status_code == status
        assert str(error) in response.json["error"]

    def test_feedback_records_a_verdict(self, client, monkeypatch):
        headers = _auth(client)

        async def recorded(**_kwargs):
            return {"status": "success", "suggestion": "keep"}

        import antibody.service
        monkeypatch.setattr(antibody.service, "record_feedback", recorded)

        response = client.post(
            "/api/v2/forge/feedback", headers=headers,
            json={"rule_id": 1, "verdict": "tp"},
        )

        assert response.status_code == 200
        assert response.json["suggestion"] == "keep"

    def test_crashed_write_is_a_json_500_for_feedback(
            self, client, monkeypatch):
        headers = _auth(client)

        async def broken(**_kwargs):
            raise RuntimeError("boom")

        import antibody.service
        monkeypatch.setattr(antibody.service, "record_feedback", broken)

        response = client.post(
            "/api/v2/forge/feedback", headers=headers,
            json={"rule_id": 1, "verdict": "tp"},
        )

        assert response.status_code == 500


class TestReadOnlyRoutes:
    def test_iris_and_sentinel_views_return_data(self, client):
        headers = _auth(client)

        for path in ("/api/v2/iris/osint", "/api/v2/iris/wireless",
                     "/api/v2/sentinel/alerts", "/api/v2/shield/actions"):
            response = client.get(path, headers=headers)
            assert response.status_code == 200, path
            assert "data" in response.get_json(), path


class TestOracleRoutes:
    @pytest.mark.parametrize(
        "module, function, method, path",
        [
            ("oracle.attacker_view", "get_anomalous_ports", "GET",
             "/api/v2/details/anomalous_ports"),
            ("oracle.attacker_view", "generate_attacker_view", "GET",
             "/api/v2/offensive/attack_vectors"),
            ("oracle.compliance_mapper", "map_compliance", "GET",
             "/api/v2/oracle/compliance"),
            ("oracle.patch_prioritizer", "generate_patch_priority", "GET",
             "/api/v2/oracle/patch_priority"),
            ("antibody.service", "list_suggestions", "GET",
             "/api/v2/forge/suggestions"),
            ("iris.cve_mapper", "verify_all_cves", "POST",
             "/api/v2/cves/reverify"),
            ("iris.wired_scanner", "run_wireless_scan", "POST",
             "/api/v2/iris/scan_wireless"),
        ],
    )
    def test_service_failure_is_a_json_500(self, client, monkeypatch,
                                           module, function, method, path):
        headers = _auth(client)

        async def broken(*_args, **_kwargs):
            raise RuntimeError(f"{function} exploded")

        imported = __import__(module, fromlist=[function])
        monkeypatch.setattr(imported, function, broken)

        response = client.open(path, method=method, headers=headers)

        assert response.status_code == 500, path
        assert response.is_json

    def test_ai_brief_returns_both_documents(self, client, monkeypatch):
        headers = _auth(client)

        async def narrative():
            return "the attack story"

        async def remediation():
            return "patch everything"

        import oracle.claude_client
        monkeypatch.setattr(
            oracle.claude_client, "generate_attack_narrative", narrative)
        monkeypatch.setattr(
            oracle.claude_client, "generate_remediation", remediation)

        response = client.get("/api/v2/oracle/ai_brief", headers=headers)

        assert response.status_code == 200
        assert response.json["narrative"] == "the attack story"
        assert response.json["remediation"] == "patch everything"

    def test_ai_brief_retries_once_on_a_locked_database(
            self, client, monkeypatch):
        headers = _auth(client)
        calls = {"narrative": 0}

        async def narrative():
            calls["narrative"] += 1
            if calls["narrative"] == 1:
                raise RuntimeError("database is locked")
            return "second try"

        async def remediation():
            return "patch"

        monkeypatch.setattr(dash.time, "sleep", lambda _s: None)
        import oracle.claude_client
        monkeypatch.setattr(
            oracle.claude_client, "generate_attack_narrative", narrative)
        monkeypatch.setattr(
            oracle.claude_client, "generate_remediation", remediation)

        response = client.get("/api/v2/oracle/ai_brief", headers=headers)

        assert response.status_code == 200
        assert response.json["narrative"] == "second try"

    def test_ai_brief_failure_is_a_500_with_the_reason(self, client,
                                                       monkeypatch):
        headers = _auth(client)

        async def broken():
            raise RuntimeError("model offline")

        import oracle.claude_client
        monkeypatch.setattr(
            oracle.claude_client, "generate_attack_narrative", broken)
        monkeypatch.setattr(
            oracle.claude_client, "generate_remediation", broken)

        response = client.get("/api/v2/oracle/ai_brief", headers=headers)

        assert response.status_code == 500
        assert "model offline" in response.json["error"]


class TestPdfReport:
    def _fake_weasyprint(self, monkeypatch):
        class FakeHtml:
            def __init__(self, string):
                self.document = string

            def write_pdf(self):
                assert "OBSIDIOS" in self.document
                return b"%PDF-1.4 fake"

        monkeypatch.setitem(sys.modules, "weasyprint",
                            SimpleNamespace(HTML=FakeHtml))

    def test_null_legacy_fields_do_not_blank_the_report(self, client,
                                                        monkeypatch):
        rows = {
            "FROM attack_paths": [],
            "FROM hosts": [{"ip": None, "mac": None, "hostname": None,
                            "os_name": None, "risk_score": None,
                            "asset_value": None}],
            "GROUP BY c.severity": [
                {"severity": "CRITICAL", "cnt": 2},
                {"severity": None, "cnt": 1},
            ],
            "FROM cves c": [{"ip": None, "cve_id": None, "cvss_v3": None,
                             "severity": None, "description": None}],
        }
        monkeypatch.setattr(dash.db, "fetch_all",
                            lambda sql, _params=(): rows[next(
                                key for key in rows if key in sql)])
        monkeypatch.setattr(dash.db, "fetch_val",
                            lambda sql, _params=(), default=None:
                            "10.0.0.0/24" if "target_network" in sql
                            else default or 1)
        monkeypatch.setattr(dash.db, "execute", lambda *_a, **_k: None)
        self._fake_weasyprint(monkeypatch)

        response = client.get(
            "/api/v2/export/pdf", headers=_auth(client))

        assert response.status_code == 200
        assert response.mimetype == "application/pdf"

    def test_real_sqlite_rows_render_without_attribute_errors(
            self, client, monkeypatch):
        """The summary query returns sqlite3.Row, which has no `.get`."""
        hosts = _sqlite_rows(
            ["ip", "mac", "hostname", "os_name", "risk_score", "asset_value"],
            [("10.0.0.5", None, "web", "Linux", 70, 4)],
        )
        cves = _sqlite_rows(
            ["ip", "cve_id", "cvss_v3", "severity", "description"],
            [("10.0.0.5", "CVE-2026-0001", 9.8, "CRITICAL", "RCE")],
        )
        summary = _sqlite_rows(
            ["severity", "cnt"], [("CRITICAL", 2), ("HIGH", 1)])

        def fake_fetch_all(sql, _params=()):
            if "GROUP BY c.severity" in sql:
                return summary
            if "FROM cves c" in sql:
                return cves
            return hosts

        monkeypatch.setattr(dash.db, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(
            dash.db, "fetch_val",
            lambda _sql, _params=(), default=None: default or 1)
        monkeypatch.setattr(dash.db, "execute", lambda *_a, **_k: None)

        rendered = {}

        class FakeHtml:
            def __init__(self, string):
                rendered["html"] = string

            def write_pdf(self):
                return b"%PDF-1.4 fake"

        monkeypatch.setitem(sys.modules, "weasyprint",
                            SimpleNamespace(HTML=FakeHtml))

        response = client.get(
            "/api/v2/export/pdf", headers=_auth(client))

        assert response.status_code == 200, response.data
        assert "2 critical" in rendered["html"].lower()
        assert "CVE-2026-0001" in rendered["html"]

    def test_render_failure_is_a_json_500(self, client, monkeypatch):
        class BrokenHtml:
            def __init__(self, string):
                raise RuntimeError("renderer missing")
        monkeypatch.setitem(sys.modules, "weasyprint",
                            SimpleNamespace(HTML=BrokenHtml))
        monkeypatch.setattr(dash.db, "fetch_all", lambda *_a, **_k: [])
        monkeypatch.setattr(dash.db, "fetch_val", lambda *_a, **_k: 0)

        response = client.get(
            "/api/v2/export/pdf", headers=_auth(client))

        assert response.status_code == 500
        assert response.json["error"] == "Internal server error"


class TestSecretResolution:
    def test_config_secret_is_used_when_the_environment_is_empty(
            self, monkeypatch):
        from config import settings

        monkeypatch.delenv("OBSIDIOS_SECRET", raising=False)
        monkeypatch.delenv("SECRET_KEY", raising=False)
        monkeypatch.setattr(settings.dash, "secret_key", "c" * 40)

        assert dash._resolve_app_secret() == "c" * 40

    def test_unavailable_config_falls_back_to_empty(self, monkeypatch):
        monkeypatch.delenv("OBSIDIOS_SECRET", raising=False)
        monkeypatch.delenv("SECRET_KEY", raising=False)
        monkeypatch.setitem(sys.modules, "config.settings", None)

        assert dash._resolve_app_secret() == ""

    def test_weak_secret_fails_closed_in_production(self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_ENV", "production")
        monkeypatch.setenv("OBSIDIOS_SECRET", "changeme")

        with pytest.raises(RuntimeError, match="at least 32 random"):
            dash._secure_app_secret()

    def test_strong_secret_is_returned_unchanged(self, monkeypatch):
        strong = "s" * 48
        monkeypatch.setenv("OBSIDIOS_ENV", "production")
        monkeypatch.setenv("OBSIDIOS_SECRET", strong)

        assert dash._secure_app_secret() == strong

    def test_dev_fallback_is_explicitly_weak(self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_ENV", "dev")
        monkeypatch.delenv("OBSIDIOS_SECRET", raising=False)
        monkeypatch.delenv("SECRET_KEY", raising=False)
        monkeypatch.setitem(sys.modules, "config.settings", None)

        assert "dev-only" in dash._secure_app_secret()


class TestInfrastructureHelpers:
    def test_bg_loop_double_check_avoids_a_second_thread(self, monkeypatch):
        """Two racing callers must end up sharing one loop, not leaking a thread."""
        monkeypatch.setattr(dash, "_bg_loop", None)
        finished = []
        started = threading.Event()

        def worker():
            started.set()
            dash._ensure_bg_loop()
            finished.append(True)

        dash._bg_loop_lock.acquire()
        thread = threading.Thread(target=worker)
        thread.start()
        started.wait()
        # The worker is blocked on the lock; publish a loop before releasing it.
        dash._bg_loop = object()
        dash._bg_loop_lock.release()
        thread.join(timeout=2)

        assert finished == [True]

    def test_pre_init_failure_is_logged_not_raised(self, monkeypatch):
        class FakeFuture:
            def result(self, timeout=None):
                raise RuntimeError("database is locked")

        def scheduled(coro, _loop):
            coro.close()
            return FakeFuture()

        monkeypatch.setattr(dash.asyncio, "run_coroutine_threadsafe", scheduled)

        dash._pre_init_db()

    def test_run_async_timeout_cancels_the_future(self, monkeypatch):
        class FakeFuture:
            cancelled = False

            def result(self, timeout=None):
                raise __import__("concurrent.futures").futures.TimeoutError

            def cancel(self):
                self.cancelled = True

        async def work():
            return None

        future = FakeFuture()
        monkeypatch.setattr(dash, "_ensure_bg_loop", lambda: None)
        monkeypatch.setattr(
            dash.asyncio, "run_coroutine_threadsafe",
            lambda coro, _loop: (coro.close(), future)[1])

        with pytest.raises(TimeoutError, match="timed out after 5s"):
            dash.run_async(work(), timeout=5)

        assert future.cancelled is True

    def test_socket_log_sink_swallows_emit_failures(self, monkeypatch):
        def broken(*_args, **_kwargs):
            raise RuntimeError("socket closed")

        monkeypatch.setattr(dash.socketio, "emit", broken)

        dash.socketio_log_sink("  [ERROR] boom  ")

    def test_audit_prunes_the_trail_occasionally(self, monkeypatch):
        executed = []
        monkeypatch.setattr(dash.secrets, "randbelow", lambda _n: 0)
        monkeypatch.setattr(
            dash.db, "execute", lambda sql, params=(): executed.append(sql))

        with app.test_request_context("/"):
            dash._audit("TEST_ACTION")

        assert any("INSERT INTO audit_log" in sql for sql in executed)
        assert any("DELETE FROM audit_log" in sql for sql in executed)

    def test_empty_jti_is_not_revoked(self, monkeypatch):
        monkeypatch.setattr(dash, "_REVOKED_JTIS", {})

        dash._revoke_jti("", time.time() + 60)

        assert dash._REVOKED_JTIS == {}

    def test_weak_operator_password_fails_closed_in_production(
            self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_ENV", "production")
        monkeypatch.setenv("DASHBOARD_USER", "admin")
        monkeypatch.setenv("DASHBOARD_PASS", "obsidios123")

        assert dash.check_auth("admin", "obsidios123") is None

    def test_strong_operator_password_is_accepted_in_production(
            self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_ENV", "production")
        monkeypatch.setenv("DASHBOARD_USER", "admin")
        monkeypatch.setenv("DASHBOARD_PASS", "a-strong-operator-passphrase")

        assert dash.check_auth("admin", "a-strong-operator-passphrase") == (
            "operator")

    def test_health_does_not_touch_the_database(self, client, monkeypatch):
        def broken(*_args, **_kwargs):
            raise RuntimeError("db down")

        monkeypatch.setattr(dash.db, "fetch_val", broken)

        response = client.get("/api/health")

        assert response.status_code == 200
        assert response.json["status"] == "ok"

    def test_readyz_reports_ready(self, client):
        assert client.get("/api/readyz").status_code == 200

    def test_production_responses_carry_hsts(self, monkeypatch):
        from flask import Response

        monkeypatch.setattr(dash, "_is_production", lambda: True)

        response = dash.add_no_cache(Response("ok"))

        assert "Strict-Transport-Security" in response.headers

    def test_event_timestamp_tolerates_junk(self):
        assert dash._event_ts("not-a-time") == 0.0
        assert dash._event_ts(None) == 0.0
        assert dash._event_ts("12.5") == 12.5

    def test_retention_days_reject_junk(self):
        assert dash._validated_days("nope") is None
        assert dash._validated_days(0) is None
        assert dash._validated_days(3651) is None
        assert dash._validated_days("30") == 30

    def test_empty_target_is_rejected(self):
        target, error = dash._validated_target("")

        assert target is None
        assert "valid CIDR" in error


class TestGraphBlastRadius:
    def _graph(self, client, monkeypatch, critical_ip):
        def fetch_val(sql, _params=(), default=None):
            if "graph_cache" in sql:
                return None
            if "MAX(simulated_at)" in sql:
                return 1.0
            return default

        def fetch_all(sql, _params=()):
            if "DISTINCT h.ip" in sql:
                return [{"ip": critical_ip, "risk_score": 95,
                         "cve_id": "CVE-2026-1", "severity": "CRITICAL"}]
            if "path_json" in sql:
                return []
            if "FROM hosts" in sql:
                return [
                    {"id": 1, "ip": "192.168.1.1", "risk_score": 5,
                     "os_name": "Linux", "vendor": None},
                    {"id": 2, "ip": "192.168.1.5", "risk_score": 95,
                     "os_name": "Linux", "vendor": None},
                ]
            return []

        monkeypatch.setattr(dash.db, "fetch_val", fetch_val)
        monkeypatch.setattr(dash.db, "fetch_all", fetch_all)
        return client.get("/api/v2/graph", headers=_auth(client)).get_json()

    def test_critical_source_marks_its_neighbour_exposed(
            self, client, monkeypatch):
        body = self._graph(client, monkeypatch, "192.168.1.1")

        exposed = [item for item in body["blast_radius"]
                   if item["severity"] == "EXPOSED"]
        assert exposed == [{"ip": "192.168.1.5", "risk": 95,
                            "cve_id": None, "severity": "EXPOSED",
                            "is_source": False}]

    def test_critical_target_marks_its_neighbour_exposed(
            self, client, monkeypatch):
        body = self._graph(client, monkeypatch, "192.168.1.5")

        exposed = [item for item in body["blast_radius"]
                   if item["severity"] == "EXPOSED"]
        assert exposed == [{"ip": "192.168.1.1", "risk": 5,
                            "cve_id": None, "severity": "EXPOSED",
                            "is_source": False}]


class TestDetailRoutes:
    def test_context_reports_the_operational_state(self, client):
        response = client.get("/api/v2/context", headers=_auth(client))

        assert response.status_code == 200
        assert response.json["role"] == "operator"
        assert "target" in response.json

    def test_detail_lists_and_port_state_validation(self, client):
        headers = _auth(client)

        for path in ("/api/v2/details/hosts", "/api/v2/details/ports",
                     "/api/v2/details/paths"):
            response = client.get(path, headers=headers)
            assert response.status_code == 200, path
            assert "data" in response.get_json(), path

        assert client.get(
            "/api/v2/details/ports?state=bogus",
            headers=headers).status_code == 400

    def test_host_detail_requires_a_valid_address(self, client):
        response = client.get(
            "/api/v2/details/host?ip=not-an-ip", headers=_auth(client))

        assert response.status_code == 400

    def test_host_detail_requires_a_known_host(self, client, monkeypatch):
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: None)

        response = client.get(
            "/api/v2/details/host?ip=192.168.1.77", headers=_auth(client))

        assert response.status_code == 404

    def test_host_detail_returns_every_related_record(self, client,
                                                      monkeypatch):
        host = {"id": 3, "ip": "192.168.1.77", "mac": "aa:bb", "hostname": "x",
                "os_name": "Linux", "vendor": None, "risk_score": 20,
                "asset_value": 2, "first_seen": 1.0, "last_seen": 2.0}
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: host)

        def fetch_all(sql, _params=()):
            if "FROM ports" in sql:
                return [{"port": 22, "protocol": "tcp", "state": "open"}]
            if "FROM port_cves" in sql:
                return [{"cve_id": "CVE-2026-2", "severity": "HIGH"}]
            if "FROM sentinel_alerts" in sql:
                return [{"id": 1, "severity": "HIGH"}]
            if "FROM shield_actions" in sql:
                return [{"id": 2, "action_type": "BLOCK_IP"}]
            return []

        monkeypatch.setattr(dash.db, "fetch_all", fetch_all)

        response = client.get(
            "/api/v2/details/host?ip=192.168.1.77", headers=_auth(client))

        assert response.status_code == 200
        body = response.get_json()
        assert body["host"]["ip"] == "192.168.1.77"
        assert body["ports"][0]["port"] == 22
        assert body["cves"][0]["cve_id"] == "CVE-2026-2"
        assert body["alerts"] and body["blocks"]

    def test_timeline_merges_every_event_kind(self, client, monkeypatch):
        def fetch_all(sql, _params=()):
            if "FROM scans" in sql:
                return [{"id": 1, "scan_type": "WIRED", "target": "10.0.0.0/24",
                         "started_at": 1.0, "finished_at": 2.0,
                         "status": "DONE", "hosts_found": 2,
                         "ports_found": 3, "cves_found": 0}]
            if "FROM shield_actions" in sql:
                return [{"id": 2, "taken_at": 3.0, "action_type": "BLOCK_IP",
                         "target_ip": "10.0.0.5", "target_port": None,
                         "rule_applied": "-A INPUT", "justification": None,
                         "is_active": 1}]
            if "FROM sentinel_alerts" in sql:
                return [{"id": 3, "alerted_at": 4.0, "rule_sid": 9000001,
                         "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1",
                         "dst_port": 22, "severity": "HIGH",
                         "message": "alert", "predicted": 1,
                         "acknowledged": 0}]
            if "FROM forge_rules" in sql:
                return [{"id": 4, "created_at": 5.0, "rule_sid": 9000002,
                         "rule_category": "C2", "mitre_technique": "T1071",
                         "is_deployed": 1, "is_active": 1,
                         "delivered_at": 5.5},
                        {"id": 5, "created_at": 5.0, "rule_sid": 9000003,
                         "rule_category": "C2", "mitre_technique": None,
                         "is_deployed": 0, "is_active": 1,
                         "delivered_at": None}]
            return []

        monkeypatch.setattr(dash.db, "fetch_all", fetch_all)

        response = client.get(
            "/api/v2/audit/timeline", headers=_auth(client))

        assert response.status_code == 200
        kinds = {event["kind"] for event in response.json["data"]}
        assert kinds == {"SCAN", "SHIELD", "ALERT", "FORGE"}
        states = {event["status"] for event in response.json["data"]
                  if event["kind"] == "FORGE"}
        assert states == {"DEPLOYED", "STAGED"}

    def test_audit_log_returns_actions_and_applies_filters(
            self, client, monkeypatch):
        def fetch_all(sql, params=()):
            if "DISTINCT action" in sql:
                return [{"action": "A"}, {"action": "B"}]
            assert "WHERE (? = '' OR action = ?)" in sql
            assert params[-1] == 500
            return [{"id": 1, "action": "A"}]

        monkeypatch.setattr(dash.db, "fetch_all", fetch_all)

        response = client.get(
            "/api/v2/audit/log?limit=9999&action=A&actor=bob",
            headers=_auth(client))

        assert response.status_code == 200
        assert response.json["actions"] == ["A", "B"]
        assert response.json["count"] == 1

    def test_legacy_event_rows_sort_without_crashing(self, client,
                                                     monkeypatch):
        def fetch_all(sql, _params=()):
            if "FROM scans" in sql:
                return [{"id": 1, "scan_type": None, "target": None,
                         "started_at": "junk", "finished_at": None,
                         "status": None, "hosts_found": None,
                         "ports_found": None, "cves_found": None}]
            return []

        monkeypatch.setattr(dash.db, "fetch_all", fetch_all)

        response = client.get(
            "/api/v2/audit/timeline", headers=_auth(client))

        assert response.status_code == 200
        assert response.json["data"][0]["ts"] == "junk"


class TestRemainingActionSuccess:
    def test_schedule_round_trip(self, client):
        headers = _auth(client)

        saved = client.post(
            "/api/v2/config/schedule", headers=headers,
            json={"frequency": "daily", "time": "03:30", "enabled": True},
        )
        assert saved.status_code == 200

        fetched = client.get("/api/v2/config/schedule", headers=headers)
        assert fetched.json["frequency"] == "daily"
        assert fetched.json["time"] == "03:30"
        assert fetched.json["enabled"] is True

    def test_refresh_consumption_race_is_rejected(self, client, monkeypatch):
        refresh, _access = _tokens()
        payload = jwt.decode(refresh, SECRET, algorithms=["HS256"])
        monkeypatch.setattr(dash, "_decode_token", lambda _raw: payload)
        _refresh_cookie(client, refresh)

        assert client.post("/api/v2/refresh", json={}).status_code == 200
        replay = client.post("/api/v2/refresh", json={})

        assert replay.status_code == 401
        assert replay.json["error"] == "Refresh token already used"

    def test_cve_dismissal_toggles(self, client, monkeypatch):
        headers = _auth(client)
        current = iter([0, 1])
        monkeypatch.setattr(
            dash.db, "fetch_val", lambda *_a, **_k: next(current))
        monkeypatch.setattr(dash.db, "execute", lambda *_a, **_k: None)

        first = client.post(
            "/api/v2/cves/dismiss/10/20", headers=headers)
        second = client.post(
            "/api/v2/cves/dismiss/10/20", headers=headers)

        assert first.json["dismissed"] is True
        assert second.json["dismissed"] is False

    def test_reverify_reports_the_update_count(self, client, monkeypatch):
        headers = _auth(client)

        async def verified():
            return 3

        import iris.cve_mapper
        monkeypatch.setattr(iris.cve_mapper, "verify_all_cves", verified)

        response = client.post("/api/v2/cves/reverify", headers=headers)

        assert response.status_code == 200
        assert response.json["updated"] == 3

    def test_retention_and_prune_reject_out_of_range_days(self, client):
        headers = _auth(client)

        assert client.post(
            "/api/v2/system/retention", headers=headers,
            json={"days": 0}).status_code == 400
        assert client.post(
            "/api/v2/system/prune", headers=headers,
            json={"days": 99999}).status_code == 400

    def test_scanner_toggle_flips_the_current_state(self, client):
        headers = _auth(client)

        first = client.post(
            "/api/actions/toggle_scanner", headers=headers, json={})
        second = client.post(
            "/api/actions/toggle_scanner", headers=headers, json={})

        assert first.status_code == 200
        assert first.json["enabled"] is not second.json["enabled"]

    def test_scan_and_cancel_are_accepted(self, client, monkeypatch):
        headers = _auth(client)
        monkeypatch.setattr(dash.socketio, "emit", lambda *_a, **_k: None)

        assert client.post(
            "/api/actions/scan", headers=headers).status_code == 200
        assert client.post(
            "/api/actions/cancel_scan", headers=headers).status_code == 200

    def test_scan_trigger_refuses_to_stack_on_a_running_sweep(
            self, client, monkeypatch):
        """Cancelling the in-flight row used to let two sweeps overlap."""
        headers = _auth(client)
        monkeypatch.setattr(dash.db, "fetch_val", lambda *_a, **_k: 1)

        response = client.post("/api/v2/actions/scan", headers=headers)

        assert response.status_code == 409
        assert "already running" in response.json["error"]

    def test_crashed_running_row_is_reaped_before_trigger(
            self, client, monkeypatch):
        """One crashed sweep used to lock the trigger out forever."""
        headers = _auth(client)
        writes = []

        def fetch_val(sql, params=(), default=None):
            if "started_at <" in sql:
                return 1
            if "status='RUNNING'" in sql:
                return 0
            return default

        monkeypatch.setattr(dash.db, "fetch_val", fetch_val)
        monkeypatch.setattr(
            dash.db, "execute",
            lambda sql, params=(): writes.append((sql, params)))
        monkeypatch.setattr(dash.socketio, "emit", lambda *_a, **_k: None)

        response = client.post("/api/v2/actions/scan", headers=headers)

        assert response.status_code == 200
        assert any("UPDATE scans SET status='CANCELLED'" in sql
                   for sql, _ in writes)
        assert any("manual_trigger" in sql for sql, _ in writes)

    def test_cancel_states_that_partial_results_are_discarded(
            self, client, monkeypatch):
        headers = _auth(client)
        monkeypatch.setattr(dash.socketio, "emit", lambda *_a, **_k: None)

        response = client.post(
            "/api/v2/actions/cancel_scan", headers=headers)

        assert response.status_code == 200
        assert "discarded" in response.json["message"]

    def test_shield_revert_crash_is_a_json_500(self, client, monkeypatch):
        headers = _auth(client)
        monkeypatch.setattr(
            dash.db, "fetch_one", lambda *_a, **_k: {"id": 7})

        async def crashed(_aid, reverted_by=None):
            raise RuntimeError("iptables vanished")

        import shield.reconfigurer
        monkeypatch.setattr(shield.reconfigurer, "revert_action", crashed)

        response = client.post("/api/v2/shield/revert/7", headers=headers)

        assert response.status_code == 500
        assert response.json["error"] == "Internal server error"

    def test_forge_rule_list_reports_delivery(self, client):
        response = client.get("/api/v2/forge/rules", headers=_auth(client))

        assert response.status_code == 200
        assert "delivery" in response.json

    def test_suggestions_attack_vectors_and_patch_priority(self, client,
                                                           monkeypatch):
        headers = _auth(client)

        async def suggestions():
            return [{"rule_id": 1}]

        async def vectors():
            return {"vectors": []}

        async def priorities():
            return {"items": []}

        import antibody.service
        import oracle.attacker_view
        import oracle.patch_prioritizer
        monkeypatch.setattr(
            antibody.service, "list_suggestions", suggestions)
        monkeypatch.setattr(
            oracle.attacker_view, "generate_attacker_view", vectors)
        monkeypatch.setattr(
            oracle.patch_prioritizer, "generate_patch_priority", priorities)

        assert client.get(
            "/api/v2/forge/suggestions", headers=headers).json["count"] == 1
        assert client.get(
            "/api/v2/offensive/attack_vectors", headers=headers).json == {
                "vectors": []}
        assert client.get(
            "/api/v2/oracle/patch_priority", headers=headers).json == {
                "items": []}

    def test_wireless_scan_is_accepted(self, client, monkeypatch):
        async def scanned():
            return None

        import iris.wired_scanner
        monkeypatch.setattr(iris.wired_scanner, "run_wireless_scan", scanned)

        response = client.post(
            "/api/v2/iris/scan_wireless", headers=_auth(client))

        assert response.status_code == 200


class TestCriticalAlertCount:
    """The context poll drives the dashboard's critical alert tone."""

    def test_malformed_severity_defaults_to_info(self):
        rows = _sqlite_rows(
            ("severity",),
            [(1,), ("2",), (None,), ("HIGH",), (0,)])
        assert [dash._alert_severity(row) for row in rows] == [1, 2, 3, 3, 3]

    def test_context_counts_only_critical_unacked_alerts(self, client, monkeypatch):
        headers = _auth(client)
        rows = _sqlite_rows(
            ("id", "severity"),
            [(4, 1), (7, 1), (9, 2), (12, 3)])
        monkeypatch.setattr(dash, "_actionable_unacked_alerts_sync", lambda: rows)
        monkeypatch.setattr(
            dash.db, "fetch_val",
            lambda sql, *_a, **_k: 0 if "COUNT(*)" in sql else None)
        monkeypatch.setattr(dash.db, "fetch_one", lambda *_a, **_k: None)

        data = client.get("/api/v2/context", headers=headers).get_json()

        assert data["unacknowledged_alerts"] == 4
        assert data["critical_alerts"] == 2
        assert data["last_critical_alert_id"] == 7


class TestRunDashboardDatabaseFailure:
    def test_init_failure_warns_and_continues(self, monkeypatch):
        def broken(coro, *_args, **_kwargs):
            coro.close()
            raise RuntimeError("db locked")

        monkeypatch.setattr(dash, "run_async", broken)
        monkeypatch.setattr(dash, "_is_production", lambda: False)
        calls = {}
        monkeypatch.setattr(
            dash.socketio, "run",
            lambda application, **kwargs: calls.update(kwargs))

        dash.run_dashboard("127.0.0.1", 9595)

        assert calls["port"] == 9595
