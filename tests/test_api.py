"""Tests for dashboard/app.py — Flask API endpoint tests."""
import json
import sqlite3

import pytest

from dashboard.app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key-32-chars-minimum-ok!'
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

class TestCsvExport:
    """The CSV must contain exactly what the CVE page shows."""

    def test_cve_export_excludes_dismissed_and_retired_hosts(self, client, monkeypatch):
        import json as _json

        rv = client.post(
            "/api/v2/login",
            json={"username": "admin", "password": "obsidios123"},
        )
        token = _json.loads(rv.data)["token"]
        headers = {"Authorization": f"Bearer {token}"}

        captured = []

        def fake_fetch_all(sql, params=()):
            captured.append(sql)
            return [{"ip": "10.0.0.5", "cve_id": "CVE-2026-0001",
                     "cvss_v3": 9.8, "severity": "CRITICAL"}]

        monkeypatch.setattr("dashboard.app.db.fetch_all", fake_fetch_all)

        rv = client.get("/api/v2/export/csv?type=cves", headers=headers)
        assert rv.status_code == 200
        assert "CVE-2026-0001" in rv.get_data(as_text=True)

        sql = " ".join(captured)
        assert "pc.dismissed = 0" in sql
        assert "h.is_active = 1" in sql

    def test_unsupported_format_is_rejected(self, client):
        import json as _json

        rv = client.post(
            "/api/v2/login",
            json={"username": "admin", "password": "obsidios123"},
        )
        headers = {"Authorization": f"Bearer {_json.loads(rv.data)['token']}"}
        assert client.get("/api/v2/export/xml", headers=headers).status_code == 404


class TestConfigTargetCanonicalisation:
    """The dashboard used to store host bits exactly as typed."""

    def test_post_stores_the_canonical_network(self, client, monkeypatch):
        token = _auth_token(client)
        executed = []

        monkeypatch.setattr(
            "dashboard.app.db.execute",
            lambda sql, params=(): executed.append((sql, params)),
        )
        monkeypatch.setattr("dashboard.app._audit", lambda *a, **k: None)

        rv = client.post(
            "/api/v2/config/target",
            json={"target": "192.168.1.7/24", "profile": "stealth"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert rv.status_code == 200, rv.data[:200]
        stored = [p for sql, p in executed if "target_network" in sql]
        assert stored == [("192.168.1.0/24",)]
        assert rv.get_json()["profile"] == "STEALTH"


class TestConfigErrorResponses:
    """Config endpoints must answer with JSON, not Flask's HTML 500 page."""

    @pytest.mark.parametrize(
        "path,method,failing,payload",
        [
            ("/api/v2/config/target", "get", "fetch_val", None),
            ("/api/v2/config/target", "post", "execute",
             {"target": "10.44.0.0/24", "profile": "fast"}),
            ("/api/v2/config/schedule", "get", "fetch_val", None),
            ("/api/v2/config/schedule", "post", "execute",
             {"frequency": "daily", "time": "03:00", "enabled": True}),
            ("/api/v2/config/targets", "get", "fetch_all", None),
            ("/api/v2/config/targets", "post", "execute",
             {"name": "lab", "target": "10.44.0.0/24", "profile": "fast"}),
            ("/api/v2/config/targets/1/use", "post", "fetch_one", None),
            ("/api/v2/alerts/config", "get", "fetch_val", None),
            ("/api/v2/alerts/config", "post", "execute",
             {"critical_to_discord": True, "high_to_dashboard": False}),
        ],
    )
    def test_db_failure_returns_json_500(
            self, client, monkeypatch, path, method, failing, payload):
        token = _auth_token(client)

        def boom(*_args, **_kwargs):
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(f"dashboard.app.db.{failing}", boom)
        kwargs = {"headers": {"Authorization": f"Bearer {token}"}}
        if payload is not None:
            kwargs["json"] = payload
        rv = getattr(client, method)(path, **kwargs)

        assert rv.status_code == 500, rv.data[:300]
        assert rv.is_json, rv.data[:300]
        assert rv.get_json() == {"error": "Internal server error"}

    def test_network_detection_failure_returns_json_500(
            self, client, monkeypatch):
        token = _auth_token(client)

        def boom():
            raise RuntimeError("no route to host")

        monkeypatch.setattr("config.network_detector.detect_network", boom)
        rv = client.get(
            "/api/v2/config/detect-network",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert rv.status_code == 500, rv.data[:300]
        assert rv.get_json() == {"error": "Internal server error"}

    def test_schedule_get_survives_null_legacy_values(
            self, client, monkeypatch):
        """A NULL setting used to crash `'Tomorrow at ' + None`."""
        token = _auth_token(client)
        monkeypatch.setattr("dashboard.app.db.fetch_val", lambda *a, **k: None)

        rv = client.get(
            "/api/v2/config/schedule",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert rv.status_code == 200, rv.data[:300]
        assert rv.get_json() == {
            "frequency": "",
            "time": "02:00",
            "enabled": False,
            # A disabled/unknown schedule has no truthful next run.
            "next_run": None,
        }

    def test_next_run_estimate_is_only_returned_when_knowable(self):
        import datetime

        from dashboard.app import _next_run_estimate

        assert _next_run_estimate("daily", "02:00", False) is None
        assert _next_run_estimate("hourly", "02:00", True) is None
        assert _next_run_estimate("daily", "not-a-time", True) is None

        estimate = datetime.datetime.fromisoformat(
            _next_run_estimate("daily", "02:00", True))
        assert (estimate.hour, estimate.minute) == (2, 0)
        # The scheduler (AsyncIOScheduler) runs on the host clock, so the
        # estimate must carry the host's UTC offset — not a hardcoded UTC one.
        local_now = datetime.datetime.now().astimezone()
        assert estimate.utcoffset() == local_now.utcoffset()
        assert estimate > datetime.datetime.now(datetime.UTC)


class TestRetentionParsing:
    @pytest.mark.parametrize(
        "stored,expected",
        [
            (None, 30),
            ("not-a-number", 30),
            ("0", 30),
            ("-5", 30),
            ("99999", 30),
            ("45", 45),
        ],
    )
    def test_get_coerces_legacy_values(
            self, client, monkeypatch, stored, expected):
        token = _auth_token(client)
        monkeypatch.setattr("dashboard.app.db.fetch_val", lambda *a, **k: stored)

        rv = client.get(
            "/api/v2/system/retention",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert rv.status_code == 200, rv.data[:300]
        assert rv.get_json() == {"days": expected}


class TestPruneAgesIncompleteScans:
    """Retention must age scans that never got a finished_at.

    Cancelled/failed scans (and a crashed RUNNING row) have finished_at=NULL.
    Ageing on that column alone retained them forever; a stale RUNNING row also
    keeps `is_scanning` true and blocks new scan triggers indefinitely.
    """

    _SCHEMA = """
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY, scan_type TEXT, target TEXT,
            started_at REAL, finished_at REAL, hosts_found INTEGER DEFAULT 0,
            ports_found INTEGER DEFAULT 0, cves_found INTEGER DEFAULT 0,
            status TEXT, error TEXT);
        CREATE TABLE scan_diffs (
            id INTEGER PRIMARY KEY, scan_id INTEGER, diff_type TEXT, detail TEXT,
            severity TEXT DEFAULT 'INFO', created_at REAL DEFAULT 0);
        CREATE TABLE behavioral_events (id INTEGER PRIMARY KEY, ts REAL);
        CREATE TABLE anomalies (
            id INTEGER PRIMARY KEY, acknowledged INTEGER DEFAULT 0,
            detected_at REAL);
        CREATE TABLE system_settings (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY, ts REAL DEFAULT 0, actor TEXT, role TEXT,
            action TEXT, target TEXT, detail TEXT, ip TEXT,
            outcome TEXT DEFAULT 'success');
    """

    class _Adapter:
        def __init__(self, conn):
            self.conn = conn

        def fetch_val(self, sql, params=(), default=None):
            row = self.conn.execute(sql, params).fetchone()
            return row[0] if row else default

        def fetch_one(self, sql, params=()):
            row = self.conn.execute(sql, params).fetchone()
            return dict(row) if row else None

        def fetch_all(self, sql, params=()):
            rows = self.conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]

        def execute(self, sql, params=()):
            self.conn.execute(sql, params)
            self.conn.commit()

    def _db_with_old_scans(self):
        import time

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(self._SCHEMA)
        now = time.time()
        old = now - 40 * 86400
        conn.executemany(
            "INSERT INTO scans (id, scan_type, target, started_at, finished_at, status) "
            "VALUES (?, 'FULL', '10.0.0.0/24', ?, ?, ?)",
            [
                (1, old, old + 60, 'DONE'),
                (2, old, None, 'CANCELLED'),
                (3, old, None, 'FAILED'),
                (4, old, None, 'RUNNING'),
                (5, now, None, 'RUNNING'),
            ],
        )
        conn.executemany(
            "INSERT INTO scan_diffs (scan_id, diff_type, detail) VALUES (?, 'NEW_HOST', 'x')",
            [(1,), (2,), (3,), (4,), (5,)],
        )
        conn.commit()
        return conn

    def test_old_incomplete_and_stale_running_scans_are_pruned(
            self, client, monkeypatch):
        token = _auth_token(client)
        conn = self._db_with_old_scans()
        monkeypatch.setattr("dashboard.app.db", self._Adapter(conn))

        rv = client.post(
            "/api/v2/system/prune",
            json={"days": 30},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert rv.status_code == 200, rv.data[:300]
        assert rv.get_json()["deleted_scans"] == 4
        remaining = [r["id"] for r in conn.execute("SELECT id FROM scans ORDER BY id")]
        # Only the scan that started after the cutoff may survive.
        assert remaining == [5]
        diffs = [r["scan_id"] for r in conn.execute(
            "SELECT scan_id FROM scan_diffs ORDER BY scan_id")]
        assert diffs == [5]
        conn.close()


class TestPostureScoreScope:
    def test_dismissed_findings_do_not_lower_the_headline_score(self, monkeypatch):
        from dashboard.app import sync_calculate_global_posture

        captured = []

        def fetch_all(sql, params=()):
            captured.append(sql)
            if "risk_score" in sql:
                return [{"risk_score": 0.0}]
            return []

        monkeypatch.setattr("dashboard.app.db.fetch_all", fetch_all)
        monkeypatch.setattr("dashboard.app.db.fetch_val", lambda *a, **k: 0)

        assert sync_calculate_global_posture() == 100.0
        severity_sql = next(s for s in captured if "GROUP BY c.severity" in s)
        assert "pc.dismissed" in severity_sql
        assert "NOT_AFFECTED" in severity_sql
        assert "h.is_active" in severity_sql


class TestPdfExportScope:
    def test_pdf_queries_exclude_dismissed_and_retired_findings(self, client, monkeypatch):
        import weasyprint

        import dashboard.app as dash

        rv = client.post(
            "/api/v2/login",
            json={"username": "admin", "password": "obsidios123"},
        )
        headers = {"Authorization": f"Bearer {json.loads(rv.data)['token']}"}

        captured = []

        def fake_fetch_all(sql, params=()):
            captured.append(sql)
            return []

        monkeypatch.setattr(dash.db, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(dash.db, "fetch_val", lambda *a, **k: 0)
        monkeypatch.setattr(dash.db, "execute", lambda *a, **k: None)
        monkeypatch.setattr(
            weasyprint, "HTML",
            lambda **kw: type("FakeHTML", (), {
                "write_pdf": lambda self: b"%PDF-1.4 test"})(),
        )

        rv = client.post("/api/v2/export/pdf", headers=headers)
        assert rv.status_code == 200

        cve_queries = [q for q in captured if "FROM cves c" in q]
        assert cve_queries, "the report must query CVEs"
        for sql in cve_queries:
            assert "pc.dismissed" in sql
            assert "NOT_AFFECTED" in sql
            assert "h.is_active = 1" in sql


    def test_unknown_severity_does_not_break_the_report(self, client, monkeypatch):
        """INFO/NONE/NULL buckets are valid CVEs, not a reason to 500."""
        import weasyprint

        import dashboard.app as dash

        rv = client.post(
            "/api/v2/login",
            json={"username": "admin", "password": "obsidios123"},
        )
        headers = {"Authorization": f"Bearer {json.loads(rv.data)['token']}"}

        rendered = {}

        def fake_fetch_all(sql, params=()):
            if "GROUP BY c.severity" in sql:
                return [
                    {"severity": "INFO", "cnt": 2},
                    {"severity": None, "cnt": 1},
                    {"severity": "critical", "cnt": 3},
                ]
            return []

        def fake_fetch_val(sql, params=(), default=None):
            if "COUNT(*) FROM hosts" in sql:
                return 4
            if "COUNT(*) FROM cves" in sql:
                return 6
            if "attack_paths" in sql:
                return 1
            if "system_settings" in sql:
                return "10.0.0.0/24"
            return default

        class FakeHTML:
            def __init__(self, string=None):
                rendered["html"] = string

            def write_pdf(self):
                return b"%PDF-1.4 test"

        monkeypatch.setattr(dash.db, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(dash.db, "fetch_val", fake_fetch_val)
        monkeypatch.setattr(dash.db, "execute", lambda *a, **k: None)
        monkeypatch.setattr(weasyprint, "HTML", FakeHTML)

        rv = client.post("/api/v2/export/pdf", headers=headers)

        assert rv.status_code == 200, rv.data
        # Lowercase "critical" is still counted; INFO/NULL are ignored rather
        # than crashing the renderer.
        assert "3 critical" in rendered["html"]

    def test_unreadable_severity_count_does_not_abort_the_report(
            self, client, monkeypatch):
        """A legacy/junk COUNT column must not turn the export into a 500."""
        import weasyprint

        import dashboard.app as dash

        headers = {"Authorization": f"Bearer {_auth_token(client)}"}
        rendered = {}

        def fake_fetch_all(sql, params=()):
            if "GROUP BY c.severity" in sql:
                return [{"severity": "CRITICAL", "cnt": "not-a-number"}]
            return []

        def fake_fetch_val(sql, params=(), default=None):
            return default if default is not None else 0

        class FakeHTML:
            def __init__(self, string=None):
                rendered["html"] = string

            def write_pdf(self):
                return b"%PDF-1.4 test"

        monkeypatch.setattr(dash.db, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(dash.db, "fetch_val", fake_fetch_val)
        monkeypatch.setattr(dash.db, "execute", lambda *a, **k: None)
        monkeypatch.setattr(weasyprint, "HTML", FakeHTML)

        rv = client.post("/api/v2/export/pdf", headers=headers)

        assert rv.status_code == 200, rv.data
        assert "0 critical" in rendered["html"]


class TestSqlLiteralSafety:
    """SQLite's double-quoted-string fallback is not standard SQL."""

    def test_stats_uses_single_quoted_state_literal(self, client, monkeypatch):
        import dashboard.app as dash

        headers = {"Authorization": f"Bearer {_auth_token(client)}"}
        captured = []

        def fake_fetch_val(sql, params=(), default=None):
            captured.append(sql)
            return default if default is not None else 0

        def fake_fetch_all(sql, params=()):
            captured.append(sql)
            return []

        monkeypatch.setattr(dash.db, "fetch_val", fake_fetch_val)
        monkeypatch.setattr(dash.db, "fetch_all", fake_fetch_all)

        rv = client.get("/api/v2/stats", headers=headers)

        assert rv.status_code == 200, rv.data
        assert any("FROM ports" in sql for sql in captured)
        assert not any('state="open"' in sql for sql in captured)

    def test_exploit_status_binds_its_literal(self, client, monkeypatch):
        import dashboard.app as dash

        headers = {"Authorization": f"Bearer {_auth_token(client)}"}
        captured = []

        def fake_fetch_all(sql, params=()):
            captured.append((sql, params))
            return []

        monkeypatch.setattr(dash.db, "fetch_all", fake_fetch_all)

        rv = client.get("/api/v2/cves/exploit_status", headers=headers)

        assert rv.status_code == 200, rv.data
        sql, params = captured[-1]
        assert "THEORETICAL" not in sql
        assert params == ("THEORETICAL",)

    def test_exploit_status_excludes_dismissed_and_not_affected(self, client):
        """The endpoint is metadata-only, but it must not report a dismissed
        false positive as live exploitable exposure."""
        import uuid

        from chronicle import db as cdb
        from dashboard.app import run_async

        marker = f"10.252.{int(uuid.uuid4().hex[:2], 16)}.{int(uuid.uuid4().hex[2:4], 16)}"
        suffix = uuid.uuid4().hex[:8]
        ids = {
            "live": f"CVE-2026-{suffix}l",
            "dismissed": f"CVE-2026-{suffix}d",
            "not_affected": f"CVE-2026-{suffix}n",
        }
        state = {}

        async def setup():
            await cdb.init()
            await cdb.execute("DELETE FROM hosts WHERE ip=?", (marker,))
            host = await cdb.execute_returning(
                "INSERT INTO hosts (ip,is_active,risk_score,asset_value) "
                "VALUES (?,1,100,10) RETURNING id", (marker,))
            state["host_id"] = host["id"]
            port = await cdb.execute_returning(
                "INSERT INTO ports (host_id,port,protocol,state,service) "
                "VALUES (?,443,'tcp','open','https') RETURNING id", (host["id"],))
            for label, dismissed, verified in (
                ("live", 0, "CONFIRMED"),
                ("dismissed", 1, "CONFIRMED"),
                ("not_affected", 0, "NOT_AFFECTED"),
            ):
                cve = await cdb.execute_returning(
                    "INSERT INTO cves (cve_id,cvss_v3,severity) "
                    "VALUES (?,9.8,'CRITICAL') RETURNING id", (ids[label],))
                await cdb.execute(
                    "INSERT INTO port_cves "
                    "(port_id,cve_id,exploit_status,dismissed,verified_status) "
                    "VALUES (?,?,?,?,?)",
                    (port["id"], cve["id"], "PUBLIC_EXPLOIT", dismissed, verified))

        async def cleanup():
            await cdb.execute("DELETE FROM hosts WHERE id=?", (state["host_id"],))
            for cve_id in ids.values():
                await cdb.execute("DELETE FROM cves WHERE cve_id=?", (cve_id,))

        run_async(setup())
        try:
            rv = client.get(
                "/api/v2/cves/exploit_status",
                headers={"Authorization": f"Bearer {_auth_token(client)}"},
            )
            assert rv.status_code == 200, rv.data
            rows = [r for r in json.loads(rv.data)["data"] if r.get("ip") == marker]
            assert [r["cve_id"] for r in rows] == [ids["live"]]
        finally:
            run_async(cleanup())


class TestGraphEndpointResilience:
    """A corrupt cache/row must degrade the graph, never 500 the page."""

    @staticmethod
    def _auth(client):
        rv = client.post("/api/v2/login", json={
            "username": "admin", "password": "obsidios123"})
        return {"Authorization": f"Bearer {json.loads(rv.data)['token']}"}

    def test_corrupt_graph_cache_falls_back_to_live_hosts(self, client, monkeypatch):
        import dashboard.app as dash

        headers = self._auth(client)
        queries = []

        def fake_val(sql, params=(), default=None):
            if "graph_cache" in sql:
                return "{not valid json"
            return default

        def fake_all(sql, params=()):
            queries.append(sql)
            if "SELECT id, ip, risk_score, os_name, vendor FROM hosts" in sql:
                return [{"id": "10.0.0.5", "ip": "10.0.0.5",
                         "risk_score": 10, "os_name": "Linux", "vendor": None}]
            return []

        monkeypatch.setattr(dash.db, "fetch_val", fake_val)
        monkeypatch.setattr(dash.db, "fetch_all", fake_all)

        rv = client.get("/api/v2/graph", headers=headers)
        assert rv.status_code == 200, rv.data[:200]
        assert rv.get_json()["nodes"] == [
            {"id": "10.0.0.5", "risk": 10, "os": "Linux"}]
        assert any("FROM hosts" in q for q in queries)

    def test_cached_graph_nodes_with_bad_ids_are_skipped(self, client, monkeypatch):
        """A cache entry is untrusted JSON; one junk node used to 500 it."""
        import dashboard.app as dash

        headers = self._auth(client)
        queries = []

        def fake_val(sql, params=(), default=None):
            if "graph_cache" in sql:
                return json.dumps({"nodes": [
                    None,
                    "not-a-node",
                    {"id": 5},
                    {"id": "", "risk": 1},
                    {"id": "10.0.0.1", "risk": 9, "os": "Linux"},
                ]})
            return default

        def fake_all(sql, params=()):
            queries.append(sql)
            return []

        monkeypatch.setattr(dash.db, "fetch_val", fake_val)
        monkeypatch.setattr(dash.db, "fetch_all", fake_all)

        rv = client.get("/api/v2/graph", headers=headers)
        assert rv.status_code == 200, rv.data[:200]
        assert rv.get_json()["nodes"] == [
            {"id": "10.0.0.1", "risk": 9, "os": "Linux"}]
        assert not any(
            "SELECT id, ip, risk_score, os_name, vendor FROM hosts" in sql
            for sql in queries
        )

    def test_corrupt_path_json_is_skipped(self, client, monkeypatch):
        import dashboard.app as dash

        headers = self._auth(client)
        calls = {"n": 0}

        def fake_val(sql, params=(), default=None):
            if "graph_cache" in sql:
                return None
            if "MAX(simulated_at)" in sql:
                return 1234.0
            return default

        def fake_all(sql, params=()):
            if "SELECT id, ip, risk_score, os_name, vendor FROM hosts" in sql:
                return [
                    {"id": "10.0.0.1", "ip": "10.0.0.1", "risk_score": 5,
                     "os_name": "Linux", "vendor": None},
                    {"id": "10.0.0.2", "ip": "10.0.0.2", "risk_score": 5,
                     "os_name": "Linux", "vendor": None},
                ]
            if "path_json" in sql:
                calls["n"] += 1
                return [
                    {"path_json": "['truncated"},
                    {"path_json": json.dumps([
                        {"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}])},
                ]
            return []

        monkeypatch.setattr(dash.db, "fetch_val", fake_val)
        monkeypatch.setattr(dash.db, "fetch_all", fake_all)

        rv = client.get("/api/v2/graph", headers=headers)
        assert rv.status_code == 200, rv.data[:200]
        links = rv.get_json()["links"]
        assert {"source": "10.0.0.1", "target": "10.0.0.2",
                "type": "KILL_CHAIN"} in links

    def test_blast_radius_ignores_dismissed_and_not_affected(self, client, monkeypatch):
        import dashboard.app as dash

        headers = self._auth(client)
        captured = {}

        def fake_all(sql, params=()):
            if "SELECT id, ip, risk_score, os_name, vendor FROM hosts" in sql:
                return [{"id": "10.0.0.1", "ip": "10.0.0.1", "risk_score": 5,
                         "os_name": "Linux", "vendor": None}]
            if "FROM hosts h JOIN ports p" in sql:
                captured["critical_sql"] = sql
            return []

        monkeypatch.setattr(dash.db, "fetch_val", lambda *a, **k: None)
        monkeypatch.setattr(dash.db, "fetch_all", fake_all)

        rv = client.get("/api/v2/graph", headers=headers)
        assert rv.status_code == 200
        sql = captured["critical_sql"]
        assert "COALESCE(pc.dismissed,0)=0" in sql
        assert "NOT_AFFECTED" in sql
        assert "h.is_active=1" in sql


class TestNetworkStats:
    """The throughput panel must read the interface OBSIDIOS is watching."""

    @staticmethod
    def _auth(client):
        rv = client.post("/api/v2/login", json={
            "username": "admin", "password": "obsidios123"})
        return {"Authorization": f"Bearer {json.loads(rv.data)['token']}"}

    def test_capture_interface_is_configurable(self, monkeypatch):
        import dashboard.app as dash

        monkeypatch.delenv("OBSIDIOS_CAPTURE_IFACE", raising=False)
        assert dash._capture_iface() == "eth0"
        monkeypatch.setenv("OBSIDIOS_CAPTURE_IFACE", "enp3s0")
        assert dash._capture_iface() == "enp3s0"

    def test_net_dev_parsing_uses_the_real_column_layout(self, tmp_path):
        import dashboard.app as dash

        proc = tmp_path / "net_dev"
        proc.write_text(
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
            "enp3s0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"
        )
        stats = dash._parse_net_dev(str(proc))
        assert stats["enp3s0"] == {
            "rx_bytes": 1000, "rx_packets": 10,
            "tx_bytes": 2000, "tx_packets": 20,
        }

    def test_truncated_or_non_numeric_lines_are_skipped(self, tmp_path):
        import dashboard.app as dash

        proc = tmp_path / "net_dev"
        proc.write_text(
            "header\nheader\n"
            "eth0: 1 2\n"                       # too few columns
            "eth0: x 2 3 4 5 6 7 8 9 10 11\n"   # non-numeric
            "lo: 7 8 0 0 0 0 0 0 9 10 0 0 0 0 0 0\n"
        )
        assert dash._parse_net_dev(str(proc)) == {
            "lo": {"rx_bytes": 7, "rx_packets": 8,
                   "tx_bytes": 9, "tx_packets": 10},
        }

    def test_missing_proc_file_returns_empty_stats(self):
        import dashboard.app as dash

        assert dash._parse_net_dev("/nonexistent/proc/net/dev") == {}

    def test_endpoint_reports_configured_interface_not_eth0(
            self, client, monkeypatch):
        import dashboard.app as dash

        headers = self._auth(client)
        monkeypatch.setenv("OBSIDIOS_CAPTURE_IFACE", "enp3s0")
        monkeypatch.setattr(dash, "_net_prev", {})
        monkeypatch.setattr(dash, "_net_prev_time", 0)
        monkeypatch.setattr(dash, "_get_latency", lambda: 0.0)

        samples = iter([
            {"enp3s0": {"rx_bytes": 1000, "rx_packets": 100,
                        "tx_bytes": 2000, "tx_packets": 200},
             "eth0": {"rx_bytes": 9_000_000, "rx_packets": 900_000,
                      "tx_bytes": 9_000_000, "tx_packets": 900_000}},
            {"enp3s0": {"rx_bytes": 2024, "rx_packets": 108,
                        "tx_bytes": 3024, "tx_packets": 208},
             "eth0": {"rx_bytes": 9_000_000, "rx_packets": 900_000,
                      "tx_bytes": 9_000_000, "tx_packets": 900_000}},
        ])
        monkeypatch.setattr(dash, "_parse_net_dev", lambda *a, **k: next(samples))

        first = client.get("/api/network/stats", headers=headers)
        second = client.get("/api/network/stats", headers=headers)
        assert first.status_code == 200 and second.status_code == 200
        body = second.get_json()
        # 1024 rx + 1024 tx bytes over >= 0.5s, 8 packets each way.
        assert body["packets_per_sec"] == 32.0
        assert body["bytes_per_sec"] == 4096.0
        assert body["bandwidth_mbps"] == 0.03


class TestRunDashboardWiring:
    """The launch mode decides the bind address and Socket.IO worker model."""

    def _stub_init(self, dash, monkeypatch):
        def fake_run_async(coro, timeout=None):
            coro.close()
            return None

        monkeypatch.setattr(dash, "run_async", fake_run_async)

    def test_production_uses_one_gthread_worker(self, monkeypatch):
        import dashboard.app as dash

        self._stub_init(dash, monkeypatch)
        monkeypatch.setattr(dash, "_is_production", lambda: True)

        created = []

        class FakeCfg:
            def __init__(self):
                self.values = {}

            def set(self, key, value):
                self.values[key] = value

        class FakeBase:
            def __init__(self):
                self.cfg = FakeCfg()
                created.append(self)

            def run(self):
                # Gunicorn calls load_config() before serving.
                self.load_config()

        import gunicorn.app.base
        monkeypatch.setattr(gunicorn.app.base, "BaseApplication", FakeBase)

        dash.run_dashboard("127.0.0.1", 9000)

        assert created, "the dashboard must start a gunicorn application"
        cfg = created[0].cfg.values
        assert cfg["bind"] == "127.0.0.1:9000"
        assert cfg["worker_class"] == "gthread"
        # One worker keeps long-polling sessions sticky without a message queue.
        assert cfg["workers"] == 1
        assert cfg["threads"] == 8
        assert created[0].load() is dash.app

    def test_development_uses_the_werkzeug_server(self, monkeypatch):
        import dashboard.app as dash

        self._stub_init(dash, monkeypatch)
        monkeypatch.setattr(dash, "_is_production", lambda: False)
        calls = {}

        def fake_run(application, **kwargs):
            calls["app"] = application
            calls.update(kwargs)

        monkeypatch.setattr(dash.socketio, "run", fake_run)

        dash.run_dashboard("127.0.0.1", 9191)

        assert calls["app"] is dash.app
        assert calls["host"] == "127.0.0.1"
        assert calls["port"] == 9191
        assert calls["use_reloader"] is False

    def test_no_explicit_bind_uses_the_documented_settings(self, monkeypatch):
        """`python -m dashboard.app` must honour OBSIDIOS_DASH_HOST/PORT."""
        import dashboard.app as dash
        from config import settings as settings_mod

        self._stub_init(dash, monkeypatch)
        monkeypatch.setattr(dash, "_is_production", lambda: False)
        monkeypatch.setattr(settings_mod.dash, "host", "127.0.0.9")
        monkeypatch.setattr(settings_mod.dash, "port", 9292)
        calls = {}

        def fake_run(application, **kwargs):
            calls["app"] = application
            calls.update(kwargs)

        monkeypatch.setattr(dash.socketio, "run", fake_run)

        dash.run_dashboard()

        assert calls["host"] == "127.0.0.9"
        assert calls["port"] == 9292
