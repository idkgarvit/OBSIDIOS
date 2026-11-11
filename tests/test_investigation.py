"""Tests for investigation workflows: host drill-down and unified audit timeline."""
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


class TestHostDetail:
    def test_requires_auth(self, client):
        assert client.get("/api/v2/details/host?ip=192.168.1.1").status_code == 401

    @pytest.mark.parametrize("bad", ["", "not-an-ip", "192.168.1.1' OR 1=1--", "999.1.1.1"])
    def test_rejects_invalid_ip(self, client, bad):
        h = _auth(client)
        rv = client.get(f"/api/v2/details/host?ip={bad}", headers=h)
        assert rv.status_code == 400

    def test_missing_host_returns_404(self, client, monkeypatch):
        h = _auth(client)
        monkeypatch.setattr("dashboard.app.db.fetch_one", lambda *a, **k: None)
        rv = client.get("/api/v2/details/host?ip=10.9.9.9", headers=h)
        assert rv.status_code == 404

    def test_returns_all_sections_and_scopes_queries(self, client, monkeypatch):
        h = _auth(client)
        monkeypatch.setattr(
            "dashboard.app.db.fetch_one",
            lambda *a, **k: {"id": 42, "ip": "10.0.0.5", "hostname": "web-01",
                             "risk_score": 8.5},
        )
        captured = []

        def fake_all(sql, params=()):
            captured.append((sql, params))
            if "FROM ports" in sql:
                return [{"port": 22, "protocol": "tcp", "state": "open",
                         "service": "ssh"}]
            if "FROM port_cves" in sql:
                return [{"cve_id": "CVE-2024-6387", "severity": "HIGH"}]
            if "FROM sentinel_alerts" in sql:
                return [{"id": 3, "src_ip": "10.0.0.5", "acknowledged": 0}]
            if "FROM shield_actions" in sql:
                return [{"id": 9, "target_ip": "10.0.0.5", "is_active": 1}]
            return []

        monkeypatch.setattr("dashboard.app.db.fetch_all", fake_all)
        rv = client.get("/api/v2/details/host?ip=10.0.0.5", headers=h)
        assert rv.status_code == 200
        d = json.loads(rv.data)
        assert set(d) == {"host", "ports", "cves", "alerts", "blocks"}
        assert d["host"]["id"] == 42
        assert d["ports"][0]["port"] == 22
        assert d["cves"][0]["cve_id"] == "CVE-2024-6387"
        assert d["alerts"][0]["id"] == 3
        assert d["blocks"][0]["id"] == 9
        # Every child query must be scoped to the resolved host, never global.
        assert len(captured) == 4
        for sql, params in captured:
            assert "10.0.0.5" not in sql          # parameterised, never interpolated
            assert params, f"unscoped query: {sql[:60]}"
        assert captured[0][1] == (42,)
        assert captured[1][1] == (42,)
        assert captured[2][1] == ("10.0.0.5", "10.0.0.5")
        assert captured[3][1] == ("10.0.0.5",)


class TestAuditTimeline:
    def test_requires_auth(self, client):
        assert client.get("/api/v2/audit/timeline").status_code == 401

    def test_merges_sources_newest_first(self, client, monkeypatch):
        h = _auth(client)
        rows = {
            "FROM scans": [
                {"id": 1, "scan_type": "FULL", "target": "10.0.0.0/24",
                 "started_at": 100.0, "finished_at": 120.0, "status": "DONE",
                 "hosts_found": 4, "ports_found": 12, "cves_found": 5},
            ],
            "FROM shield_actions": [
                {"id": 2, "taken_at": 300.0, "action_type": "BLOCK_IP",
                 "target_ip": "10.0.0.9", "target_port": None,
                 "rule_applied": "drop", "justification": "C2 beacon",
                 "is_active": 0},
            ],
            "FROM sentinel_alerts": [
                {"id": 3, "alerted_at": 200.0, "rule_sid": 9000001,
                 "src_ip": "10.0.0.7", "dst_ip": "10.0.0.8", "dst_port": 443,
                 "severity": 1, "message": "exploit attempt", "predicted": 0,
                 "acknowledged": 0},
            ],
            "FROM forge_rules": [
                {"id": 4, "created_at": 250.0, "rule_sid": 9000002,
                 "rule_category": "LATERAL", "mitre_technique": "T1021",
                 "is_deployed": 1, "is_active": 1, "delivered_at": 260.0},
            ],
        }

        def fake_all(sql, params=()):
            for marker, value in rows.items():
                if marker in sql:
                    return value
            return []

        monkeypatch.setattr("dashboard.app.db.fetch_all", fake_all)
        rv = client.get("/api/v2/audit/timeline?limit=50", headers=h)
        assert rv.status_code == 200
        d = json.loads(rv.data)
        assert d["count"] == 4
        assert [e["kind"] for e in d["data"]] == ["SHIELD", "FORGE", "ALERT", "SCAN"]
        by_kind = {e["kind"]: e for e in d["data"]}
        assert by_kind["SHIELD"]["status"] == "REVERTED"
        assert by_kind["SHIELD"]["host"] == "10.0.0.9"
        assert by_kind["FORGE"]["status"] == "DEPLOYED"
        assert by_kind["ALERT"]["status"] == "OPEN"
        assert by_kind["ALERT"]["severity"] == 1
        assert by_kind["SCAN"]["counts"] == {"hosts": 4, "ports": 12, "cves": 5}

    def test_limit_is_clamped(self, client, monkeypatch):
        h = _auth(client)
        seen = []

        def fake_all(sql, params=()):
            seen.append(params)
            return []

        monkeypatch.setattr("dashboard.app.db.fetch_all", fake_all)
        assert client.get("/api/v2/audit/timeline?limit=99999", headers=h).status_code == 200
        paged = [params for params in seen if params]
        assert paged and all(params == (500,) for params in paged)
        seen.clear()
        assert client.get("/api/v2/audit/timeline?limit=nonsense", headers=h).status_code == 200
        paged = [params for params in seen if params]
        assert paged and all(params == (100,) for params in paged)

    def test_null_rule_sid_gets_a_readable_title(self, client, monkeypatch):
        """A Suricata-native alert has no rule_sid; the feed must not say 'SID None'."""
        h = _auth(client)
        monkeypatch.setattr(
            "dashboard.app.db.fetch_all",
            lambda sql, params=(): [
                {"id": 7, "alerted_at": 200.0, "rule_sid": None,
                 "src_ip": "203.0.113.45", "dst_ip": "192.168.1.50", "dst_port": 22,
                 "severity": 2, "message": "ET SCAN Potential SSH Scan",
                 "predicted": 0, "acknowledged": 1}
            ] if "FROM sentinel_alerts" in sql else [],
        )
        rv = client.get("/api/v2/audit/timeline", headers=h)
        d = json.loads(rv.data)
        assert d["data"][0]["title"] == "Suricata alert"
        assert "None" not in d["data"][0]["title"]

    def test_non_numeric_timestamps_do_not_break_the_feed(self, client, monkeypatch):
        """Legacy rows may hold text timestamps; one must not 500 the feed."""
        h = _auth(client)
        monkeypatch.setattr(
            "dashboard.app.db.fetch_all",
            lambda sql, params=(): [
                {"id": 1, "scan_type": "FAST", "target": "t",
                 "started_at": "not-a-timestamp", "finished_at": None,
                 "status": "DONE", "hosts_found": 0, "ports_found": 0,
                 "cves_found": 0},
                {"id": 2, "scan_type": "FAST", "target": "t",
                 "started_at": 50.0, "finished_at": 51.0,
                 "status": "DONE", "hosts_found": 1, "ports_found": 2,
                 "cves_found": 3},
            ] if "FROM scans" in sql else [],
        )
        rv = client.get("/api/v2/audit/timeline", headers=h)
        assert rv.status_code == 200, rv.data[:200]
        assert [e["id"] for e in json.loads(rv.data)["data"]] == [2, 1]

    def test_events_cut_to_limit_after_merge(self, client, monkeypatch):
        h = _auth(client)
        many = [
            {"id": i, "scan_type": "FAST", "target": "t", "started_at": float(i),
             "finished_at": float(i) + 1, "status": "DONE",
             "hosts_found": 0, "ports_found": 0, "cves_found": 0}
            for i in range(10)
        ]
        monkeypatch.setattr(
            "dashboard.app.db.fetch_all",
            lambda sql, params=(): many if "FROM scans" in sql else [],
        )
        rv = client.get("/api/v2/audit/timeline?limit=3", headers=h)
        d = json.loads(rv.data)
        assert d["count"] == 3
        assert [e["ts"] for e in d["data"]] == [9.0, 8.0, 7.0]
