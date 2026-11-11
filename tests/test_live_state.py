"""Current-state semantics shared by the scanner, dashboard and ORACLE.

Historical rows stay in SQLite; a live view may only count a host, service,
path or prediction that still exists. These tests pin the predicates in
``chronicle/live_state.py`` and the scanner hook that retires paths when a
host disappears.
"""
from __future__ import annotations

import json
import time
import uuid

import pytest

from chronicle import db, live_state
from dashboard.app import run_async


def _ip() -> str:
    raw = uuid.uuid4().hex
    return f"10.253.{int(raw[:2], 16)}.{int(raw[2:4], 16)}"


def _steps(*ips: str) -> str:
    return json.dumps([{"ip": ip, "technique": "ssh"} for ip in ips])


class TestPathLiveness:
    def test_all_hops_active_is_live(self):
        assert live_state.path_is_live(
            _steps("10.0.0.1", "10.0.0.2"), {"10.0.0.1", "10.0.0.2"})

    def test_one_offline_hop_retires_the_path(self):
        assert not live_state.path_is_live(
            _steps("10.0.0.1", "10.0.0.2"), {"10.0.0.1"})

    @pytest.mark.parametrize("raw", [
        None,
        "",
        "not json",
        "{}",
        "[]",
        "[1, 2, 3]",
        '[{"ip": null}]',
        '[{"ip": 7}]',
        '[{"technique": "ssh"}]',
        '["10.0.0.1"]',
    ])
    def test_malformed_paths_are_not_live(self, raw):
        assert not live_state.path_is_live(raw, {"10.0.0.1"})


class TestAlertActionability:
    ACTIVE = {"10.0.0.1", "10.0.0.2"}

    def test_real_alerts_stay_actionable_until_acknowledged(self):
        assert live_state.alert_is_actionable(
            {"predicted": 0, "src_ip": "203.0.113.5", "dst_ip": "10.0.0.1"},
            self.ACTIVE, set())

    def test_prediction_on_a_dead_path_is_not_actionable(self):
        assert not live_state.alert_is_actionable(
            {"predicted": 1, "attack_path_id": 3,
             "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
            self.ACTIVE, {4})

    def test_prediction_needs_at_least_one_live_endpoint(self):
        assert not live_state.alert_is_actionable(
            {"predicted": 1, "attack_path_id": None,
             "src_ip": "10.9.9.9", "dst_ip": "10.8.8.8"},
            self.ACTIVE, set())
        assert live_state.alert_is_actionable(
            {"predicted": 1, "attack_path_id": None,
             "src_ip": "10.9.9.9", "dst_ip": "10.0.0.2"},
            self.ACTIVE, set())

    def test_live_prediction_is_actionable(self):
        assert live_state.alert_is_actionable(
            {"predicted": 1, "attack_path_id": 3,
             "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
            self.ACTIVE, {3})


class TestDatabaseLiveness:
    def test_retire_stale_paths_deactivates_paths_and_their_rules(self):
        active_ip, offline_ip = _ip(), _ip()
        sid_live = int(uuid.uuid4().int % 900_000_000) + 10_000_000
        sid_stale = sid_live + 1

        async def scenario():
            await db.init()
            active = await db.execute_returning(
                "INSERT INTO hosts (ip,is_active,last_seen) VALUES (?,1,?) "
                "RETURNING id", (active_ip, time.time()))
            offline = await db.execute_returning(
                "INSERT INTO hosts (ip,is_active,last_seen) VALUES (?,0,?) "
                "RETURNING id", (offline_ip, time.time() - 10_000))
            live_path = await db.execute_returning(
                "INSERT INTO attack_paths (path_json,is_active) VALUES (?,1) "
                "RETURNING id", (_steps(active_ip),))
            stale_path = await db.execute_returning(
                "INSERT INTO attack_paths (path_json,is_active) VALUES (?,1) "
                "RETURNING id", (_steps(active_ip, offline_ip),))
            await db.execute(
                "INSERT INTO forge_rules (rule_sid,attack_path_id,rule_text,"
                "rule_category,is_active) VALUES (?,?,?,?,1)",
                (sid_live, live_path["id"], "alert tcp any any -> any any (sid:1;)", "RECON"))
            await db.execute(
                "INSERT INTO forge_rules (rule_sid,attack_path_id,rule_text,"
                "rule_category,is_active) VALUES (?,?,?,?,1)",
                (sid_stale, stale_path["id"], "alert tcp any any -> any any (sid:2;)", "RECON"))
            try:
                retired = await live_state.retire_stale_attack_paths()
                live_state_flag = await db.fetch_val(
                    "SELECT is_active FROM attack_paths WHERE id=?",
                    (live_path["id"],))
                stale_state = await db.fetch_val(
                    "SELECT is_active FROM attack_paths WHERE id=?",
                    (stale_path["id"],))
                live_rule = await db.fetch_val(
                    "SELECT is_active FROM forge_rules WHERE rule_sid=?",
                    (sid_live,))
                stale_rule = await db.fetch_val(
                    "SELECT is_active FROM forge_rules WHERE rule_sid=?",
                    (sid_stale,))
                return (retired, live_state_flag, stale_state,
                        live_rule, stale_rule)
            finally:
                await db.execute(
                    "DELETE FROM forge_rules WHERE rule_sid IN (?,?)",
                    (sid_live, sid_stale))
                await db.execute(
                    "DELETE FROM attack_paths WHERE id IN (?,?)",
                    (live_path["id"], stale_path["id"]))
                await db.execute(
                    "DELETE FROM hosts WHERE id IN (?,?)",
                    (active["id"], offline["id"]))

        assert run_async(scenario()) == (1, 1, 0, 1, 0)

    def test_counts_ignore_dead_paths_and_stale_predictions(self):
        active_ip, offline_ip = _ip(), _ip()

        async def scenario():
            await db.init()
            active = await db.execute_returning(
                "INSERT INTO hosts (ip,is_active,last_seen) VALUES (?,1,?) "
                "RETURNING id", (active_ip, time.time()))
            offline = await db.execute_returning(
                "INSERT INTO hosts (ip,is_active,last_seen) VALUES (?,0,?) "
                "RETURNING id", (offline_ip, time.time() - 10_000))
            # An older database can still carry an active path whose host has
            # already gone offline; read-side predicates must catch it.
            stale_path = await db.execute_returning(
                "INSERT INTO attack_paths (path_json,is_active) VALUES (?,1) "
                "RETURNING id", (_steps(active_ip, offline_ip),))
            await db.execute(
                "INSERT INTO sentinel_alerts (src_ip,dst_ip,predicted,"
                "acknowledged,attack_path_id) VALUES (?,?,1,0,?)",
                (active_ip, offline_ip, stale_path["id"]))
            await db.execute(
                "INSERT INTO sentinel_alerts (src_ip,dst_ip,predicted,"
                "acknowledged) VALUES (?,?,1,0)",
                (offline_ip, "198.51.100.9"))
            await db.execute(
                "INSERT INTO sentinel_alerts (src_ip,dst_ip,predicted,"
                "acknowledged) VALUES (?,?,0,0)",
                (offline_ip, "198.51.100.9"))
            try:
                return (
                    await live_state.count_live_attack_paths(),
                    await live_state.count_actionable_alerts(),
                    await live_state.count_actionable_alerts(
                        include_acknowledged=True),
                )
            finally:
                await db.execute(
                    "DELETE FROM sentinel_alerts WHERE src_ip IN (?,?)",
                    (active_ip, offline_ip))
                await db.execute(
                    "DELETE FROM attack_paths WHERE id=?", (stale_path["id"],))
                await db.execute(
                    "DELETE FROM hosts WHERE id IN (?,?)",
                    (active["id"], offline["id"]))

        # No live path. Only the real alert is actionable; both predictions
        # point at a host that is gone.
        assert run_async(scenario()) == (0, 1, 1)

    def test_scanner_offline_transition_retires_paths_immediately(self):
        live_ip, gone_ip = _ip(), _ip()

        async def scenario():
            await db.init()
            live = await db.execute_returning(
                "INSERT INTO hosts (ip,is_active,last_seen) VALUES (?,1,?) "
                "RETURNING id", (live_ip, time.time()))
            gone = await db.execute_returning(
                "INSERT INTO hosts (ip,is_active,last_seen) VALUES (?,1,?) "
                "RETURNING id", (gone_ip, time.time() - 10_000))
            path = await db.execute_returning(
                "INSERT INTO attack_paths (path_json,is_active) VALUES (?,1) "
                "RETURNING id", (_steps(live_ip, gone_ip),))
            try:
                from iris import wired_scanner as wired
                moved = await wired._mark_missing_hosts_offline(
                    [live_ip], grace=60)
                state = await db.fetch_val(
                    "SELECT is_active FROM attack_paths WHERE id=?",
                    (path["id"],))
                return moved, state
            finally:
                await db.execute(
                    "DELETE FROM attack_paths WHERE id=?", (path["id"],))
                await db.execute(
                    "DELETE FROM hosts WHERE id IN (?,?)",
                    (live["id"], gone["id"]))

        assert run_async(scenario()) == (1, 0)


@pytest.fixture
def client():
    from dashboard.app import app

    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key-32-chars-minimum-ok!"
    with app.test_client() as client:
        yield client


def _headers(client) -> dict[str, str]:
    response = client.post(
        "/api/v2/login", json={"username": "admin", "password": "obsidios123"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


class TestDashboardEndpoints:
    def test_stats_paths_ports_and_alerts_ignore_stale_state(self, client):
        headers = _headers(client)
        baseline = client.get("/api/v2/stats", headers=headers).get_json()
        active_ip, offline_ip = _ip(), _ip()

        async def seed():
            await db.init()
            active = await db.execute_returning(
                "INSERT INTO hosts (ip,is_active,last_seen) VALUES (?,1,?) "
                "RETURNING id", (active_ip, time.time()))
            offline = await db.execute_returning(
                "INSERT INTO hosts (ip,is_active,last_seen) VALUES (?,0,?) "
                "RETURNING id", (offline_ip, time.time() - 10_000))
            active_port = await db.execute_returning(
                "INSERT INTO ports (host_id,port,protocol,state,service) "
                "VALUES (?,22,'tcp','open','ssh') RETURNING id",
                (active["id"],))
            offline_port = await db.execute_returning(
                "INSERT INTO ports (host_id,port,protocol,state,service) "
                "VALUES (?,443,'tcp','open','https') RETURNING id",
                (offline["id"],))
            cve_ids = []
            for suffix, severity in (("A", "CRITICAL"), ("B", "CRITICAL")):
                cve = await db.execute_returning(
                    "INSERT INTO cves (cve_id,cvss_v3,severity,description) "
                    "VALUES (?,9.8,?,'x') RETURNING id",
                    (f"CVE-2026-{uuid.uuid4().hex[:8]}{suffix}", severity))
                cve_ids.append(cve["id"])
            await db.execute(
                "INSERT INTO port_cves (port_id,cve_id,dismissed,verified_status) "
                "VALUES (?,?,0,'CONFIRMED')", (active_port["id"], cve_ids[0]))
            await db.execute(
                "INSERT INTO port_cves (port_id,cve_id,dismissed,verified_status) "
                "VALUES (?,?,0,'CONFIRMED')", (offline_port["id"], cve_ids[1]))
            live_path = await db.execute_returning(
                "INSERT INTO attack_paths (path_json,is_active) VALUES (?,1) "
                "RETURNING id", (_steps(active_ip),))
            stale_path = await db.execute_returning(
                "INSERT INTO attack_paths (path_json,is_active) VALUES (?,1) "
                "RETURNING id", (_steps(active_ip, offline_ip),))
            stale_alert = await db.execute_returning(
                "INSERT INTO sentinel_alerts (src_ip,dst_ip,predicted,"
                "acknowledged,attack_path_id) VALUES (?,?,1,0,?) RETURNING id",
                (active_ip, offline_ip, stale_path["id"]))
            real_alert = await db.execute_returning(
                "INSERT INTO sentinel_alerts (src_ip,dst_ip,severity,"
                "predicted,acknowledged,message) VALUES (?,?,1,0,0,'real') "
                "RETURNING id", (offline_ip, "198.51.100.9"))
            await db.execute(
                "INSERT INTO anomalies (host_id,anomaly_type,confidence) "
                "VALUES (?,'PORT_SCAN',0.9)", (active["id"],))
            await db.execute(
                "INSERT INTO anomalies (host_id,anomaly_type,confidence) "
                "VALUES (?,'PORT_SCAN',0.9)", (offline["id"],))
            return {
                "host_ids": (active["id"], offline["id"]),
                "cve_ids": cve_ids,
                "path_ids": (live_path["id"], stale_path["id"]),
                "alert_ids": (stale_alert["id"], real_alert["id"]),
                "live_steps": _steps(active_ip),
                "stale_steps": _steps(active_ip, offline_ip),
            }

        seeded = run_async(seed())
        try:
            after = client.get("/api/v2/stats", headers=headers).get_json()
            assert after["hosts"] == baseline["hosts"] + 1
            assert after["ports"] == baseline["ports"] + 1
            assert after["cves"] == baseline["cves"] + 1
            assert after["critical_cves"] == baseline["critical_cves"] + 1
            assert after["paths"] == baseline["paths"] + 1
            assert after["alerts"] == baseline["alerts"] + 1
            assert after["active_anomalies"] == baseline["active_anomalies"] + 1

            paths = client.get(
                "/api/v2/details/paths", headers=headers).get_json()["data"]
            path_jsons = [p["path_json"] for p in paths]
            assert seeded["live_steps"] in path_jsons
            assert seeded["stale_steps"] not in path_jsons

            ports = client.get(
                "/api/v2/details/ports?state=open", headers=headers
            ).get_json()["data"]
            assert active_ip in {p["ip"] for p in ports}
            assert offline_ip not in {p["ip"] for p in ports}

            alerts = client.get(
                "/api/v2/sentinel/alerts", headers=headers).get_json()["data"]
            by_id = {a["id"]: a for a in alerts}
            stale, real = seeded["alert_ids"]
            assert by_id[stale]["actionable"] is False
            assert by_id[stale]["dst_active"] is False
            assert by_id[real]["actionable"] is True
        finally:
            async def cleanup():
                await db.execute(
                    "DELETE FROM sentinel_alerts WHERE id IN (?,?)",
                    seeded["alert_ids"])
                await db.execute(
                    "DELETE FROM attack_paths WHERE id IN (?,?)",
                    seeded["path_ids"])
                await db.execute(
                    "DELETE FROM hosts WHERE id IN (?,?)",
                    seeded["host_ids"])
                for cve_id in seeded["cve_ids"]:
                    await db.execute("DELETE FROM cves WHERE id=?", (cve_id,))

            run_async(cleanup())

    def test_metrics_and_timeline_report_current_state(self, client,
                                                       monkeypatch):
        headers = _headers(client)
        # /metrics is unauthenticated; this test is about the numbers, not auth.
        monkeypatch.setenv("OBSIDIOS_METRICS_PUBLIC", "1")

        def metrics() -> dict[str, float]:
            body = client.get("/metrics").get_data(as_text=True)
            values = {}
            for line in body.splitlines():
                if line.startswith("obsidios_") and " " in line:
                    key, value = line.rsplit(" ", 1)
                    try:
                        values[key] = float(value)
                    except ValueError:
                        pass
            return values

        before = metrics()
        active_ip, offline_ip = _ip(), _ip()
        sid = int(uuid.uuid4().int % 900_000_000) + 10_000_000

        async def seed():
            await db.init()
            active = await db.execute_returning(
                "INSERT INTO hosts (ip,is_active,last_seen) VALUES (?,1,?) "
                "RETURNING id", (active_ip, time.time()))
            offline = await db.execute_returning(
                "INSERT INTO hosts (ip,is_active,last_seen) VALUES (?,0,?) "
                "RETURNING id", (offline_ip, time.time() - 10_000))
            active_port = await db.execute_returning(
                "INSERT INTO ports (host_id,port,protocol,state,service) "
                "VALUES (?,22,'tcp','open','ssh') RETURNING id",
                (active["id"],))
            offline_port = await db.execute_returning(
                "INSERT INTO ports (host_id,port,protocol,state,service) "
                "VALUES (?,443,'tcp','open','https') RETURNING id",
                (offline["id"],))
            cve_ids = []
            for suffix in ("A", "B"):
                cve = await db.execute_returning(
                    "INSERT INTO cves (cve_id,cvss_v3,severity,description) "
                    "VALUES (?,9.8,'CRITICAL','x') RETURNING id",
                    (f"CVE-2026-{uuid.uuid4().hex[:8]}{suffix}",))
                cve_ids.append(cve["id"])
            await db.execute(
                "INSERT INTO port_cves (port_id,cve_id,dismissed,verified_status) "
                "VALUES (?,?,0,'CONFIRMED')", (active_port["id"], cve_ids[0]))
            await db.execute(
                "INSERT INTO port_cves (port_id,cve_id,dismissed,verified_status) "
                "VALUES (?,?,0,'CONFIRMED')", (offline_port["id"], cve_ids[1]))
            live_path = await db.execute_returning(
                "INSERT INTO attack_paths (path_json,is_active) VALUES (?,1) "
                "RETURNING id", (_steps(active_ip),))
            stale_path = await db.execute_returning(
                "INSERT INTO attack_paths (path_json,is_active) VALUES (?,1) "
                "RETURNING id", (_steps(active_ip, offline_ip),))
            stale_alert = await db.execute_returning(
                "INSERT INTO sentinel_alerts (src_ip,dst_ip,predicted,"
                "acknowledged,attack_path_id) VALUES (?,?,1,0,?) RETURNING id",
                (active_ip, offline_ip, stale_path["id"]))
            forge = await db.execute_returning(
                "INSERT INTO forge_rules (rule_sid,rule_text,rule_category,"
                "is_active,delivered_at) VALUES (?,'alert','RECON',0,?) "
                "RETURNING id", (sid, time.time()))
            return {
                "host_ids": (active["id"], offline["id"]),
                "cve_ids": cve_ids,
                "path_ids": (live_path["id"], stale_path["id"]),
                "alert_id": stale_alert["id"],
                "forge_id": forge["id"],
            }

        seeded = run_async(seed())
        try:
            after = metrics()
            assert after["obsidios_hosts_active"] == before["obsidios_hosts_active"] + 1
            assert after["obsidios_open_ports"] == before["obsidios_open_ports"] + 1
            assert after["obsidios_cves_total"] == before["obsidios_cves_total"] + 1
            assert (after["obsidios_attack_paths_active"]
                    == before["obsidios_attack_paths_active"] + 1)

            timeline = client.get(
                "/api/v2/audit/timeline?limit=500", headers=headers).get_json()
            by_id = {(event["kind"], event["id"]): event
                     for event in timeline["data"]}
            assert by_id[("ALERT", seeded["alert_id"])]["status"] == "STALE"
            assert by_id[("FORGE", seeded["forge_id"])]["status"] == "RETIRED"
        finally:
            async def cleanup():
                await db.execute(
                    "DELETE FROM sentinel_alerts WHERE id=?",
                    (seeded["alert_id"],))
                await db.execute(
                    "DELETE FROM forge_rules WHERE rule_sid=?", (sid,))
                await db.execute(
                    "DELETE FROM attack_paths WHERE id IN (?,?)",
                    seeded["path_ids"])
                await db.execute(
                    "DELETE FROM hosts WHERE id IN (?,?)", seeded["host_ids"])
                for cve_id in seeded["cve_ids"]:
                    await db.execute("DELETE FROM cves WHERE id=?", (cve_id,))

            run_async(cleanup())
