"""Posture, compliance and attacker-view regressions.

All three are operator-facing judgement calls: dismissing a false positive or
retiring a host must improve the score, and an HTTPS service must not have an
empty attack playbook just because it has its own dictionary key.
"""
import asyncio

from dashboard.app import run_async
from oracle import attacker_view
from oracle.compliance_mapper import map_compliance
from oracle.posture_score import (
    _calculate_exposure_score,
    _calculate_patch_score,
    calculate_posture_score,
)

HOST = "10.9.9.9"
PORT = 443


async def _seed(host_active=1, dismissed=0, verified="UNVERIFIED", severity="CRITICAL"):
    from chronicle import db

    await db.init()
    await db.execute("DELETE FROM hosts WHERE ip=?", (HOST,))
    await db.execute("DELETE FROM cves WHERE cve_id=?", ("CVE-2026-9999",))
    await db.execute(
        "INSERT INTO hosts (ip, hostname, os_name, is_active, risk_score)"
        " VALUES (?,?,?,?,?)",
        (HOST, "demo", "Linux", host_active, 80.0),
    )
    host_id = await db.fetch_val("SELECT id FROM hosts WHERE ip=?", (HOST,))
    await db.execute(
        "INSERT INTO ports (host_id, port, protocol, state, service)"
        " VALUES (?,?,?,?,?)",
        (host_id, PORT, "tcp", "open", "https"),
    )
    port_id = await db.fetch_val(
        "SELECT id FROM ports WHERE host_id=? AND port=?", (host_id, PORT)
    )
    await db.execute(
        "INSERT INTO cves (cve_id, cvss_v3, severity) VALUES (?,?,?)",
        ("CVE-2026-9999", 9.8, severity),
    )
    cve_id = await db.fetch_val(
        "SELECT id FROM cves WHERE cve_id=?", ("CVE-2026-9999",)
    )
    await db.execute(
        "INSERT INTO port_cves (port_id, cve_id, dismissed, verified_status)"
        " VALUES (?,?,?,?)",
        (port_id, cve_id, dismissed, verified),
    )
    return host_id, port_id, cve_id


async def _cleanup():
    from chronicle import db

    await db.execute("DELETE FROM hosts WHERE ip=?", (HOST,))
    await db.execute("DELETE FROM cves WHERE cve_id=?", ("CVE-2026-9999",))


class TestPatchScore:
    """Assertions are deltas: the shared test DB may hold other findings."""

    @staticmethod
    def _delta(seed_kwargs):
        async def scenario():
            from chronicle import db

            await db.init()
            await _cleanup()
            before = await _calculate_patch_score()
            await _seed(**seed_kwargs)
            try:
                after = await _calculate_patch_score()
            finally:
                await _cleanup()
            return before, after

        return run_async(scenario())

    def test_critical_cve_on_a_live_host_lowers_the_score(self):
        before, after = self._delta({})
        assert after["critical_cves"] == before["critical_cves"] + 1
        assert after["score"] < before["score"]

    def test_dismissed_cve_is_not_counted(self):
        before, after = self._delta({"dismissed": 1})
        assert after == before

    def test_not_affected_verdict_is_not_counted(self):
        before, after = self._delta({"verified": "NOT_AFFECTED"})
        assert after == before

    def test_cve_on_retired_host_is_not_counted(self):
        before, after = self._delta({"host_active": 0})
        assert after == before


class TestExposureScore:
    def test_ports_on_retired_hosts_do_not_count(self):
        async def scenario():
            from chronicle import db

            await db.init()
            await db.execute("DELETE FROM hosts WHERE ip=?", (HOST,))
            before = await _calculate_exposure_score()
            await db.execute("INSERT INTO hosts (ip, is_active) VALUES (?,0)", (HOST,))
            host_id = await db.fetch_val("SELECT id FROM hosts WHERE ip=?", (HOST,))
            for port in (1, 2, 3, 4, 5, 6, 7, 8):
                await db.execute(
                    "INSERT INTO ports (host_id, port, state, service) VALUES (?,?,'open','http')",
                    (host_id, port),
                )
            try:
                return before, await _calculate_exposure_score()
            finally:
                await db.execute("DELETE FROM hosts WHERE ip=?", (HOST,))

        before, after = run_async(scenario())
        assert after["exposed_services"] == before["exposed_services"]
        assert after["score"] == before["score"]

    def test_open_port_on_a_live_host_counts(self):
        async def scenario():
            await _seed()
            try:
                return await _calculate_exposure_score()
            finally:
                await _cleanup()

        result = run_async(scenario())
        assert result["exposed_services"] >= 1
        assert result["score"] < 100


class TestCompliance:
    ISSUE = "CRITICAL-severity vulnerabilities unpatched"

    @classmethod
    def _count(cls, result):
        assert "error" not in result, result
        return sum(
            1 for finding in result["findings"]
            if any(cls.ISSUE in issue for issue in finding["issues"])
        )

    def _delta(self, seed_kwargs):
        async def scenario():
            from chronicle import db

            await db.init()
            await _cleanup()
            before = await map_compliance("PCI-DSS")
            await _seed(**seed_kwargs)
            try:
                after = await map_compliance("PCI-DSS")
            finally:
                await _cleanup()
            return self._count(before), self._count(after)

        return run_async(scenario())

    def test_dismissed_cve_does_not_force_non_compliance(self):
        before, after = self._delta({"dismissed": 1})
        assert after == before

    def test_undismissed_critical_cve_is_reported(self):
        before, after = self._delta({})
        assert after > before

    def test_unknown_framework_is_rejected(self):
        result = run_async(map_compliance("NOT-A-FRAMEWORK"))
        assert "error" in result


class TestAttackerView:
    def test_https_gets_the_http_playbook(self):
        assert attacker_view.get_attacks_for_service("https", 443) == \
            attacker_view.get_attacks_for_service("http", 80)

    def test_bacnet_is_mapped(self):
        assert attacker_view.get_attacks_for_service("bacnet", 47808)

    def test_port_fallback_still_works_for_unknown_names(self):
        assert attacker_view.get_attacks_for_service("", 3389)

    def test_unknown_service_and_port_has_no_playbook(self):
        assert attacker_view.get_attacks_for_service("gopher", 70) == []

    def test_attacker_view_uses_live_hosts_only(self):
        async def scenario():
            await _seed(host_active=0)
            try:
                return await attacker_view.generate_attacker_view()
            finally:
                await _cleanup()

        result = run_async(scenario())
        assert all(f["ip"] != HOST for f in result["findings"])


class TestPostureRoundTrip:
    def test_score_is_bounded_and_recorded(self):
        async def scenario():
            from chronicle import db

            await _seed()
            try:
                return await calculate_posture_score()
            finally:
                await db.execute(
                    "DELETE FROM posture_scores WHERE id="
                    " (SELECT MAX(id) FROM posture_scores)"
                )
                await _cleanup()

        result = run_async(scenario())
        assert 0 <= result["overall_score"] <= 100
        assert result["risk_level"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert set(result["breakdown"]) >= {"patch_status", "wireless", "osint"}


class TestAttackerViewBatching:
    """Both builders must issue one query, not one per host.

    The old implementation ran a port query inside a loop over hosts, so a
    large scan serialised thousands of round-trips on the dashboard's single
    background DB loop.
    """

    class FakeDB:
        def __init__(self, rows):
            self.rows = rows
            self.queries = []

        async def fetch_all(self, sql, params=()):
            self.queries.append(sql)
            return self.rows

    def test_anomalous_ports_issues_one_query(self, monkeypatch):
        rows = [
            {"host_id": 1, "ip": "10.0.0.10", "hostname": "web",
             "os_name": "Linux", "port": 80, "protocol": "tcp",
             "service": "http"},
            {"host_id": 1, "ip": "10.0.0.10", "hostname": "web",
             "os_name": "Linux", "port": 4444, "protocol": "tcp",
             "service": None},
            {"host_id": 2, "ip": "10.0.0.11", "hostname": "quiet",
             "os_name": None, "port": None, "protocol": None,
             "service": None},
        ]
        fake = self.FakeDB(rows)
        monkeypatch.setattr(attacker_view, "db", fake)

        result = asyncio.run(attacker_view.get_anomalous_ports())
        assert len(fake.queries) == 1, "must not query per host"
        assert len(result) == 1
        entry = result[0]
        assert entry["ip"] == "10.0.0.10"
        assert entry["detected_type"] == ["web_server"]
        # 80 is universally expected; 4444 is not part of the web profile.
        assert [p["port"] for p in entry["anomalous_ports"]] == [4444]
        assert entry["anomalous_ports"][0]["service"] is None

    def test_attacker_view_issues_one_query_and_counts_empty_hosts(
            self, monkeypatch):
        rows = [
            {"host_id": 1, "ip": "10.0.0.10", "hostname": "web",
             "os_name": "Linux", "risk_score": 80, "port": 22,
             "protocol": "tcp", "service": "ssh"},
            {"host_id": 1, "ip": "10.0.0.10", "hostname": "web",
             "os_name": "Linux", "risk_score": 80, "port": 3306,
             "protocol": "tcp", "service": "mysql"},
            {"host_id": 2, "ip": "10.0.0.11", "hostname": None,
             "os_name": None, "risk_score": None, "port": None,
             "protocol": None, "service": None},
        ]
        fake = self.FakeDB(rows)
        monkeypatch.setattr(attacker_view, "db", fake)
        monkeypatch.setattr(attacker_view, "_get_local_ips", lambda: set())

        result = asyncio.run(attacker_view.generate_attacker_view())
        assert len(fake.queries) == 1, "must not query per host"
        # A host with no open ports is still a discoverable host.
        assert result["total_hosts"] == 2
        finding = next(f for f in result["findings"] if f["ip"] == "10.0.0.10")
        assert {a["port"] for a in finding["attacks"]} == {22, 3306}
        assert result["total_techniques"] == 7   # ssh 4 + mysql 3

    def test_admin_ports_are_skipped_only_on_the_sensor_itself(
            self, monkeypatch):
        rows = [
            {"host_id": 1, "ip": "127.0.0.1", "hostname": "sensor",
             "os_name": "Linux", "risk_score": 10, "port": 8080,
             "protocol": "tcp", "service": "http"},
            {"host_id": 1, "ip": "127.0.0.1", "hostname": "sensor",
             "os_name": "Linux", "risk_score": 10, "port": 22,
             "protocol": "tcp", "service": "ssh"},
            {"host_id": 2, "ip": "10.0.0.10", "hostname": "remote",
             "os_name": "Linux", "risk_score": 90, "port": 8080,
             "protocol": "tcp", "service": "http"},
        ]
        fake = self.FakeDB(rows)
        monkeypatch.setattr(attacker_view, "db", fake)
        monkeypatch.setattr(attacker_view, "_get_local_ips",
                            lambda: {"127.0.0.1"})

        result = asyncio.run(attacker_view.generate_attacker_view())
        local = next(f for f in result["findings"] if f["ip"] == "127.0.0.1")
        remote = next(f for f in result["findings"] if f["ip"] == "10.0.0.10")
        assert {a["port"] for a in local["attacks"]} == {22}
        assert local["is_local_machine"] is True
        assert {a["port"] for a in remote["attacks"]} == {8080}
        assert remote["is_local_machine"] is False

    def test_summary_order_is_stable_for_tied_counts(self, monkeypatch):
        rows = [
            {"host_id": 1, "ip": "10.0.0.10", "hostname": None,
             "os_name": None, "risk_score": 1, "port": 22,
             "protocol": "tcp", "service": "ssh"},
        ]
        monkeypatch.setattr(attacker_view, "db", self.FakeDB(rows))
        monkeypatch.setattr(attacker_view, "_get_local_ips", lambda: set())

        first = asyncio.run(attacker_view.generate_attacker_view())["summary"]
        second = asyncio.run(attacker_view.generate_attacker_view())["summary"]
        assert first == second
        assert "4 possible attack techniques" in first
