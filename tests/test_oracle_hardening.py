"""ORACLE hardening regressions: threat intelligence + TAGNN.

The threat-intel module must never report un-checked addresses as "clear", and
TAGNN must not duplicate a prediction on every run or crash on sparse data.
"""
import asyncio

import pytest

from oracle import tagnn
from oracle import threat_intel as ti


@pytest.fixture(autouse=True)
def _clean_feed(monkeypatch):
    """No test inherits another test's feed path, demo flag or cache."""
    monkeypatch.delenv("OBSIDIOS_THREAT_FEED_FILE", raising=False)
    monkeypatch.delenv("OBSIDIOS_THREAT_INTEL_DEMO", raising=False)
    ti._FEED_CACHE.update({"mtime": None, "path": None, "entries": {}})
    yield
    ti._FEED_CACHE.update({"mtime": None, "path": None, "entries": {}})


class TestFeedLoading:
    def test_demo_feed_is_opt_in(self):
        assert ti._load_feed() == {}
        ti.os.environ["OBSIDIOS_THREAT_INTEL_DEMO"] = "1"
        try:
            assert "10.0.0.1" in ti._load_feed()
        finally:
            del ti.os.environ["OBSIDIOS_THREAT_INTEL_DEMO"]

    def test_operator_feed_parses_scores_reputation_and_comments(self, tmp_path, monkeypatch):
        feed = tmp_path / "feed.txt"
        feed.write_text(
            "# operator blocklist\n"
            "203.0.113.9, 77, suspicious\n"
            "198.51.100.4\n"
            "not-an-ip, 50\n"
            "192.0.2.7, not-a-score, scanner\n"
        )
        monkeypatch.setenv("OBSIDIOS_THREAT_FEED_FILE", str(feed))

        entries = ti._load_feed()
        assert entries["203.0.113.9"] == {
            "score": 77, "reputation": "suspicious", "threats": ["blocklist_match"],
        }
        assert entries["198.51.100.4"]["score"] == 90
        assert entries["198.51.100.4"]["reputation"] == "malicious"
        assert entries["192.0.2.7"]["score"] == 90
        assert entries["192.0.2.7"]["reputation"] == "scanner"
        assert "not-an-ip" not in entries

    def test_scores_are_clamped(self, tmp_path, monkeypatch):
        feed = tmp_path / "feed.txt"
        feed.write_text("203.0.113.9,999\n198.51.100.4,-5\n")
        monkeypatch.setenv("OBSIDIOS_THREAT_FEED_FILE", str(feed))
        entries = ti._load_feed()
        assert entries["203.0.113.9"]["score"] == 100
        assert entries["198.51.100.4"]["score"] == 0

    def test_feed_is_re_read_when_it_changes(self, tmp_path, monkeypatch):
        feed = tmp_path / "feed.txt"
        feed.write_text("203.0.113.9\n")
        monkeypatch.setenv("OBSIDIOS_THREAT_FEED_FILE", str(feed))
        assert "203.0.113.9" in ti._load_feed()

        feed.write_text("203.0.113.10\n")
        # Force a different mtime regardless of filesystem timestamp granularity.
        stat = feed.stat()
        ti.os.utime(feed, (stat.st_atime, stat.st_mtime + 10))
        entries = ti._load_feed()
        assert "203.0.113.10" in entries
        assert "203.0.113.9" not in entries

    def test_missing_feed_file_is_empty_not_fatal(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_THREAT_FEED_FILE", str(tmp_path / "nope.txt"))
        assert ti._load_feed() == {}


class TestCheckThreatIntel:
    def test_duplicates_and_invalid_inputs_are_accounted_for(self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_THREAT_INTEL_DEMO", "1")
        result = asyncio.run(ti.check_threat_intel(
            ["10.0.0.1", "10.0.0.1", "not-an-ip", None, "10.0.0.7"]
        ))
        assert result["total_checked"] == 2
        assert result["threats_found"] == 1
        assert result["clear"] == 1
        assert result["invalid"] == 2
        assert result["results"][0]["ip"] == "10.0.0.1"
        assert result["results"][0]["action_required"] is True

    def test_empty_and_none_input(self):
        for value in ([], None):
            result = asyncio.run(ti.check_threat_intel(value))
            assert result["total_checked"] == 0
            assert result["invalid"] == 0
            assert result["clear"] == 0

    def test_ipv6_is_normalized(self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_THREAT_INTEL_DEMO", "1")
        result = asyncio.run(ti.check_threat_intel(["2001:DB8::1"]))
        assert result["total_checked"] == 1
        assert result["invalid"] == 0


def _threat_row(**overrides):
    row = {
        "ip": "10.44.0.5", "service": "ssh", "version": "8.2",
        "port": 22, "protocol": "tcp", "cve_id": "CVE-2024-0001",
        "cvss_v3": 9.8, "severity": "CRITICAL",
    }
    row.update(overrides)
    return row


class TestServiceThreats:
    def test_findings_group_by_endpoint(self, monkeypatch):
        class FakeDB:
            async def fetch_all(self, _sql, params=()):
                return [
                    _threat_row(),
                    _threat_row(cve_id="CVE-2024-0002", severity="HIGH", cvss_v3=8.1),
                    _threat_row(ip="10.44.0.6", port=443, protocol="tcp",
                                service="https", cve_id="CVE-2024-0003",
                                severity="HIGH", cvss_v3=7.5),
                ]

        monkeypatch.setattr(ti, "db", FakeDB())
        result = asyncio.run(ti.check_service_threats())
        assert result["service_count"] == 2
        assert result["vulnerable_services"] == 2
        ssh = next(f for f in result["findings"] if f["port"] == 22)
        assert ssh["risk"] == "HIGH"
        assert ssh["known_exploits"] == ["CVE-2024-0001", "CVE-2024-0002"]
        https = next(f for f in result["findings"] if f["port"] == 443)
        assert https["risk"] == "MEDIUM"

    def test_known_exploits_are_capped(self, monkeypatch):
        class FakeDB:
            async def fetch_all(self, _sql, params=()):
                return [
                    _threat_row(cve_id=f"CVE-2024-{i:04d}", severity="HIGH")
                    for i in range(1, 9)
                ]

        monkeypatch.setattr(ti, "db", FakeDB())
        result = asyncio.run(ti.check_service_threats())
        assert len(result["findings"]) == 1
        assert len(result["findings"][0]["known_exploits"]) == 5


class TestThreatSummary:
    def test_summary_uses_real_counts(self, monkeypatch):
        class FakeDB:
            async def fetch_val(self, sql, params=(), default=None):
                if "hosts" in sql:
                    return 4
                if "ports" in sql:
                    return 9
                return 3

        monkeypatch.setattr(ti, "db", FakeDB())
        monkeypatch.setattr(ti, "_load_feed", lambda: {"203.0.113.9": {}})
        summary = asyncio.run(ti.get_threat_summary())
        assert summary["network_size"] == 4
        assert summary["exposed_services"] == 9
        assert summary["feed_entries"] == 1
        assert summary["feed_configured"] is False
        assert summary["threat_level"] == "MEDIUM"


class FakeTagnnDB:
    def __init__(self, hosts, ports, existing=None, insert_id=5):
        self.hosts = hosts
        self.ports = ports
        self.existing = existing
        self.insert_id = insert_id
        self.executed = []
        self.inserted = []
        self.fetched = []

    async def fetch_all(self, sql, params=()):
        if "FROM hosts" in sql:
            return self.hosts
        if "FROM ports" in sql:
            return self.ports
        return []

    async def fetch_one(self, sql, params=()):
        self.fetched.append((sql, params))
        return self.existing

    async def execute(self, sql, params=()):
        self.executed.append((sql, params))

    async def execute_returning(self, sql, params=()):
        self.inserted.append((sql, params))
        return {"id": self.insert_id} if self.insert_id else None


def _host(id_, ip, risk=1.0, value=1.0):
    return {"id": id_, "ip": ip, "risk_score": risk, "asset_value": value}


def _port(host_id, port):
    return {"host_id": host_id, "port": port, "service": "ssh"}


class TestTagnn:
    def test_predictions_are_persisted(self, monkeypatch):
        hosts = [
            _host(1, "10.44.0.1", value=1.0),
            _host(2, "10.44.0.2", value=9.0),
            _host(3, "10.44.0.3", value=5.0),
        ]
        ports = [_port(2, 22), _port(2, 445), _port(3, 443)]
        fake = FakeTagnnDB(hosts, ports)
        monkeypatch.setattr(tagnn, "db", fake)
        monkeypatch.setenv("OBSIDIOS_GATEWAY", "192.168.1.1")

        predictions = asyncio.run(tagnn.run_tagnn_prediction())
        assert predictions
        assert {p["target"] for p in predictions} == {"10.44.0.2", "10.44.0.3"}
        assert all("TAGNN" in p["narrative"] for p in predictions)
        assert fake.inserted
        assert any("INSERT INTO attack_paths" in sql for sql, _ in fake.inserted)

    def test_gateway_is_never_a_target(self, monkeypatch):
        hosts = [
            _host(1, "192.168.1.1", value=100.0),
            _host(2, "10.44.0.2", value=9.0),
            _host(3, "10.44.0.3", value=8.0),
        ]
        ports = [_port(1, 22), _port(2, 22), _port(3, 22)]
        monkeypatch.setattr(tagnn, "db", FakeTagnnDB(hosts, ports))
        monkeypatch.setenv("OBSIDIOS_GATEWAY", "192.168.1.1")

        predictions = asyncio.run(tagnn.run_tagnn_prediction())
        assert predictions
        assert all(p["target"] != "192.168.1.1" for p in predictions)
        assert any(p["entry"] == "192.168.1.1" for p in predictions)

    def test_existing_prediction_is_refreshed_not_duplicated(self, monkeypatch):
        hosts = [
            _host(1, "10.44.0.1", value=1.0),
            _host(2, "10.44.0.2", value=9.0),
        ]
        ports = [_port(2, 22)]
        fake = FakeTagnnDB(hosts, ports, existing={"id": 42})
        monkeypatch.setattr(tagnn, "db", fake)
        monkeypatch.setenv("OBSIDIOS_GATEWAY", "192.168.1.1")

        asyncio.run(tagnn.run_tagnn_prediction())
        assert fake.inserted == []
        assert any("UPDATE attack_paths" in sql and "simulated_at" in sql
                   for sql, _ in fake.executed)

    def test_all_predictions_retired_when_none_persist(self, monkeypatch):
        hosts = [
            _host(1, "10.44.0.1"),
            _host(2, "10.44.0.2", value=9.0),
        ]
        ports = [_port(2, 22)]
        fake = FakeTagnnDB(hosts, ports, insert_id=None)
        monkeypatch.setattr(tagnn, "db", fake)
        monkeypatch.setenv("OBSIDIOS_GATEWAY", "192.168.1.1")

        asyncio.run(tagnn.run_tagnn_prediction())
        retire = [(sql, params) for sql, params in fake.executed
                  if "is_active=0" in sql and "TAGNN" in sql]
        assert retire
        assert "NOT IN" not in retire[-1][0]

    def test_sparse_data_does_not_crash(self, monkeypatch):
        hosts = [
            {"id": 1, "ip": "10.44.0.1", "risk_score": None, "asset_value": None},
            {"id": 2, "ip": "10.44.0.2", "risk_score": None, "asset_value": None},
        ]
        fake = FakeTagnnDB(hosts, [_port(2, 22)])
        monkeypatch.setattr(tagnn, "db", fake)
        predictions = asyncio.run(tagnn.run_tagnn_prediction())
        assert isinstance(predictions, list)

    def test_single_host_returns_empty(self, monkeypatch):
        fake = FakeTagnnDB([_host(1, "10.44.0.1")], [])
        monkeypatch.setattr(tagnn, "db", fake)
        assert asyncio.run(tagnn.run_tagnn_prediction()) == []
        assert fake.executed == []
