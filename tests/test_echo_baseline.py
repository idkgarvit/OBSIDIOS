"""ECHO baseline learning and public-API regressions.

A legacy baseline row with non-numeric aggregates must not stop a host from
learning, and the anomaly pipeline must persist/auto-respond correctly.
"""
import asyncio
import json
import time

import scapy.all as scapy
from scapy.all import ARP, IP, TCP, Ether

from chronicle import db
from chronicle.models import Anomaly, AnomalyType, BehavioralEvent
from config import settings as settings_module
from dashboard.app import run_async
from echo import drift_detector as dd


def _event(**overrides):
    return BehavioralEvent(host_id=0, **overrides)


class TestResolveNetwork:
    def test_explicit_network_is_parsed(self):
        assert str(dd._resolve_network("10.44.0.0/24")) == "10.44.0.0/24"

    def test_invalid_network_is_rejected(self):
        assert dd._resolve_network("not-a-network") is None

    def test_none_uses_the_configured_target(self, monkeypatch):
        monkeypatch.setattr(settings_module.scan, "target_network", "10.9.0.0/16")
        assert str(dd._resolve_network(None)) == "10.9.0.0/16"

    def test_unconfigured_target_tracks_nothing(self, monkeypatch):
        monkeypatch.setattr(settings_module.scan, "target_network", "")
        assert dd._resolve_network(None) is None


class TestCollectorEdges:
    def test_invalid_ip_is_not_local(self):
        collector = dd.PacketCollector(network="10.44.0.0/24")
        assert collector._is_local("not-an-ip") is False

    def test_no_network_tracks_no_hosts(self):
        collector = dd.PacketCollector(network=None)
        assert collector._is_local("10.44.0.1") is False

    def test_non_ip_packet_is_ignored(self):
        collector = dd.PacketCollector(network="10.44.0.0/24")
        collector._process_packet(Ether() / ARP())
        assert collector.get_window_snapshot() == {}

    def test_capture_uses_the_requested_duration(self, monkeypatch):
        calls = []

        def fake_sniff(**kwargs):
            calls.append(kwargs)

        monkeypatch.setattr(scapy, "sniff", fake_sniff)
        collector = dd.PacketCollector(network="10.44.0.0/24")
        collector.start_capture(7)

        assert calls[0]["timeout"] == 7
        assert calls[0]["iface"] == dd.DEFAULT_IFACE
        assert calls[0]["store"] is False
        assert collector._running is False

    def test_capture_failure_clears_running_flag(self, monkeypatch):
        def broken_sniff(**_kwargs):
            raise OSError("interface disappeared")

        monkeypatch.setattr(scapy, "sniff", broken_sniff)
        collector = dd.PacketCollector(network="10.44.0.0/24")
        collector.start_capture(1)
        assert collector._running is False


class RecordingBaselineDB:
    def __init__(self, row):
        self.row = row
        self.written = []

    async def fetch_one(self, *_a, **_k):
        return self.row

    async def execute_returning(self, sql, params=()):
        self.written.append((sql, params))
        return {"id": 1}


class TestBaselineUpdates:
    def test_first_observation_creates_the_baseline(self, monkeypatch):
        fake = RecordingBaselineDB(None)
        monkeypatch.setattr(dd, "db", fake)

        event = _event(ts=time.time(), bytes_in=10, bytes_out=20,
                       sessions=2, peers=["10.44.0.2"],
                       protocols={"tcp": 3})
        asyncio.run(dd._update_baseline(1, event))

        sql, params = fake.written[0]
        assert "INSERT INTO behavioral_baselines" in sql
        assert params[0] == 1                 # host_id
        assert params[14] == 1                # sample_count
        assert json.loads(params[10]) == ["10.44.0.2"]
        assert json.loads(params[11]) == {"tcp": 3}

    def test_legacy_string_aggregates_do_not_block_learning(self, monkeypatch):
        fake = RecordingBaselineDB({
            "host_id": 1, "sample_count": "3",
            "bytes_in_mean": "10", "bytes_in_std": "1",
            "bytes_out_mean": "20", "bytes_out_std": "2",
            "session_count_mean": "1", "session_count_std": "0",
            "active_hours_bitmap": "1", "peer_set_json": '["10.44.0.2"]',
            "protocol_dist_json": '{"tcp": "garbage"}',
            "dns_query_rate_mean": "0", "dns_query_rate_std": "0",
        })
        monkeypatch.setattr(dd, "db", fake)

        asyncio.run(dd._update_baseline(1, _event(
            bytes_in=12, bytes_out=22, sessions=2, peers=["10.44.0.9"],
            protocols={"tcp": 2},
        )))

        assert len(fake.written) == 1
        params = fake.written[0][1]
        assert params[12] == 4, "sample_count must advance from the string value"
        assert json.loads(params[9])["tcp"] == 2
        assert json.loads(params[8]) == ["10.44.0.2", "10.44.0.9"]

    def test_non_numeric_protocol_counts_are_treated_as_zero(self, monkeypatch):
        fake = RecordingBaselineDB({
            "host_id": 1, "sample_count": 1,
            "bytes_in_mean": 0, "bytes_in_std": 0,
            "bytes_out_mean": 0, "bytes_out_std": 0,
            "session_count_mean": 0, "session_count_std": 0,
            "active_hours_bitmap": 0, "peer_set_json": "[]",
            "protocol_dist_json": '{"udp": null, "tcp": "x"}',
            "dns_query_rate_mean": 0, "dns_query_rate_std": 0,
        })
        monkeypatch.setattr(dd, "db", fake)

        asyncio.run(dd._update_baseline(1, _event(protocols={"tcp": 1, "udp": 2})))

        protocols = json.loads(fake.written[0][1][9])
        assert protocols == {"tcp": 1, "udp": 2}


class TestPersistAndRespond:
    def test_persist_returns_the_new_row_id(self, monkeypatch):
        class FakeDB:
            async def execute_returning(self, sql, params=()):
                return {"id": 42}

        monkeypatch.setattr(dd, "db", FakeDB())
        anomaly = Anomaly(host_id=1, anomaly_type=AnomalyType.NEW_PEER,
                          confidence=0.5, detail="x")
        assert asyncio.run(dd._persist_anomaly(anomaly)) == 42

    def test_persist_returns_none_when_the_insert_yields_nothing(self, monkeypatch):
        class FakeDB:
            async def execute_returning(self, *_a, **_k):
                return None

        monkeypatch.setattr(dd, "db", FakeDB())
        anomaly = Anomaly(host_id=1, anomaly_type=AnomalyType.NEW_PEER,
                          confidence=0.5, detail="x")
        assert asyncio.run(dd._persist_anomaly(anomaly)) is None

    def test_low_confidence_anomaly_is_not_auto_actioned(self, monkeypatch):
        import shield.reconfigurer as shield_mod

        calls = []

        async def fake_respond(*args):
            calls.append(args)

        monkeypatch.setattr(shield_mod, "respond_to_anomaly", fake_respond)
        anomaly = Anomaly(host_id=1, anomaly_type=AnomalyType.NEW_PEER,
                          confidence=0.5, detail="x")
        assert asyncio.run(dd._autorespond(anomaly, 1)) is None
        assert calls == []

    def test_high_confidence_anomaly_reaches_shield(self, monkeypatch):
        import shield.reconfigurer as shield_mod

        calls = []

        async def fake_respond(*args):
            calls.append(args)
            return {"status": "dry_run"}

        monkeypatch.setattr(shield_mod, "respond_to_anomaly", fake_respond)
        anomaly = Anomaly(host_id=1, anomaly_type=AnomalyType.DATA_EXFIL_SUSPECT,
                          confidence=0.95, detail="x")
        assert asyncio.run(dd._autorespond(anomaly, 7)) == {"status": "dry_run"}
        assert calls == [(7, 1, 0.95)]

    def test_shield_failure_is_swallowed(self, monkeypatch):
        import shield.reconfigurer as shield_mod

        async def broken(*_a):
            raise RuntimeError("iptables missing")

        monkeypatch.setattr(shield_mod, "respond_to_anomaly", broken)
        anomaly = Anomaly(host_id=1, anomaly_type=AnomalyType.DATA_EXFIL_SUSPECT,
                          confidence=0.95, detail="x")
        assert asyncio.run(dd._autorespond(anomaly, 7)) is None


class TestEchoDbFlow:
    def test_first_window_then_high_confidence_anomaly(self, monkeypatch):
        import shield.reconfigurer as shield_mod

        shield_calls = []

        async def fake_respond(anomaly_id, host_id, confidence):
            shield_calls.append((anomaly_id, host_id, confidence))
            return {"status": "dry_run"}

        monkeypatch.setattr(shield_mod, "respond_to_anomaly", fake_respond)

        ip = "10.99.88.1"

        async def scenario():
            await db.init()
            await db.execute("DELETE FROM hosts WHERE ip=?", (ip,))
            row = await db.execute_returning(
                "INSERT INTO hosts (ip, is_active) VALUES (?,1) RETURNING id", (ip,)
            )
            hid = row["id"]
            try:
                first = await dd.process_window({ip: _event(
                    bytes_in=100, bytes_out=200, sessions=2,
                    peers=["8.8.8.8"], protocols={"tcp": 2},
                )})
                baseline = await db.fetch_one(
                    "SELECT sample_count, is_baseline_ready FROM behavioral_baselines "
                    "WHERE host_id=?", (hid,)
                )
                await db.execute(
                    "UPDATE behavioral_baselines SET sample_count=30, is_baseline_ready=1, "
                    "bytes_in_mean=100, bytes_in_std=10, bytes_out_mean=200, bytes_out_std=10, "
                    "session_count_mean=2, session_count_std=1, "
                    "dns_query_rate_mean=0, dns_query_rate_std=1 WHERE host_id=?",
                    (hid,),
                )
                second = await dd.process_window({ip: _event(
                    bytes_in=100, bytes_out=10_000, sessions=2,
                    peers=["8.8.8.8"], protocols={"tcp": 2},
                )})
                stored = await db.fetch_all(
                    "SELECT anomaly_type, confidence FROM anomalies WHERE host_id=?",
                    (hid,),
                )
                return hid, first, baseline, second, stored
            finally:
                await db.execute("DELETE FROM anomalies WHERE host_id=?", (hid,))
                await db.execute("DELETE FROM behavioral_events WHERE host_id=?", (hid,))
                await db.execute("DELETE FROM behavioral_baselines WHERE host_id=?", (hid,))
                await db.execute("DELETE FROM hosts WHERE id=?", (hid,))

        hid, first, baseline, second, stored = run_async(scenario())

        assert first == []
        assert baseline["sample_count"] == 1
        assert baseline["is_baseline_ready"] == 0
        assert [a.anomaly_type for a in second] == [AnomalyType.DATA_EXFIL_SUSPECT]
        assert stored and stored[0]["anomaly_type"] == "DATA_EXFIL_SUSPECT"
        assert stored[0]["confidence"] > 0.99
        assert len(shield_calls) == 1
        assert shield_calls[0][0] > 0
        assert shield_calls[0][1] == hid


class FakeCollector:
    def __init__(self, iface=dd.DEFAULT_IFACE, network=None):
        self.iface = iface
        self.network = dd._resolve_network(network) or "10.44.0.0/24"
        self.duration = None

    def start_capture(self, duration):
        self.duration = duration

    def get_window_snapshot(self):
        return {}


class TestRunEchoReporting:
    def _patch(self, monkeypatch, anomalies, hosts=None, baseline=None):
        monkeypatch.setattr(dd, "PacketCollector", FakeCollector)

        class FakeDB:
            async def fetch_all(self, sql, params=()):
                return hosts or []

            async def fetch_one(self, sql, params=()):
                return {"ip": "10.44.0.1"}

        async def fake_process(_snapshot):
            return anomalies

        async def fake_baseline(_host_id):
            return baseline

        monkeypatch.setattr(dd, "db", FakeDB())
        monkeypatch.setattr(dd, "process_window", fake_process)
        monkeypatch.setattr(dd, "_get_or_create_baseline", fake_baseline)

    def test_no_hosts_and_no_anomalies_is_clean(self, monkeypatch):
        self._patch(monkeypatch, [])
        assert asyncio.run(dd.run_echo(iface="eth0", network="10.44.0.0/24")) == []

    def test_anomalies_are_reported_with_host_ip(self, monkeypatch):
        anomaly = Anomaly(host_id=1, anomaly_type=AnomalyType.NEW_PEER,
                          confidence=0.7, detail="new peer")
        self._patch(
            monkeypatch, [anomaly],
            hosts=[{"id": 1, "ip": "10.44.0.1"}],
            baseline={"sample_count": 20, "is_baseline_ready": 1},
        )
        assert asyncio.run(
            dd.run_echo(iface="eth0", network="10.44.0.0/24")
        ) == [anomaly]


def test_packet_accounting_still_works_after_hardening():
    collector = dd.PacketCollector(network="10.44.0.0/24")
    collector._process_packet(
        IP(src="10.44.0.1", dst="8.8.8.8") / TCP(sport=1000, dport=443, flags="S")
    )
    event = collector.get_window_snapshot()["10.44.0.1"]
    assert event.sessions == 1
    assert event.bytes_out > 0
    assert event.peers == ["8.8.8.8"]
