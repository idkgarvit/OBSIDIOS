"""ECHO behavioral-drift hardening regressions.

Covers the failure modes that turn the immune system into a liability:
* unbounded per-window host/peer maps (memory exhaustion from spoofed sources),
* one malformed host aborting the whole observation window,
* wrong anomaly classification (exfil vs ordinary spike),
* packet parsing that raises instead of skipping.
"""
import asyncio
import json
import time

import pytest
from scapy.all import DNS, DNSQR, IP, TCP, UDP, IPv6

from chronicle.models import Anomaly, AnomalyType, BehavioralEvent
from echo import drift_detector as dd


def _baseline(**overrides):
    base = {
        "is_baseline_ready": True,
        "bytes_out_mean": 1000.0,
        "bytes_out_std": 100.0,
        "bytes_in_mean": 1000.0,
        "bytes_in_std": 100.0,
        "peer_set_json": '["10.44.0.2"]',
        "active_hours_bitmap": 0,
        "dns_query_rate_mean": 5.0,
        "dns_query_rate_std": 1.0,
        "session_count_mean": 2.0,
        "session_count_std": 1.2,
    }
    base.update(overrides)
    return base


def _event(**overrides):
    event = BehavioralEvent(host_id=0, **overrides)
    return event


@pytest.fixture
def collector():
    return dd.PacketCollector(network="10.44.0.0/24")


class TestZScore:
    def test_zero_std_is_neutral(self):
        assert dd._zscore(9999, 100, 0.0) == 0.0

    def test_absolute_direction(self):
        assert dd._zscore(50, 100, 25) == 2.0
        assert dd._zscore(150, 100, 25) == 2.0


class TestAnomalyTyping:
    def test_huge_outbound_is_data_exfil(self):
        event = _event(bytes_out=4000, bytes_in=1000)
        anomalies = asyncio.run(dd._detect_anomalies(1, event, _baseline()))
        types = {a.anomaly_type for a in anomalies}
        assert AnomalyType.DATA_EXFIL_SUSPECT in types
        assert AnomalyType.TRAFFIC_SPIKE not in types

    def test_moderate_outbound_is_traffic_spike(self):
        event = _event(bytes_out=1300, bytes_in=1000)
        anomalies = asyncio.run(dd._detect_anomalies(1, event, _baseline()))
        assert [a.anomaly_type for a in anomalies] == [AnomalyType.TRAFFIC_SPIKE]

    def test_inbound_spike_only_reports_traffic(self):
        event = _event(bytes_out=1000, bytes_in=5000)
        anomalies = asyncio.run(dd._detect_anomalies(1, event, _baseline()))
        assert [a.anomaly_type for a in anomalies] == [AnomalyType.TRAFFIC_SPIKE]

    def test_new_peer_is_reported(self):
        event = _event(bytes_out=1000, bytes_in=1000, peers=["10.44.0.99"])
        anomalies = asyncio.run(dd._detect_anomalies(1, event, _baseline()))
        assert [a.anomaly_type for a in anomalies] == [AnomalyType.NEW_PEER]
        assert "10.44.0.99" in anomalies[0].detail

    def test_known_peer_is_not_reported(self):
        event = _event(bytes_out=1000, bytes_in=1000, peers=["10.44.0.2"])
        assert asyncio.run(dd._detect_anomalies(1, event, _baseline())) == []

    def test_off_hours_activity(self):
        ts = time.mktime((2026, 1, 1, 3, 0, 0, 0, 0, -1))
        event = _event(ts=ts, bytes_out=1000, bytes_in=1000)
        # Only hour 4 is "normal" for this host.
        anomalies = asyncio.run(
            dd._detect_anomalies(1, event, _baseline(active_hours_bitmap=1 << 4))
        )
        assert [a.anomaly_type for a in anomalies] == [AnomalyType.HOUR_DRIFT]

    def test_large_dns_query_marks_tunnelling(self):
        event = _event(bytes_out=1000, bytes_in=1000,
                       protocols={"dns_large": 3})
        anomalies = asyncio.run(dd._detect_anomalies(1, event, _baseline()))
        assert [a.anomaly_type for a in anomalies] == [AnomalyType.DNS_ANOMALY]
        assert "tunneling" in anomalies[0].detail

    def test_dns_rate_spike(self):
        event = _event(bytes_out=1000, bytes_in=1000, dns_queries=60)
        anomalies = asyncio.run(dd._detect_anomalies(1, event, _baseline()))
        assert [a.anomaly_type for a in anomalies] == [AnomalyType.DNS_ANOMALY]
        assert anomalies[0].z_score > dd.ZSCORE_THRESHOLD

    def test_beacon_regularity(self):
        event = _event(bytes_out=1000, bytes_in=1000, sessions=6)
        anomalies = asyncio.run(dd._detect_anomalies(
            1, event, _baseline(session_count_mean=6.0, session_count_std=0.5)
        ))
        assert [a.anomaly_type for a in anomalies] == [AnomalyType.BEACON_PATTERN]

    def test_baseline_not_ready_returns_nothing(self):
        event = _event(bytes_out=10 ** 9)
        anomalies = asyncio.run(
            dd._detect_anomalies(1, event, _baseline(is_baseline_ready=False))
        )
        assert anomalies == []

    def test_corrupt_peer_set_does_not_crash(self):
        event = _event(bytes_out=1000, bytes_in=1000, peers=["10.44.0.2"])
        baseline = _baseline(peer_set_json="{not json")
        anomalies = asyncio.run(dd._detect_anomalies(1, event, baseline))
        assert [a.anomaly_type for a in anomalies] == [AnomalyType.NEW_PEER]


class TestPacketCollector:
    def test_outbound_and_inbound_accounting(self, collector):
        collector._process_packet(
            IP(src="10.44.0.1", dst="8.8.8.8") / TCP(sport=1000, dport=443, flags="S")
        )
        collector._process_packet(
            IP(src="8.8.8.8", dst="10.44.0.1") / UDP(sport=53, dport=5353)
        )
        snapshot = collector.get_window_snapshot()
        local = snapshot["10.44.0.1"]
        assert local.bytes_out > 0
        assert local.bytes_in > 0
        assert local.sessions == 1
        assert local.protocols["tcp"] == 1
        assert set(local.peers) == {"8.8.8.8"}

    def test_packets_outside_observation_network_are_ignored(self, collector):
        collector._process_packet(
            IP(src="203.0.113.5", dst="203.0.113.9") / TCP(flags="S")
        )
        assert collector.get_window_snapshot() == {}

    def test_dns_query_counting_and_large_query_flag(self, collector):
        small = IP(src="10.44.0.1", dst="10.44.0.2") / UDP(sport=5353, dport=53) / DNS(
            rd=1, qd=DNSQR(qname="example.com")
        )
        big_name = ".".join(["a" * 60] * 4) + ".com"
        big = IP(src="10.44.0.1", dst="10.44.0.2") / UDP(sport=5353, dport=53) / DNS(
            rd=1, qd=DNSQR(qname=big_name)
        )
        collector._process_packet(small)
        collector._process_packet(big)
        event = collector.get_window_snapshot()["10.44.0.1"]
        assert event.dns_queries == 2
        assert event.protocols.get("dns_large") == 1

    def test_host_cap_bounds_memory(self, collector, monkeypatch):
        monkeypatch.setattr(dd, "MAX_TRACKED_HOSTS", 1)
        collector._process_packet(
            IP(src="10.44.0.1", dst="10.44.0.2") / TCP(flags="S")
        )
        collector._process_packet(
            IP(src="10.44.0.3", dst="10.44.0.4") / TCP(flags="S")
        )
        assert list(collector.get_window_snapshot()) == ["10.44.0.1"]

    def test_peer_cap_bounds_memory(self, collector, monkeypatch):
        monkeypatch.setattr(dd, "MAX_TRACKED_PEERS", 2)
        for last_octet in range(1, 6):
            collector._process_packet(
                IP(src="10.44.0.1", dst=f"8.8.8.{last_octet}") / TCP(flags="S")
            )
        event = collector.get_window_snapshot()["10.44.0.1"]
        assert len(event.peers) == 2

    def test_malformed_packet_never_raises(self, collector):
        collector._process_packet(None)
        collector._process_packet(object())
        assert collector.get_window_snapshot() == {}

    def test_snapshot_resets_counters(self, collector):
        collector._process_packet(
            IP(src="10.44.0.1", dst="8.8.8.8") / TCP(flags="S")
        )
        assert collector.get_window_snapshot()
        assert collector.get_window_snapshot() == {}


class TestProcessWindow:
    def test_one_host_failure_does_not_stop_the_others(self, monkeypatch):
        class FakeDB:
            async def fetch_one(self, _sql, params=()):
                if params[0] == "10.44.0.1":
                    raise RuntimeError("database hiccup")
                return {"id": 2}

            async def execute(self, *_a, **_k):
                return None

        async def fake_baseline(_host_id):
            return _baseline()

        async def fake_detect(host_id, _event, _baseline):
            return [Anomaly(host_id=host_id, anomaly_type=AnomalyType.NEW_PEER,
                            confidence=0.5, detail="test")]

        async def fake_persist(_anomaly):
            return 10

        async def fake_respond(*_a):
            return None

        monkeypatch.setattr(dd, "db", FakeDB())
        monkeypatch.setattr(dd, "_get_or_create_baseline", fake_baseline)
        monkeypatch.setattr(dd, "_detect_anomalies", fake_detect)
        monkeypatch.setattr(dd, "_persist_anomaly", fake_persist)
        monkeypatch.setattr(dd, "_update_baseline", fake_baseline)
        monkeypatch.setattr(dd, "_autorespond", fake_respond)

        anomalies = asyncio.run(dd.process_window({
            "10.44.0.1": _event(),
            "10.44.0.2": _event(),
        }))
        assert [a.host_id for a in anomalies] == [2]


class TestIPv6Observation:
    def test_ipv6_hosts_are_tracked(self):
        collector = dd.PacketCollector(network="2001:db8::/64")
        collector._process_packet(
            IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(flags="S")
        )
        snapshot = collector.get_window_snapshot()
        assert "2001:db8::1" in snapshot
        assert snapshot["2001:db8::1"].sessions == 1
        assert set(snapshot["2001:db8::1"].peers) == {"2001:db8::2"}

    def test_ipv6_outside_the_network_is_ignored(self):
        collector = dd.PacketCollector(network="2001:db8::/64")
        collector._process_packet(
            IPv6(src="2001:dead::1", dst="2001:dead::2") / TCP(flags="S")
        )
        assert collector.get_window_snapshot() == {}


class TestSilenceIsNotExfiltration:
    """A host going quiet must not be reported as data theft."""

    def test_zero_traffic_against_a_busy_baseline_is_neutral(self):
        event = _event(bytes_out=0, bytes_in=0, dns_queries=0, sessions=0)
        baseline = _baseline(bytes_out_mean=50_000.0, bytes_out_std=500.0,
                             bytes_in_mean=50_000.0, bytes_in_std=500.0,
                             dns_query_rate_mean=40.0, dns_query_rate_std=2.0)
        assert asyncio.run(dd._detect_anomalies(1, event, baseline)) == []

    def test_malformed_null_aggregates_do_not_raise(self):
        event = _event(bytes_out=1, bytes_in=1, dns_queries=1, sessions=1)
        baseline = _baseline(
            bytes_out_mean=None, bytes_out_std=None,
            bytes_in_mean=None, bytes_in_std=None,
            dns_query_rate_mean=None, dns_query_rate_std=None,
            session_count_mean=None, session_count_std=None,
            active_hours_bitmap=None,
        )
        assert asyncio.run(dd._detect_anomalies(1, event, baseline)) == []


class TestDnsDirection:
    def test_responses_are_not_counted_as_queries(self, collector):
        big_name = ".".join(["a" * 60] * 4) + ".com"
        response = IP(src="10.44.0.2", dst="10.44.0.1") / UDP(
            sport=53, dport=5353) / DNS(qr=1, qd=DNSQR(qname=big_name))
        collector._process_packet(response)
        event = collector.get_window_snapshot().get("10.44.0.1")
        assert event is not None
        assert event.dns_queries == 0
        assert "dns_large" not in event.protocols

    def test_query_and_response_pair_counts_once(self, collector):
        q = IP(src="10.44.0.1", dst="10.44.0.2") / UDP(sport=5353, dport=53) / DNS(
            rd=1, qd=DNSQR(qname="example.com"))
        r = IP(src="10.44.0.2", dst="10.44.0.1") / UDP(sport=53, dport=5353) / DNS(
            qr=1, qd=DNSQR(qname="example.com"))
        collector._process_packet(q)
        collector._process_packet(r)
        assert collector.get_window_snapshot()["10.44.0.1"].dns_queries == 1


class TestNewPeerIsOperatorOnly:
    def test_confidence_is_capped_below_autoresponse(self):
        peers = [f"10.44.0.{n}" for n in range(50, 60)]
        event = _event(bytes_out=1000, bytes_in=1000, peers=peers)
        anomalies = asyncio.run(dd._detect_anomalies(1, event, _baseline()))
        assert [a.anomaly_type for a in anomalies] == [AnomalyType.NEW_PEER]
        anomaly = anomalies[0]
        assert anomaly.confidence == dd.NEW_PEER_MAX_CONFIDENCE
        assert anomaly.confidence < dd.AUTORESPOND_MIN_CONFIDENCE
        assert asyncio.run(dd._autorespond(anomaly, 1)) is None

    def test_detail_order_is_deterministic(self):
        event = _event(bytes_out=1000, bytes_in=1000,
                       peers=["10.44.0.30", "10.44.0.20", "10.44.0.10"])
        first = asyncio.run(dd._detect_anomalies(1, event, _baseline()))[0]
        second = asyncio.run(dd._detect_anomalies(1, event, _baseline()))[0]
        assert first.detail == second.detail
        assert "10.44.0.10, 10.44.0.20, 10.44.0.30" in first.detail

    def test_saturated_peer_baseline_stops_repeating_the_alert(self, monkeypatch):
        monkeypatch.setattr(dd, "MAX_BASELINE_PEERS", 2)
        event = _event(bytes_out=1000, bytes_in=1000, peers=["10.44.0.99"])
        baseline = _baseline(peer_set_json='["10.44.0.2", "10.44.0.3"]')
        assert asyncio.run(dd._detect_anomalies(1, event, baseline)) == []


class TestBaselineNulls:
    def test_legacy_null_row_updates_without_raising(self, monkeypatch):
        class FakeDB:
            def __init__(self):
                self.written = None

            async def fetch_one(self, _sql, _params=()):
                return {
                    "host_id": 1, "sample_count": None,
                    "bytes_in_mean": None, "bytes_in_std": None,
                    "bytes_out_mean": None, "bytes_out_std": None,
                    "session_count_mean": None, "session_count_std": None,
                    "active_hours_bitmap": None, "peer_set_json": None,
                    "protocol_dist_json": None,
                    "dns_query_rate_mean": None, "dns_query_rate_std": None,
                }

            async def execute_returning(self, _sql, params=()):
                self.written = params
                return {"id": 1}

        fake = FakeDB()
        monkeypatch.setattr(dd, "db", fake)
        asyncio.run(dd._update_baseline(1, _event(bytes_out=10, bytes_in=20)))
        assert fake.written is not None
        assert fake.written[0] > 0          # window_end
        assert fake.written[12] == 1        # sample_count incremented from NULL


class TestBaselineActuallyLearns:
    """The baseline update used to serialise a `set`, so every write after the
    first observation raised TypeError and no host ever became baseline-ready.
    """

    class FakeDB:
        def __init__(self, row):
            self.row = row
            self.written = []

        async def fetch_one(self, _sql, _params=()):
            return dict(self.row)

        async def execute_returning(self, _sql, params=()):
            self.written.append(params)
            return {"id": 1}

    def test_second_observation_writes_valid_peer_json(self, monkeypatch):
        fake = self.FakeDB({
            "host_id": 1, "sample_count": 1,
            "bytes_in_mean": 100.0, "bytes_in_std": 0.0,
            "bytes_out_mean": 200.0, "bytes_out_std": 0.0,
            "session_count_mean": 1.0, "session_count_std": 0.0,
            "active_hours_bitmap": 1, "peer_set_json": '["10.44.0.2"]',
            "protocol_dist_json": '{"tcp": 1}',
            "dns_query_rate_mean": 0.0, "dns_query_rate_std": 0.0,
        })
        monkeypatch.setattr(dd, "db", fake)

        asyncio.run(dd._update_baseline(
            1, _event(bytes_out=300, bytes_in=150, peers=["10.44.0.9"])))

        assert len(fake.written) == 1
        params = fake.written[0]
        assert params[12] == 2, "sample_count must advance"
        peers = json.loads(params[8])
        assert peers == ["10.44.0.2", "10.44.0.9"]
        protocols = json.loads(params[9])
        assert protocols["tcp"] == 1

    def test_saturated_baseline_still_writes(self, monkeypatch):
        monkeypatch.setattr(dd, "MAX_BASELINE_PEERS", 2)
        fake = self.FakeDB({
            "host_id": 1, "sample_count": 4,
            "bytes_in_mean": 1.0, "bytes_in_std": 0.0,
            "bytes_out_mean": 1.0, "bytes_out_std": 0.0,
            "session_count_mean": 0.0, "session_count_std": 0.0,
            "active_hours_bitmap": 0,
            "peer_set_json": '["10.44.0.2", "10.44.0.3"]',
            "protocol_dist_json": "{}",
            "dns_query_rate_mean": 0.0, "dns_query_rate_std": 0.0,
        })
        monkeypatch.setattr(dd, "db", fake)

        asyncio.run(dd._update_baseline(
            1, _event(bytes_out=1, bytes_in=1, peers=["10.44.0.99"])))
        assert json.loads(fake.written[0][8]) == ["10.44.0.2", "10.44.0.3"]
