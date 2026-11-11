"""OSINT, patch-prioritisation and heartbeat regressions.

These paths run unattended on a schedule, so their failure modes are quiet:
duplicate findings inflate the posture score, deduping by CVE hides vulnerable
hosts, and a single missed ARP reply flips a machine offline.
"""
import asyncio
import sqlite3
import uuid

import pytest

from chronicle import db as cdb
from dashboard.app import run_async
from iris import heartbeat
from iris import osint_scanner as osint
from oracle import patch_prioritizer as pp


class FakeDB:
    def __init__(self, rows=None, scalar=None):
        self.rows = rows or []
        self.scalar = scalar
        self.executed = []
        self.queries = []

    async def fetch_all(self, sql, params=()):
        self.queries.append((sql, params))
        return self.rows

    async def fetch_one(self, sql, params=()):
        self.queries.append((sql, params))
        return self.rows[0] if self.rows else None

    async def fetch_val(self, sql, params=(), default=None):
        self.queries.append((sql, params))
        return self.scalar if self.scalar is not None else default

    async def execute(self, sql, params=()):
        self.executed.append((sql, params))

    async def execute_returning(self, sql, params=()):
        self.executed.append((sql, params))
        return None if self.scalar is not None else {"id": 1}


class TestOsintFindings:
    def test_identical_unremediated_finding_is_not_stored_twice(self, monkeypatch):
        fake = FakeDB(scalar=1)
        monkeypatch.setattr(osint, "db", fake)

        stored = asyncio.run(osint._store_finding(
            "LOCAL", "INTERNAL_NETWORK", "10.44.0.1", "detail", "INFO"
        ))
        assert stored is False

    def test_new_finding_is_stored(self, monkeypatch):
        fake = FakeDB(scalar=None)
        monkeypatch.setattr(osint, "db", fake)

        stored = asyncio.run(osint._store_finding(
            "LOCAL", "INTERNAL_NETWORK", "10.44.0.1", "detail", "INFO"
        ))
        assert stored is True
        params = fake.executed[0][1]
        assert params[:5] == (
            "LOCAL", "INTERNAL_NETWORK", "10.44.0.1", "detail", "INFO",
        )
        assert params[5:] == (
            "LOCAL", "INTERNAL_NETWORK", "10.44.0.1", "detail",
        )

    def test_invalid_addresses_are_skipped_before_shodan(self, monkeypatch):
        fake = FakeDB()
        monkeypatch.setattr(osint, "db", fake)

        class BoomAPI:
            def host(self, _ip):
                raise AssertionError("Shodan must not see a non-IP")

        monkeypatch.setattr(osint.shodan, "Shodan", lambda _key: BoomAPI())
        monkeypatch.setattr(osint.osint_cfg, "shodan_api_key", "key")
        asyncio.run(osint.run_osint_scan(["not-an-ip", "", None]))
        assert fake.executed == []
        assert fake.queries == []

    def test_private_host_gets_exactly_one_internal_finding(self, monkeypatch):
        fake = FakeDB(scalar=None)
        monkeypatch.setattr(osint, "db", fake)

        async def no_enrichment(_ip):
            return []

        monkeypatch.setattr(osint, "_enrich_local_ip", no_enrichment)
        monkeypatch.setattr(osint.osint_cfg, "shodan_api_key", "")
        asyncio.run(osint.run_osint_scan(["10.44.0.1"]))
        assert len(fake.executed) == 1
        assert fake.executed[0][1][1] == "INTERNAL_NETWORK"

    def test_public_host_is_queried_and_findings_stored(self, monkeypatch):
        fake = FakeDB(scalar=None)
        monkeypatch.setattr(osint, "db", fake)

        class API:
            def host(self, ip):
                return {"data": [{"port": 443, "transport": "tcp"}]}

        monkeypatch.setattr(osint.shodan, "Shodan", lambda _key: API())
        monkeypatch.setattr(osint.osint_cfg, "shodan_api_key", "key")
        asyncio.run(osint.run_osint_scan(["8.8.8.8"]))
        assert fake.executed[0][1][:5] == (
            "SHODAN", "EXTERNAL_EXPOSURE", "8.8.8.8",
            "Exposed Service: tcp/443", "HIGH",
        )

    @pytest.mark.parametrize("address", [
        "203.0.113.9",    # documentation range
        "100.64.0.7",     # CGNAT: is_private is False, is_global is False
        "192.0.2.5",      # documentation range
        "fd00::1",        # IPv6 ULA
        "169.254.1.1",    # link-local
    ])
    def test_non_routable_addresses_are_never_sent_to_shodan(
            self, address, monkeypatch):
        fake = FakeDB(scalar=None)
        monkeypatch.setattr(osint, "db", fake)

        class BoomAPI:
            def host(self, _ip):
                raise AssertionError("Shodan must not see a non-routable address")

        monkeypatch.setattr(osint.shodan, "Shodan", lambda _key: BoomAPI())
        monkeypatch.setattr(osint.osint_cfg, "shodan_api_key", "key")

        async def no_enrichment(_ip):
            return []

        monkeypatch.setattr(osint, "_enrich_local_ip", no_enrichment)
        asyncio.run(osint.run_osint_scan([address]))
        assert fake.executed[0][1][1] == "INTERNAL_NETWORK"

    def test_mac_vendor_lookup(self):
        assert osint._lookup_mac_vendor("b8:27:eb:aa:bb:cc") == "Raspberry Pi Foundation"
        assert osint._lookup_mac_vendor("AA-BB-CC-DD-EE-FF") is None


class TestOsintDedupe:
    def test_overlapping_scans_insert_exactly_one_finding(self):
        """A scheduled scan and a manual trigger can hit the same host at once.

        The old SELECT-then-INSERT let both passes see no row and insert, so
        the same exposure was counted twice in the posture score.
        """
        marker = f"osint-race-{uuid.uuid4().hex}"

        async def scenario():
            try:
                results = await asyncio.gather(*[
                    osint._store_finding(
                        "LOCAL", "INTERNAL_NETWORK", marker, "detail", "INFO")
                    for _ in range(4)
                ])
                count = await cdb.fetch_val(
                    "SELECT COUNT(*) FROM osint_findings WHERE target=?",
                    (marker,))
            finally:
                await cdb.execute(
                    "DELETE FROM osint_findings WHERE target=?", (marker,))
            return results, count

        results, count = run_async(scenario())

        assert count == 1
        assert results.count(True) == 1


class TestPatchPriority:
    def _row(self, **overrides):
        row = {
            "host_id": 1,
            "ip": "10.44.0.5", "risk_score": 5.0, "asset_value": 8.0,
            "cve_id": "CVE-2024-0001", "cvss_v3": 9.8, "severity": "CRITICAL",
            "description": "", "port": 443, "service": "https",
            "exploit_status": None, "effective_cvss": None, "path_count": 0,
        }
        row.update(overrides)
        return row

    def test_same_cve_on_two_hosts_yields_two_patch_items(self, monkeypatch):
        rows = [
            self._row(),
            self._row(host_id=2, ip="10.44.0.6", port=8443, asset_value=10.0),
        ]
        monkeypatch.setattr(pp, "db", FakeDB(rows=rows))
        result = asyncio.run(pp.generate_patch_priority())
        assert len(result["priority_list"]) == 2
        assert {item["ip"] for item in result["priority_list"]} == {
            "10.44.0.5", "10.44.0.6",
        }

    def test_duplicate_rows_for_same_host_and_port_are_collapsed(self, monkeypatch):
        rows = [self._row(), self._row()]
        monkeypatch.setattr(pp, "db", FakeDB(rows=rows))
        assert len(asyncio.run(pp.generate_patch_priority())["priority_list"]) == 1

    def test_exploit_status_marks_item_exploitable(self, monkeypatch):
        rows = [self._row(exploit_status="PUBLIC_EXPLOIT")]
        monkeypatch.setattr(pp, "db", FakeDB(rows=rows))
        result = asyncio.run(pp.generate_patch_priority())
        assert result["exploitable_count"] == 1

    def test_no_cves_returns_empty_summary(self, monkeypatch):
        monkeypatch.setattr(pp, "db", FakeDB(rows=[]))
        result = asyncio.run(pp.generate_patch_priority())
        assert result["priority_list"] == []
        assert result["total_critical"] == 0

    def test_dismissed_and_not_affected_cves_are_not_prioritized(self):
        """The patch list must agree with every other finding view."""
        ip = f"10.253.{int(uuid.uuid4().hex[:2], 16)}.{int(uuid.uuid4().hex[2:4], 16)}"
        active_id = f"CVE-2026-{uuid.uuid4().hex[:8]}"
        dismissed_id = f"CVE-2026-{uuid.uuid4().hex[:8]}"
        not_affected_id = f"CVE-2026-{uuid.uuid4().hex[:8]}"

        async def scenario():
            await cdb.init()
            await cdb.execute("DELETE FROM hosts WHERE ip=?", (ip,))
            host = await cdb.execute_returning(
                "INSERT INTO hosts (ip,is_active,risk_score,asset_value) "
                "VALUES (?,1,100,10) RETURNING id", (ip,))
            port = await cdb.execute_returning(
                "INSERT INTO ports (host_id,port,protocol,state,service) "
                "VALUES (?,443,'tcp','open','https') RETURNING id", (host["id"],))
            for cve_id, dismissed, verified in (
                (active_id, 0, "CONFIRMED"),
                (dismissed_id, 1, "CONFIRMED"),
                (not_affected_id, 0, "NOT_AFFECTED"),
            ):
                cve = await cdb.execute_returning(
                    "INSERT INTO cves (cve_id,cvss_v3,severity) "
                    "VALUES (?,10.0,'CRITICAL') RETURNING id", (cve_id,))
                await cdb.execute(
                    "INSERT INTO port_cves (port_id,cve_id,dismissed,verified_status) "
                    "VALUES (?,?,?,?)",
                    (port["id"], cve["id"], dismissed, verified))
            try:
                result = await pp.generate_patch_priority()
                return [i["cve_id"] for i in result["priority_list"]
                        if i["ip"] == ip]
            finally:
                await cdb.execute("DELETE FROM hosts WHERE id=?", (host["id"],))
                for cve_id in (active_id, dismissed_id, not_affected_id):
                    await cdb.execute("DELETE FROM cves WHERE cve_id=?", (cve_id,))

        assert run_async(scenario()) == [active_id]


class TestHeartbeat:
    def test_invalid_target_is_refused(self, monkeypatch):
        called = []

        async def discovery(_target):
            called.append(1)
            return []

        monkeypatch.setattr(
            heartbeat.wired_scanner, "discover_hosts", discovery)
        asyncio.run(heartbeat.heartbeat_once("0.0.0.0/0"))
        assert called == []

    def _run_once(self, monkeypatch, arp_hosts, db_rows):
        monkeypatch.setenv("OBSIDIOS_FAST_OFFLINE_GRACE_SECONDS", "60")
        fake = FakeDB(rows=db_rows)
        monkeypatch.setattr(heartbeat, "db", fake)

        async def discovery(_target):
            return arp_hosts

        monkeypatch.setattr(
            heartbeat.wired_scanner, "discover_hosts", discovery)

        asyncio.run(heartbeat.heartbeat_once("10.44.0.0/24"))
        return fake

    def test_freshly_seen_host_is_not_flapped_offline(self, monkeypatch):
        import time

        now = time.time()
        fake = self._run_once(
            monkeypatch,
            arp_hosts=[{"ip": "10.44.0.1", "mac": "AA:BB:CC:DD:EE:01"}],
            db_rows=[
                {"ip": "10.44.0.1", "last_seen": now - 5},
                {"ip": "10.44.0.9", "last_seen": now - 5},
            ],
        )
        down = [params[0] for sql, params in fake.executed if "is_active=0" in sql]
        assert down == []

    def test_sqlite_row_records_do_not_crash_the_sweep(self, monkeypatch):
        """CHRONICLE returns sqlite3.Row, which has no `.get` method."""
        import time

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE hosts (ip TEXT, last_seen REAL)")
        conn.executemany(
            "INSERT INTO hosts VALUES (?, ?)",
            [("10.44.0.1", time.time() - 5),
             ("10.44.0.9", time.time() - 1000)],
        )
        rows = conn.execute("SELECT ip, last_seen FROM hosts").fetchall()
        conn.close()

        monkeypatch.setenv("OBSIDIOS_FAST_OFFLINE_GRACE_SECONDS", "60")
        fake = FakeDB(rows=rows)
        monkeypatch.setattr(heartbeat, "db", fake)

        async def discovery(_target):
            return [{"ip": "10.44.0.1", "mac": "AA:BB:CC:DD:EE:01"}]

        monkeypatch.setattr(
            heartbeat.wired_scanner, "discover_hosts", discovery)

        result = asyncio.run(heartbeat.heartbeat_once("10.44.0.0/24"))

        assert result["status"] == "ok"
        assert result["down"] == 1
        down = [params[0] for sql, params in fake.executed if "is_active=0" in sql]
        assert down == ["10.44.0.9"]

    def test_host_unseen_beyond_grace_is_marked_offline(self, monkeypatch):
        import time

        now = time.time()
        fake = self._run_once(
            monkeypatch,
            arp_hosts=[{"ip": "10.44.0.1", "mac": "AA:BB:CC:DD:EE:01"}],
            db_rows=[
                {"ip": "10.44.0.1", "last_seen": now - 5},
                {"ip": "10.44.0.9", "last_seen": now - 1000},
            ],
        )
        down = [(sql, params) for sql, params in fake.executed if "is_active=0" in sql]
        assert [params[0] for _sql, params in down] == ["10.44.0.9"]
        # The transition timestamp is what lets compute_scan_diff report the
        # outage; without it heartbeat-detected downs are invisible.
        assert all("offline_since" in sql for sql, _params in down)

    def test_empty_discovery_never_mass_offlines(self, monkeypatch):
        """A failed sweep must not be read as "the whole network is gone"."""
        monkeypatch.setenv("OBSIDIOS_FAST_OFFLINE_GRACE_SECONDS", "0")
        fake = FakeDB(rows=[{"ip": "10.44.0.9", "last_seen": 0}])
        monkeypatch.setattr(heartbeat, "db", fake)

        async def discovery(_target):
            return []

        monkeypatch.setattr(
            heartbeat.wired_scanner, "discover_hosts", discovery)

        result = asyncio.run(heartbeat.heartbeat_once("10.44.0.0/24"))

        assert result["status"] == "empty"
        assert fake.executed == []
        assert fake.queries == []

    def test_new_host_is_inserted_reactivated_and_announced(self, monkeypatch):
        class FakeSocketIO:
            def __init__(self):
                self.events = []

            def emit(self, event, payload, namespace=None):
                self.events.append((event, payload))

        socketio = FakeSocketIO()
        monkeypatch.setenv("OBSIDIOS_FAST_OFFLINE_GRACE_SECONDS", "60")
        fake = FakeDB(rows=[])
        monkeypatch.setattr(heartbeat, "db", fake)

        async def discovery(_target):
            return [{"ip": "10.44.0.1", "mac": "AA:BB:CC:DD:EE:01"}]

        monkeypatch.setattr(
            heartbeat.wired_scanner, "discover_hosts", discovery)

        asyncio.run(heartbeat.heartbeat_once("10.44.0.0/24", socketio=socketio))
        assert any("INSERT INTO hosts" in sql for sql, _ in fake.executed)
        assert any("UPDATE hosts SET is_active=1, last_seen=?" in sql
                   for sql, _ in fake.executed)
        assert ("host_event", {"type": "UP", "ip": "10.44.0.1"}) in socketio.events


class TestOsintAvailability:
    def test_shodan_timeout_does_not_stop_the_rest_of_the_scan(self, monkeypatch):
        """One hung HTTPS connection must not stall the whole run."""
        import time as _time

        fake = FakeDB(scalar=None)
        monkeypatch.setattr(osint, "db", fake)

        class SlowAPI:
            def host(self, ip):
                if ip == "8.8.8.8":
                    _time.sleep(1.0)   # longer than the patched timeout
                    return {"data": []}
                return {"data": [{"port": 443, "transport": "tcp"}]}

        monkeypatch.setattr(osint.shodan, "Shodan", lambda _key: SlowAPI())
        monkeypatch.setattr(osint.osint_cfg, "shodan_api_key", "key")
        monkeypatch.setattr(osint, "SHODAN_TIMEOUT", 0.05)

        asyncio.run(osint.run_osint_scan(["8.8.8.8", "1.1.1.1"]))
        stored_for_second = [p for _sql, p in fake.executed if p[2] == "1.1.1.1"]
        assert stored_for_second, "the second host must still be queried"
        assert stored_for_second[0][3] == "Exposed Service: tcp/443"

    def test_reverse_dns_output_is_parsed(self, monkeypatch):
        import subprocess

        monkeypatch.setattr(
            osint.subprocess, "run",
            lambda *a, **k: subprocess.CompletedProcess(
                args=["nslookup"], returncode=0,
                stdout="Name:\tprinter.lan\nAddress: 10.0.0.9\n", stderr=""),
        )
        assert osint._reverse_dns("10.0.0.9") == "printer.lan"

    def test_reverse_dns_failure_is_not_fatal(self, monkeypatch):
        monkeypatch.setattr(
            osint, "_reverse_dns",
            lambda _ip: (_ for _ in ()).throw(RuntimeError("resolver crashed")))
        monkeypatch.setattr(osint, "db", FakeDB(scalar=None))
        findings = asyncio.run(osint._enrich_local_ip("10.0.0.9"))
        assert findings == []

    def test_reverse_dns_accepts_busybox_style_output(self, monkeypatch):
        import subprocess

        monkeypatch.setattr(
            osint.subprocess, "run",
            lambda *a, **k: subprocess.CompletedProcess(
                args=["nslookup"], returncode=0,
                stdout="Server: 10.0.0.1\nname = nas.lan.\n", stderr=""),
        )
        assert osint._reverse_dns("10.0.0.8") == "nas.lan"

    def test_reverse_dns_ignores_address_only_output(self, monkeypatch):
        import subprocess

        monkeypatch.setattr(
            osint.subprocess, "run",
            lambda *a, **k: subprocess.CompletedProcess(
                args=["nslookup"], returncode=0,
                stdout="Name: NXDOMAIN\nAddress: 10.0.0.1\n", stderr=""),
        )
        # No hostname record: the "Address:" line must not be mistaken for one.
        assert osint._reverse_dns("10.0.0.8") is None


class TestShodanPayloadRobustness:
    """Shodan banners are external data: one bad entry must not lose the rest."""

    def test_malformed_banners_are_skipped_and_valid_ones_stored(
            self, monkeypatch):
        fake = FakeDB(scalar=None)
        monkeypatch.setattr(osint, "db", fake)

        class API:
            def host(self, _ip):
                return {"data": [
                    None,
                    "not-a-banner",
                    {"transport": None, "port": 443},
                    {"transport": "TCP", "port": "8443"},
                    {"transport": "tcp", "port": None},
                    {"transport": "tcp", "port": "not-a-port"},
                    {"transport": "tcp"},
                ]}

        monkeypatch.setattr(osint.shodan, "Shodan", lambda _key: API())
        monkeypatch.setattr(osint.osint_cfg, "shodan_api_key", "key")

        asyncio.run(osint.run_osint_scan(["8.8.8.8"]))

        details = [params[3] for _sql, params in fake.executed]
        assert details == [
            "Exposed Service: unknown/443",
            "Exposed Service: tcp/8443",
        ]

    def test_private_host_with_malformed_enrichment_keeps_other_findings(
            self, monkeypatch):
        fake = FakeDB(scalar=None)
        monkeypatch.setattr(osint, "db", fake)
        monkeypatch.setattr(osint.osint_cfg, "shodan_api_key", "")

        async def enrichment(_ip):
            return [
                "not-a-finding",
                {"source": "LOCAL_DNS", "finding_type": "REVERSE_DNS",
                 "detail": "Hostname: printer.lan", "severity": "INFO"},
            ]

        monkeypatch.setattr(osint, "_enrich_local_ip", enrichment)

        asyncio.run(osint.run_osint_scan(["10.44.0.1"]))

        assert len(fake.executed) == 1
        assert fake.executed[0][1][1] == "REVERSE_DNS"

    def test_none_data_does_not_crash_the_host(self, monkeypatch):
        fake = FakeDB(scalar=None)
        monkeypatch.setattr(osint, "db", fake)

        class API:
            def host(self, _ip):
                return {"data": None}

        monkeypatch.setattr(osint.shodan, "Shodan", lambda _key: API())
        monkeypatch.setattr(osint.osint_cfg, "shodan_api_key", "key")

        asyncio.run(osint.run_osint_scan(["8.8.8.8"]))

        assert fake.executed == []


class TestMacVendorParsing:
    def test_dotted_and_dashed_macs_match_the_oui_table(self):
        assert osint._lookup_mac_vendor("0011.2233.4455") == "Apple"
        assert (osint._lookup_mac_vendor("b8-27-eb-aa-bb-cc")
                == "Raspberry Pi Foundation")

    def test_custom_file_accepts_tabs_and_full_mac_prefixes(self, tmp_path):
        table = {}
        path = tmp_path / "oui.txt"
        path.write_text(
            "# operator overrides\n"
            "00:11:22:33:44\tCustom Vendor\n"
            "not-a-mac\tIgnored Vendor\n",
            encoding="utf-8",
        )

        added = osint._load_mac_vendors(str(path), table)

        assert added == 1
        assert (osint._lookup_mac_vendor("00:11:22:33:44:55", table)
                == "Custom Vendor")

    def test_full_mac_override_beats_builtin_oui(self, tmp_path):
        """A full-MAC override must win over the six-hex OUI it starts with."""
        table = dict(osint._MAC_VENDORS)
        path = tmp_path / "oui.txt"
        path.write_text(
            "00:11:22:33:44:55\tMy Workstation\n",
            encoding="utf-8",
        )

        assert osint._load_mac_vendors(str(path), table) == 1
        assert (osint._lookup_mac_vendor("00:11:22:33:44:55", table)
                == "My Workstation")
        # Other devices behind the same built-in OUI keep the built-in vendor.
        assert osint._lookup_mac_vendor("00:11:22:99:88:77", table) == "Apple"

    def test_same_oui_override_replaces_builtin(self, tmp_path):
        table = dict(osint._MAC_VENDORS)
        path = tmp_path / "oui.txt"
        path.write_text("b8-27-eb\tOperator Pi Fleet\n", encoding="utf-8")

        assert osint._load_mac_vendors(str(path), table) == 1
        assert (osint._lookup_mac_vendor("b8:27:eb:aa:bb:cc", table)
                == "Operator Pi Fleet")

    def test_missing_custom_file_is_not_fatal(self, tmp_path):
        assert osint._load_mac_vendors(str(tmp_path / "missing.csv")) == 0
