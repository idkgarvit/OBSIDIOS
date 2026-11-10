"""IRIS detection-loop hardening regressions.

The scanner must survive a missing nmap/root, refuse unsafe targets even when
the target comes from the database, and never leave a scan row RUNNING.
"""
import asyncio
import subprocess
import time
import uuid

from chronicle import db
from dashboard.app import run_async
from iris import wired_scanner as wired


class FakeDB:
    def __init__(self):
        self.executed = []
        self.returned = []

    async def execute_returning(self, sql, params=()):
        self.executed.append((sql, params))
        return {"id": 7}

    async def execute(self, sql, params=()):
        self.executed.append((sql, params))

    async def fetch_val(self, *_a, **_k):
        return ""


class FakeHost:
    def state(self):
        return "up"

    def __getitem__(self, key):
        if key == "addresses":
            return {}
        raise KeyError(key)


class FakeScanner:
    def scan(self, hosts, arguments):
        self.hosts = hosts
        self.arguments = arguments

    def all_hosts(self):
        return ["10.44.0.7"]

    def __getitem__(self, _ip):
        return FakeHost()


class TestDiscovery:
    def test_unsafe_target_is_refused_before_any_sweep(self, monkeypatch):
        called = []

        def fake_arp(*_args):
            called.append(True)
            return []

        monkeypatch.setattr(wired, "_arp_sweep", fake_arp)
        assert asyncio.run(wired.discover_hosts("0.0.0.0/0")) == []
        assert called == []

    def test_arp_failure_still_uses_nmap_results(self, monkeypatch):
        def no_root(*_args):
            raise PermissionError("raw socket permission denied")

        monkeypatch.setattr(wired, "_arp_sweep", no_root)
        monkeypatch.setattr(wired.nmap, "PortScanner", FakeScanner)

        hosts = asyncio.run(wired.discover_hosts("10.44.0.0/24"))
        assert hosts == [{"ip": "10.44.0.7", "mac": "UNKNOWN"}]

    def test_both_sources_failing_returns_empty_not_crash(self, monkeypatch):
        def no_root(*_args):
            raise PermissionError("raw socket permission denied")

        def no_nmap(*_args, **_kwargs):
            raise FileNotFoundError("nmap")

        monkeypatch.setattr(wired, "_arp_sweep", no_root)
        monkeypatch.setattr(wired.nmap, "PortScanner", no_nmap)

        assert asyncio.run(wired.discover_hosts("10.44.0.0/24")) == []

    def test_one_malformed_nmap_record_does_not_drop_the_rest(self, monkeypatch):
        def no_root(*_args):
            raise PermissionError("raw socket permission denied")

        class BrokenHost:
            def state(self):
                return "up"

            def __getitem__(self, _key):
                raise KeyError("addresses")

        class GoodHost:
            def state(self):
                return "up"

            def __getitem__(self, _key):
                return {"mac": "aa:bb:cc:dd:ee:01"}

        class Scanner:
            def scan(self, *_args, **_kwargs):
                return None

            def all_hosts(self):
                return ["10.44.0.8", "10.44.0.9"]

            def __getitem__(self, ip):
                return BrokenHost() if ip.endswith("8") else GoodHost()

        monkeypatch.setattr(wired, "_arp_sweep", no_root)
        monkeypatch.setattr(wired.nmap, "PortScanner", Scanner)

        hosts = asyncio.run(wired.discover_hosts("10.44.0.0/24"))
        assert hosts == [{"ip": "10.44.0.9", "mac": "AA:BB:CC:DD:EE:01"}]


class TestRunScan:
    def test_no_hosts_marks_scan_done_instead_of_running_forever(self, monkeypatch):
        fake_db = FakeDB()
        monkeypatch.setattr(wired, "db", fake_db)

        async def no_hosts(_network):
            return []

        monkeypatch.setattr(wired, "discover_hosts", no_hosts)

        result = asyncio.run(wired.run_scan("10.44.0.0/24"))
        assert "no hosts discovered" in result.errors

        done = [sql for sql, _ in fake_db.executed if "status='DONE'" in sql]
        assert done, "scan row must not be left RUNNING"
        done_params = next(p for sql, p in fake_db.executed if "status='DONE'" in sql)
        assert done_params[1] == 7

    def test_unsafe_target_creates_no_scan_row(self, monkeypatch):
        fake_db = FakeDB()
        monkeypatch.setattr(wired, "db", fake_db)

        result = asyncio.run(wired.run_scan("8.8.8.0/24"))
        assert result.errors and "unsafe target" in result.errors[0]
        assert fake_db.executed == []

    def test_nmap_argument_validation_blocks_script_use(self, monkeypatch):
        fake_db = FakeDB()
        monkeypatch.setattr(wired, "db", fake_db)
        # `active_nmap_args` is a read-only pydantic property, so override the
        # validator itself: whatever it is asked about, answer "unsafe".
        monkeypatch.setattr(wired, "validate_nmap_arguments", lambda _args: (False, "script use"))

        result = asyncio.run(wired.run_scan("10.44.0.0/24"))
        assert result.errors and "unsafe nmap arguments" in result.errors[0]
        assert fake_db.executed == []


class TestFastGrace:
    def test_grace_parser_handles_garbage_and_negative_values(self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_FAST_OFFLINE_GRACE_SECONDS", "not-a-number")
        assert wired._fast_offline_grace_seconds() == 120
        monkeypatch.setenv("OBSIDIOS_FAST_OFFLINE_GRACE_SECONDS", "-5")
        assert wired._fast_offline_grace_seconds() == 0


class TestDatabaseWrites:
    def test_mark_missing_hosts_offline_uses_json_parameter(self, monkeypatch):
        old_ip, live_ip = "10.99.77.1", "10.99.77.2"

        async def scenario():
            await db.init()
            await db.execute("DELETE FROM hosts WHERE ip IN (?,?)", (old_ip, live_ip))
            now = time.time()
            await db.execute(
                "INSERT INTO hosts (ip, is_active, last_seen) VALUES (?,1,?)",
                (old_ip, now - 1000),
            )
            await db.execute(
                "INSERT INTO hosts (ip, is_active, last_seen) VALUES (?,1,?)",
                (live_ip, now),
            )
            moved = await wired._mark_missing_hosts_offline([live_ip], grace=60)
            old_active = await db.fetch_val("SELECT is_active FROM hosts WHERE ip=?", (old_ip,))
            live_active = await db.fetch_val("SELECT is_active FROM hosts WHERE ip=?", (live_ip,))
            await db.execute("DELETE FROM hosts WHERE ip IN (?,?)", (old_ip, live_ip))
            return moved, old_active, live_active

        moved, old_active, live_active = run_async(scenario())
        assert moved == 1
        assert old_active == 0
        assert live_active == 1

    def test_upsert_ports_closes_ports_missing_from_latest_scan(self):
        ip = "10.99.77.3"

        async def scenario():
            await db.init()
            await db.execute("DELETE FROM hosts WHERE ip=?", (ip,))
            row = await db.execute_returning(
                "INSERT INTO hosts (ip, is_active) VALUES (?,1) RETURNING id", (ip,)
            )
            hid = row["id"]
            now = time.time()
            await db.execute(
                "INSERT INTO ports (host_id, port, protocol, state, first_seen, last_seen) "
                "VALUES (?,22,'tcp','open',?,?)",
                (hid, now - 1000, now - 1000),
            )
            # The host was scanned this run; it just had no open ports left.
            await wired._upsert_ports(
                [{"ip": ip, "ports": []}], {ip: hid}, scan_started=now)
            state = await db.fetch_val(
                "SELECT state FROM ports WHERE host_id=? AND port=22", (hid,)
            )
            await db.execute("DELETE FROM ports WHERE host_id=?", (hid,))
            await db.execute("DELETE FROM hosts WHERE id=?", (hid,))
            return state

        assert run_async(scenario()) == "closed"

    def test_unscanned_host_keeps_its_open_ports(self):
        """A failed nmap pass is not evidence that a port closed."""
        ip = "10.99.77.4"

        async def scenario():
            await db.init()
            await db.execute("DELETE FROM hosts WHERE ip=?", (ip,))
            row = await db.execute_returning(
                "INSERT INTO hosts (ip, is_active) VALUES (?,1) RETURNING id", (ip,)
            )
            hid = row["id"]
            now = time.time()
            await db.execute(
                "INSERT INTO ports (host_id, port, protocol, state, first_seen, last_seen) "
                "VALUES (?,22,'tcp','open',?,?)",
                (hid, now - 1000, now - 1000),
            )
            # The host answered ARP but its port scan errored, so it is absent
            # from scan_data while still present in host_id_map.
            await wired._upsert_ports([], {ip: hid}, scan_started=now)
            state = await db.fetch_val(
                "SELECT state FROM ports WHERE host_id=? AND port=22", (hid,)
            )
            await db.execute("DELETE FROM ports WHERE host_id=?", (hid,))
            await db.execute("DELETE FROM hosts WHERE id=?", (hid,))
            return state

        assert run_async(scenario()) == "open"

    def test_rescan_persists_a_newly_detected_cpe(self):
        ip = "10.99.77.5"

        async def scenario():
            await db.init()
            await db.execute("DELETE FROM hosts WHERE ip=?", (ip,))
            row = await db.execute_returning(
                "INSERT INTO hosts (ip, is_active) VALUES (?,1) RETURNING id", (ip,)
            )
            hid = row["id"]
            now = time.time()
            await db.execute(
                "INSERT INTO ports (host_id, port, protocol, state, first_seen, last_seen) "
                "VALUES (?,22,'tcp','open',?,?)",
                (hid, now - 1000, now - 1000),
            )
            await wired._upsert_ports([{
                "ip": ip,
                "ports": [{
                    "port": 22, "protocol": "tcp", "state": "open",
                    "service": "ssh", "product": "openssh", "version": "9.0",
                    "cpe": "cpe:/a:openbsd:openssh:9.0",
                }],
            }], {ip: hid}, scan_started=now)
            stored = await db.fetch_one(
                "SELECT cpe, service, version FROM ports"
                " WHERE host_id=? AND port=22", (hid,)
            )
            await db.execute("DELETE FROM ports WHERE host_id=?", (hid,))
            await db.execute("DELETE FROM hosts WHERE id=?", (hid,))
            return stored

        stored = run_async(scenario())
        assert stored["cpe"] == "cpe:/a:openbsd:openssh:9.0"
        assert stored["version"] == "9.0"

    def test_malformed_port_entries_are_skipped(self):
        """Junk in a scanner result must not abort the whole port upsert."""

        class ExplodingDB:
            async def executemany(self, *_a, **_k):
                raise AssertionError("no valid rows should be written")

            async def execute(self, *_a, **_k):
                raise AssertionError("nothing to reconcile")

        original = wired.db
        wired.db = ExplodingDB()
        try:
            written = asyncio.run(wired._upsert_ports(
                [{"ip": "10.0.0.9", "ports": [
                    None, "junk", {"port": "22"}, {"port": True},
                ]}],
                {"10.0.0.9": 1},
            ))
        finally:
            wired.db = original
        assert written == 0


def test_bogus_oui_no_longer_overrides_a_real_os_guess():
    # 00:11:22 is a generic/example OUI, not an Apple one.
    assert wired._infer_os_from_mac("00:11:22:33:44:55", "Windows", 50) == ("Windows", 50)
    os_name, accuracy = wired._infer_os_from_mac("3C:07:54:11:22:33", "Linux", 40)
    assert os_name == "Apple iOS"
    assert accuracy == 30


class TestWirelessScan:
    def test_classification_rules(self):
        known = {"AA:BB:CC:DD:EE:FF": "HomeNet"}
        assert wired._classify_wireless_threat(
            "AA:BB:CC:DD:EE:FF", "HomeNet", "OPEN", None, known
        ) == "OPEN_NETWORK"
        assert wired._classify_wireless_threat(
            "AA:BB:CC:DD:EE:FF", "EvilTwin", "WPA2/WPA3", None, known
        ) == "EVIL_TWIN"
        assert wired._classify_wireless_threat(
            "BB:BB:CC:DD:EE:FF", "HomeNet", "WPA2/WPA3", None, known
        ) == "ENCRYPTED_NETWORK"
        assert wired._classify_wireless_threat(
            "CC:BB:CC:DD:EE:FF", "Strong", "WPA2/WPA3", -40, {}
        ) == "ROGUE_AP"

    def test_notifier_failure_does_not_abort_the_ap_scan(self, monkeypatch):
        ap_output = (
            "BSS AA:BB:CC:00:00:01(on wlan0)\n"
            "\tSSID: CoffeeShop\n"
            "\tsignal: -60.00 dBm\n"
            "\tchannel 6\n"
            "\n"
            "BSS AA:BB:CC:00:00:02(on wlan0)\n"
            "\tSSID: HomeNet\n"
            "\tsignal: -45.00 dBm\n"
            "\tchannel 11\n"
            "\tRSN: * Version: 1\n"
        )

        def fake_run(cmd, **_kwargs):
            if cmd == ["iw", "dev"]:
                return subprocess.CompletedProcess(cmd, 0, "Interface wlan0\n", "")
            if cmd[:3] == ["iw", "dev", "wlan0"] and cmd[-1] == "scan":
                return subprocess.CompletedProcess(cmd, 0, ap_output, "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        class FakeWirelessDB:
            def __init__(self):
                self.executed = []

            async def fetch_all(self, *_a, **_k):
                return []

            async def execute(self, sql, params=()):
                self.executed.append((sql, params))

        fake_db = FakeWirelessDB()
        monkeypatch.setattr(wired, "db", fake_db)
        monkeypatch.setattr(subprocess, "run", fake_run)
        monkeypatch.setattr(wired.scan_cfg, "enable_wireless", True)
        monkeypatch.setattr(wired.scan_cfg, "wireless_interface", "wlan0")

        import alerts.notifier as notifier

        async def boom(**_kwargs):
            raise RuntimeError("webhook down")

        monkeypatch.setattr(notifier, "buffer_alert", boom)
        asyncio.run(wired.run_wireless_scan())

        inserted = [params for sql, params in fake_db.executed
                    if "INSERT INTO wireless_threats" in sql and len(params) == 8]
        threat_types = [p[1] for p in inserted]
        # The first AP's notification fails; the second AP must still be stored.
        assert threat_types == ["OPEN_NETWORK", "ROGUE_AP"]

    def test_disabled_wireless_scan_does_nothing(self, monkeypatch):
        monkeypatch.setattr(wired.scan_cfg, "enable_wireless", False)

        def must_not_run(*_a, **_k):
            raise AssertionError("subprocess must not run when wireless is disabled")

        monkeypatch.setattr(subprocess, "run", must_not_run)
        asyncio.run(wired.run_wireless_scan())

    def test_previous_bssid_read_failure_does_not_abort_the_scan(self, monkeypatch):
        monkeypatch.setattr(wired.scan_cfg, "enable_wireless", True)
        monkeypatch.setattr(wired.scan_cfg, "wireless_interface", "wlan0")

        def fake_run(cmd, **_kwargs):
            if cmd == ["iw", "dev"]:
                return subprocess.CompletedProcess(cmd, 0, "Interface wlan0\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        class FailingDB:
            def __init__(self):
                self.executed = []

            async def fetch_all(self, sql, params=()):
                if "bssid" in sql:
                    raise RuntimeError("database is locked")
                return []

            async def execute(self, sql, params=()):
                self.executed.append((sql, params))

        fake_db = FailingDB()
        monkeypatch.setattr(wired, "db", fake_db)
        monkeypatch.setattr(subprocess, "run", fake_run)

        asyncio.run(wired.run_wireless_scan())

        # The scan continues to its history prune despite the failed lookup.
        assert any("DELETE FROM wireless_threats" in sql
                   for sql, _ in fake_db.executed)


class TestWirelessClients:
    """Client discovery must be linear, deduplicated and bounded."""

    def _patch(self, monkeypatch, station_out="", arp_out=""):
        def fake_run(cmd, **_kwargs):
            if cmd[:2] == ["iw", "dev"] and cmd[-1:] == ["dump"]:
                return subprocess.CompletedProcess(cmd, 0, station_out, "")
            if cmd and cmd[0] == "arp":
                return subprocess.CompletedProcess(cmd, 0, arp_out, "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(subprocess, "run", fake_run)

    def test_same_client_from_both_sources_is_stored_once(self, monkeypatch):
        station = (
            "Station AA:BB:CC:00:00:01 (on wlan0)\n"
            "\tsignal:  -55 [-60, -50] dBm\n"
        )
        arp = "192.168.1.20   ether   aa:bb:cc:00:00:01   C   wlan0\n"
        self._patch(monkeypatch, station, arp)

        clients = wired._scan_wireless_clients("wlan0")
        assert [c["mac"] for c in clients] == ["AA:BB:CC:00:00:01"]
        assert clients[0]["source"] == "iw_station_dump"

    def test_multicast_and_broadcast_macs_are_skipped(self, monkeypatch):
        arp = (
            "224.0.0.1   ether   01:00:5e:00:00:01   C   wlan0\n"
            "255.255.255.255   ether   ff:ff:ff:ff:ff:ff   C   wlan0\n"
            "192.168.1.30   ether   aa:bb:cc:00:00:30   C   wlan0\n"
        )
        self._patch(monkeypatch, "", arp)
        macs = [c["mac"] for c in wired._scan_wireless_clients("wlan0")]
        assert macs == ["AA:BB:CC:00:00:30"]

    def test_malformed_address_is_not_a_mac(self, monkeypatch):
        arp = "192.168.1.40   ether   :::::::::::::::::   C   wlan0\n"
        self._patch(monkeypatch, "", arp)
        assert wired._scan_wireless_clients("wlan0") == []

    def test_client_list_is_capped(self, monkeypatch):
        monkeypatch.setattr(wired, "_MAX_WIRELESS_CLIENTS", 3)
        lines = [
            f"10.0.0.{i}   ether   aa:bb:cc:00:00:{i:02x}   C   wlan0"
            for i in range(10)
        ]
        self._patch(monkeypatch, "", "\n".join(lines))
        assert len(wired._scan_wireless_clients("wlan0")) == 3

    def test_missing_arp_binary_is_not_fatal(self, monkeypatch):
        def fake_run(cmd, **_kwargs):
            if cmd and cmd[0] == "arp":
                raise FileNotFoundError("arp")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert wired._scan_wireless_clients("wlan0") == []


class TestWirelessHistoryIsBounded:
    def test_old_inactive_rows_are_pruned(self, monkeypatch):
        monkeypatch.setattr(wired.scan_cfg, "enable_wireless", True)
        monkeypatch.setattr(wired.scan_cfg, "wireless_interface", "wlan0")

        def fake_run(cmd, **_kwargs):
            if cmd == ["iw", "dev"]:
                return subprocess.CompletedProcess(cmd, 0, "Interface wlan0\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        class FakeDB:
            def __init__(self):
                self.executed = []

            async def fetch_all(self, sql, params=()):
                if "bssid" in sql:
                    assert "LIMIT 1000" in sql
                return []

            async def execute(self, sql, params=()):
                self.executed.append((sql, params))

        fake_db = FakeDB()
        monkeypatch.setattr(wired, "db", fake_db)
        monkeypatch.setattr(subprocess, "run", fake_run)
        asyncio.run(wired.run_wireless_scan())

        prunes = [(sql, params) for sql, params in fake_db.executed
                  if "DELETE FROM wireless_threats" in sql]
        assert prunes, "history must be pruned"
        assert "is_active=0" in prunes[0][0]


class TestNmapResultParsing:
    """Nmap output is external data: one odd field must not drop a whole host."""

    class Host(dict):
        def hostname(self):
            return "printer.lan"

        def state(self):
            return "up"

        def all_protocols(self):
            return ["tcp"]

    class Scanner:
        def __init__(self, host):
            self.host = host

        def scan(self, **_kwargs):
            return None

        def all_hosts(self):
            return ["10.44.0.5"]

        def __getitem__(self, _ip):
            return self.host

    def test_osmatch_without_accuracy_does_not_discard_ports(self, monkeypatch):
        host = self.Host({
            "osmatch": [
                {"name": "Linux"},                       # no accuracy key at all
                {"name": "Windows", "accuracy": "N/A"},  # non-numeric
                {"name": "BSD", "accuracy": "92"},
            ],
            "tcp": {22: {"state": "open", "name": "ssh"}},
        })
        monkeypatch.setattr(wired.nmap, "PortScanner", lambda: self.Scanner(host))

        result = wired._nmap_scan_host("10.44.0.5", "-sV")
        assert [o["name"] for o in result["os"]] == ["Linux", "Windows", "BSD"]
        assert [o["accuracy"] for o in result["os"]] == [0, 0, 92]
        assert [p["port"] for p in result["ports"]] == [22]

    def test_malformed_osmatch_entries_are_skipped(self, monkeypatch):
        host = self.Host({
            "osmatch": ["garbage", {"accuracy": "50"}, {"name": "Linux", "accuracy": "88"}],
            "tcp": {},
        })
        monkeypatch.setattr(wired.nmap, "PortScanner", lambda: self.Scanner(host))

        result = wired._nmap_scan_host("10.44.0.5", "-sV")
        assert result["os"] == [{"name": "Linux", "accuracy": 88}]


class TestRunScanPartialFailure:
    def _common(self, monkeypatch, fake_db, host_ids, scan_data):
        monkeypatch.setattr(wired, "db", fake_db)

        async def hosts(_network):
            return [{"ip": nd["ip"], "mac": "AA:BB:CC:DD:EE:FF"} for nd in scan_data]

        async def scanned(_hosts):
            return scan_data

        async def upsert(*_a, **_k):
            return host_ids

        async def ports(*_a, **_k):
            return 0

        async def offline(*_a, **_k):
            return 0

        monkeypatch.setattr(wired, "discover_hosts", hosts)
        monkeypatch.setattr(wired, "scan_hosts_concurrent", scanned)
        monkeypatch.setattr(wired, "_upsert_hosts", upsert)
        monkeypatch.setattr(wired, "_upsert_ports", ports)
        monkeypatch.setattr(wired, "_mark_missing_hosts_offline", offline)

    def test_host_without_an_id_does_not_fail_the_scan(self, monkeypatch):
        fake_db = FakeDB()
        scan_data = [{"ip": "10.44.0.5", "hostname": "h", "os": [],
                      "ports": [{"port": 22, "protocol": "tcp",
                                 "state": "open", "service": "ssh"}]}]
        self._common(monkeypatch, fake_db, {}, scan_data)

        result = asyncio.run(wired.run_scan("10.44.0.0/24"))
        assert result.errors == []
        assert result.hosts == []
        assert any("status='DONE'" in sql for sql, _ in fake_db.executed)
        assert not any("status='FAILED'" in sql for sql, _ in fake_db.executed)

    def test_unmodellable_port_does_not_fail_the_scan(self, monkeypatch):
        fake_db = FakeDB()
        scan_data = [{"ip": "10.44.0.5", "hostname": "h", "os": [],
                      "ports": [{"port": "not-a-port"}]}]
        self._common(monkeypatch, fake_db, {"10.44.0.5": 12}, scan_data)

        result = asyncio.run(wired.run_scan("10.44.0.0/24"))
        assert result.errors == []
        assert [h.ip for h in result.hosts] == ["10.44.0.5"]
        assert result.ports == {}
        assert any("status='DONE'" in sql for sql, _ in fake_db.executed)

    def test_one_bad_port_does_not_discard_the_valid_ones(self, monkeypatch):
        fake_db = FakeDB()
        scan_data = [{"ip": "10.44.0.5", "hostname": "h", "os": [],
                      "ports": [
                          {"port": 22, "protocol": "tcp", "state": "open"},
                          {"port": "not-a-port"},
                          {"port": 443, "protocol": "tcp", "state": "open"},
                      ]}]
        self._common(monkeypatch, fake_db, {"10.44.0.5": 12}, scan_data)

        result = asyncio.run(wired.run_scan("10.44.0.0/24"))

        assert result.errors == []
        assert [p.port for p in result.ports["10.44.0.5"]] == [22, 443]

    def test_null_port_list_does_not_fail_the_scan(self, monkeypatch):
        fake_db = FakeDB()
        scan_data = [{"ip": "10.44.0.5", "hostname": "h",
                      "os": {"name": "Linux"}, "ports": None}]
        self._common(monkeypatch, fake_db, {"10.44.0.5": 12}, scan_data)

        result = asyncio.run(wired.run_scan("10.44.0.0/24"))

        assert result.errors == []
        assert [h.ip for h in result.hosts] == ["10.44.0.5"]
        assert result.hosts[0].os_name == "Linux"
        assert result.ports == {}
        assert any("status='DONE'" in sql for sql, _ in fake_db.executed)

    def test_failed_scan_bookkeeping_does_not_mask_the_original_error(
            self, monkeypatch):
        class BrokenUpdateDB(FakeDB):
            async def execute(self, sql, params=()):
                self.executed.append((sql, params))
                if "status='FAILED'" in sql:
                    raise RuntimeError("database is locked")

        fake_db = BrokenUpdateDB()
        notified = []

        async def boom(_network):
            raise RuntimeError("discovery exploded")

        async def notify(**kwargs):
            notified.append(kwargs)

        monkeypatch.setattr(wired, "db", fake_db)
        monkeypatch.setattr(wired, "discover_hosts", boom)
        monkeypatch.setattr(wired, "_notify_safe", notify)

        result = asyncio.run(wired.run_scan("10.44.0.0/24"))
        assert result.target == "10.44.0.0/24"
        assert result.errors and "discovery exploded" in result.errors[0]
        assert notified, "the operator must still be told the scan failed"


class TestScanDiff:
    def test_null_started_at_is_tolerated(self, monkeypatch):
        class DiffDB:
            async def fetch_one(self, sql, params=()):
                return {"started_at": None}

        monkeypatch.setattr(wired, "db", DiffDB())
        assert asyncio.run(wired.compute_scan_diff(2, 1)) == []

    def test_no_previous_scan_short_circuits_before_querying(self, monkeypatch):
        class ExplodingDB:
            async def fetch_one(self, sql, params=()):
                raise AssertionError("must not touch the DB without a previous scan")

        monkeypatch.setattr(wired, "db", ExplodingDB())
        assert asyncio.run(wired.compute_scan_diff(2, None)) == []
        assert asyncio.run(wired.compute_scan_diff(2, 0)) == []

    def test_missing_scan_row_returns_empty(self, monkeypatch):
        class DiffDB:
            async def fetch_one(self, sql, params=()):
                return None

        monkeypatch.setattr(wired, "db", DiffDB())
        assert asyncio.run(wired.compute_scan_diff(2, 1)) == []

    def test_new_and_gone_hosts_are_persisted(self, monkeypatch):
        class DiffDB:
            def __init__(self):
                self.writes = []

            async def fetch_one(self, sql, params=()):
                if params == (2,):
                    return {"started_at": 1000.0}
                return {"started_at": 500.0}

            async def fetch_all(self, sql, params=()):
                if "first_seen" in sql:
                    return [{"id": 7, "ip": "10.44.0.7"}]
                return [{"id": 9, "ip": "10.44.0.9"}]

            async def executemany(self, sql, rows):
                self.writes.append((sql, rows))

        fake = DiffDB()
        monkeypatch.setattr(wired, "db", fake)

        assert asyncio.run(wired.compute_scan_diff(2, 1)) == [
            {"type": "NEW_HOST", "ip": "10.44.0.7"},
            {"type": "GONE_HOST", "ip": "10.44.0.9"},
        ]
        assert len(fake.writes) == 1
        rows = fake.writes[0][1]
        assert [(r[1], r[2], r[8]) for r in rows] == [
            ("NEW_HOST", 7, "MEDIUM"),
            ("GONE_HOST", 9, "HIGH"),
        ]
        # Both rows belong to the current scan and carry no port/CVE.
        assert {r[0] for r in rows} == {2}
        assert all(r[3] is None and r[4] is None for r in rows)

    def test_no_drift_skips_the_insert(self, monkeypatch):
        class DiffDB:
            def __init__(self):
                self.writes = []

            async def fetch_one(self, sql, params=()):
                return {"started_at": 1000.0}

            async def fetch_all(self, sql, params=()):
                return []

            async def executemany(self, sql, rows):
                self.writes.append(rows)

        fake = DiffDB()
        monkeypatch.setattr(wired, "db", fake)

        assert asyncio.run(wired.compute_scan_diff(2, 1)) == []
        assert fake.writes == []

    def test_the_same_offline_transition_is_reported_only_once(self):
        """A host that stays offline must not re-enter the timeline each scan."""
        ip = f"10.250.{int(uuid.uuid4().hex[:2], 16)}.{int(uuid.uuid4().hex[:2], 16)}"

        async def scenario():
            await db.init()
            now = time.time()
            scan_ids = []
            for offset in (-600.0, -300.0, -290.0):
                row = await db.execute_returning(
                    "INSERT INTO scans (scan_type,target,started_at,status) "
                    "VALUES ('FULL',?,?,'DONE') RETURNING id",
                    (ip, now + offset))
                scan_ids.append(row["id"])
            host = await db.execute_returning(
                "INSERT INTO hosts (ip,is_active,first_seen,last_seen,offline_since) "
                "VALUES (?,0,?,?,?) RETURNING id",
                (ip, now - 1200, now - 60, now - 30))
            host_id = host["id"]
            try:
                first = await wired.compute_scan_diff(scan_ids[1], scan_ids[0])
                second = await wired.compute_scan_diff(scan_ids[2], scan_ids[1])
                count = await db.fetch_val(
                    "SELECT COUNT(*) FROM scan_diffs "
                    "WHERE host_id=? AND diff_type='GONE_HOST'", (host_id,))
            finally:
                await db.execute(
                    "DELETE FROM scan_diffs WHERE host_id=?", (host_id,))
                await db.execute("DELETE FROM hosts WHERE id=?", (host_id,))
                await db.execute(
                    "DELETE FROM scans WHERE id IN (?,?,?)", tuple(scan_ids))
            return first, second, count

        first, second, count = run_async(scenario())
        assert {"type": "GONE_HOST", "ip": ip} in first
        assert {"type": "GONE_HOST", "ip": ip} not in second
        assert count == 1
