"""IRIS nmap parsing regressions.

nmap XML is external input. One malformed protocol, port or OS record must
not discard the rest of the host, and one malformed host record must not
abort the whole scan.
"""
import asyncio

from iris import wired_scanner as wired


class FakeHost(dict):
    def __init__(
        self,
        data=None,
        *,
        hostname="printer.lan",
        state="up",
        hostname_raises=False,
        state_raises=False,
        protocols=None,
        protocols_raise=False,
    ):
        super().__init__(data or {})
        self._hostname = hostname
        self._state = state
        self._hostname_raises = hostname_raises
        self._state_raises = state_raises
        self._protocols = ["tcp"] if protocols is None else protocols
        self._protocols_raise = protocols_raise

    def hostname(self):
        if self._hostname_raises:
            raise RuntimeError("hostname lookup failed")
        return self._hostname

    def state(self):
        if self._state_raises:
            raise RuntimeError("state lookup failed")
        return self._state

    def all_protocols(self):
        if self._protocols_raise:
            raise RuntimeError("malformed XML")
        return self._protocols


class FakeScanner:
    def __init__(self, hosts):
        self._hosts = hosts
        self.scans = []
        self.arguments = None

    def scan(self, hosts=None, arguments=None, **_kwargs):
        self.scans.append(hosts)
        self.arguments = arguments

    def all_hosts(self):
        return list(self._hosts)

    def __getitem__(self, ip):
        return self._hosts[ip]


def open_port(**fields):
    return {"state": "open", **fields}


class TestParseOpenPorts:
    def test_only_open_ports_are_reported(self):
        host = FakeHost({
            "tcp": {
                22: open_port(name="ssh"),
                80: {"state": "closed", "name": "http"},
                443: {"state": "filtered", "name": "https"},
            },
            "udp": {53: open_port(name="domain")},
        }, protocols=["tcp", "udp"])

        ports = wired._parse_open_ports(host)
        assert [(p["port"], p["protocol"]) for p in ports] == [
            (22, "tcp"), (53, "udp"),
        ]

    def test_unknown_protocols_are_ignored(self):
        host = FakeHost({
            "ip": {1: open_port(name="icmp")},
            "tcp": {22: open_port(name="ssh")},
        }, protocols=["ip", "tcp"])

        ports = wired._parse_open_ports(host)
        assert [(p["port"], p["protocol"]) for p in ports] == [(22, "tcp")]

    def test_malformed_port_record_is_skipped_not_fatal(self):
        host = FakeHost({
            "tcp": {
                22: "garbage",
                80: open_port(name="http"),
                8080: {"state": "closed"},
            },
        })

        ports = wired._parse_open_ports(host)
        assert [p["port"] for p in ports] == [80]

    def test_malformed_protocol_block_is_skipped(self):
        host = FakeHost({
            "tcp": "not-a-dict",
            "udp": {53: open_port(name="domain")},
        }, protocols=["tcp", "udp"])

        ports = wired._parse_open_ports(host)
        assert [(p["port"], p["protocol"]) for p in ports] == [(53, "udp")]

    def test_protocol_lookup_failure_is_skipped(self):
        class RaisingHost(FakeHost):
            def __getitem__(self, key):
                if key == "udp":
                    raise KeyError(key)
                return super().__getitem__(key)

        host = RaisingHost({
            "udp": {53: open_port()},
            "tcp": {22: open_port(name="ssh")},
        }, protocols=["udp", "tcp"])

        assert [p["port"] for p in wired._parse_open_ports(host)] == [22]

    def test_mixed_port_key_types_do_not_crash(self):
        # sorted() raises TypeError when int and str keys are mixed; the
        # protocol is dropped, but parsing still succeeds.
        host = FakeHost({"tcp": {22: open_port(), "ssh": open_port()}})
        assert wired._parse_open_ports(host) == []

    def test_boolean_port_keys_are_not_ports(self):
        host = FakeHost({"tcp": {True: open_port(), 22: open_port()}})
        assert [p["port"] for p in wired._parse_open_ports(host)] == [22]

    def test_all_protocols_failure_returns_empty(self):
        host = FakeHost({"tcp": {22: open_port()}}, protocols_raise=True)
        assert wired._parse_open_ports(host) == []

    def test_fields_are_bounded_strings(self):
        host = FakeHost({
            "tcp": {
                22: {
                    "state": "open",
                    "name": None,
                    "product": 123,
                    "version": "9" * 400,
                    "extrainfo": "  spaced  ",
                    "cpe": "cpe:/a:openbsd:openssh:9.0",
                },
            },
        })

        port = wired._parse_open_ports(host)[0]
        assert port["service"] == ""
        assert port["product"] == "123"
        assert len(port["version"]) == 255
        assert port["extra_info"] == "spaced"
        assert port["cpe"] == "cpe:/a:openbsd:openssh:9.0"

    def test_missing_fields_become_empty_strings(self):
        host = FakeHost({"tcp": {22: open_port()}})
        port = wired._parse_open_ports(host)[0]
        assert port == {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "",
            "product": "",
            "version": "",
            "extra_info": "",
            "cpe": "",
        }


class TestNmapScanHost:
    def _scan(self, monkeypatch, host):
        scanner = FakeScanner({"10.44.0.5": host})
        monkeypatch.setattr(wired.nmap, "PortScanner", lambda: scanner)
        return wired._nmap_scan_host("10.44.0.5", "-sV")

    def test_hostname_failure_keeps_ports(self, monkeypatch):
        host = FakeHost(
            {"tcp": {22: open_port(name="ssh")}},
            hostname_raises=True,
        )
        result = self._scan(monkeypatch, host)

        assert result["hostname"] == ""
        assert [p["port"] for p in result["ports"]] == [22]

    def test_state_failure_defaults_to_unknown(self, monkeypatch):
        host = FakeHost({"tcp": {}}, state_raises=True)
        assert self._scan(monkeypatch, host)["state"] == "unknown"

    def test_host_missing_from_result_returns_empty(self, monkeypatch):
        scanner = FakeScanner({})
        monkeypatch.setattr(wired.nmap, "PortScanner", lambda: scanner)
        assert wired._nmap_scan_host("10.44.0.5", "-sV") == {}

    def test_ports_are_kept_when_osmatch_is_junk(self, monkeypatch):
        host = FakeHost(
            {"osmatch": "junk", "tcp": {22: open_port(name="ssh")}},
        )
        # Iterating the "junk" string yields chars; none are dicts, so the OS
        # list stays empty but the ports survive.
        result = self._scan(monkeypatch, host)
        assert result["os"] == []
        assert [p["port"] for p in result["ports"]] == [22]


class TestNmapDeepScan:
    def test_no_extra_ports_does_not_invoke_nmap(self, monkeypatch):
        def must_not_run():
            raise AssertionError("nmap must not run for an empty port list")

        monkeypatch.setattr(wired.nmap, "PortScanner", must_not_run)
        assert wired._nmap_deep_scan("10.44.0.5", []) == []

    def test_targeted_ports_are_sorted_and_deduplicated(self, monkeypatch):
        scanner = FakeScanner({"10.44.0.5": FakeHost({
            "tcp": {8443: open_port(name="https-alt")},
        })})
        monkeypatch.setattr(wired.nmap, "PortScanner", lambda: scanner)

        ports = wired._nmap_deep_scan("10.44.0.5", [8443, 80, 8443])

        assert scanner.arguments.endswith("-p 80,8443")
        assert [p["port"] for p in ports] == [8443]

    def test_host_missing_from_result_returns_empty(self, monkeypatch):
        scanner = FakeScanner({})
        monkeypatch.setattr(wired.nmap, "PortScanner", lambda: scanner)
        assert wired._nmap_deep_scan("10.44.0.5", [80]) == []


class TestScanHost:
    def test_unsafe_arguments_short_circuit(self, monkeypatch):
        def must_not_run(*_a, **_k):
            raise AssertionError("nmap must not run with unsafe arguments")

        monkeypatch.setattr(
            wired, "validate_nmap_arguments", lambda _args: (False, "script use")
        )
        monkeypatch.setattr(wired, "_nmap_scan_host", must_not_run)

        assert asyncio.run(wired.scan_host("10.44.0.5", asyncio.Semaphore(1))) == {}

    def test_deep_scan_merges_new_ports_without_duplicates(self, monkeypatch):
        base = {
            "ip": "10.44.0.5",
            "hostname": "printer.lan",
            "state": "up",
            "os": [],
            "ports": [{"port": 80, "protocol": "tcp", "state": "open"}],
        }
        deep_calls = []

        def fake_primary(*_a, **_k):
            return base

        def fake_deep(ip, extra_ports):
            deep_calls.append((ip, extra_ports))
            return [
                {"port": 80, "protocol": "tcp", "state": "open"},
                {"port": 8443, "protocol": "tcp", "state": "open"},
            ]

        monkeypatch.setattr(wired, "_nmap_scan_host", fake_primary)
        monkeypatch.setattr(wired, "_nmap_deep_scan", fake_deep)

        result = asyncio.run(wired.scan_host("10.44.0.5", asyncio.Semaphore(1)))

        assert result["host_types"] == ["web_server"]
        assert deep_calls and deep_calls[0][0] == "10.44.0.5"
        assert [p["port"] for p in result["ports"]] == [80, 8443]

    def test_empty_primary_result_skips_the_deep_scan(self, monkeypatch):
        def fake_primary(*_a, **_k):
            return {}

        def must_not_run(*_a, **_k):
            raise AssertionError("deep scan must not run without a host result")

        monkeypatch.setattr(wired, "_nmap_scan_host", fake_primary)
        monkeypatch.setattr(wired, "_nmap_deep_scan", must_not_run)

        assert asyncio.run(wired.scan_host("10.44.0.5", asyncio.Semaphore(1))) == {}

    def test_malformed_port_entries_do_not_crash_type_detection(self, monkeypatch):
        base = {
            "ip": "10.44.0.5",
            "ports": ["junk", {"protocol": "tcp"}, {"port": 22}],
        }

        def fake_primary(*_a, **_k):
            return base

        def fake_deep(*_a, **_k):
            return []

        monkeypatch.setattr(wired, "_nmap_scan_host", fake_primary)
        monkeypatch.setattr(wired, "_nmap_deep_scan", fake_deep)

        result = asyncio.run(wired.scan_host("10.44.0.5", asyncio.Semaphore(1)))
        assert result["host_types"] == ["default"]


class TestScanHostsConcurrent:
    def test_malformed_host_entries_are_skipped(self, monkeypatch):
        called = []

        async def fake_scan(ip, _sem):
            called.append(ip)
            return {"ip": ip}

        monkeypatch.setattr(wired, "scan_host", fake_scan)

        results = asyncio.run(wired.scan_hosts_concurrent([
            {"ip": "10.0.0.1"},
            {"mac": "aa:bb:cc:dd:ee:ff"},
            "junk",
            {"ip": 42},
            {"ip": ""},
        ]))

        assert called == ["10.0.0.1"]
        assert results == [{"ip": "10.0.0.1"}]


class TestDetectHostType:
    def test_multiple_signatures_are_all_reported(self):
        assert wired._detect_host_type([80, 3306, 445]) == [
            "web_server", "database", "file_share",
        ]

    def test_unknown_ports_fall_back_to_default(self):
        assert wired._detect_host_type([12345]) == ["default"]

    def test_no_open_ports_fall_back_to_default(self):
        assert wired._detect_host_type([]) == ["default"]


class TestInferOsFromMac:
    def test_empty_mac_keeps_the_nmap_guess(self):
        assert wired._infer_os_from_mac("", "Linux", 90) == ("Linux", 90)

    def test_unknown_oui_keeps_the_nmap_guess(self):
        assert wired._infer_os_from_mac(
            "00:11:22:33:44:55", "Windows", 50
        ) == ("Windows", 50)

    def test_confident_nmap_guess_is_not_overridden(self):
        assert wired._infer_os_from_mac(
            "3C:07:54:11:22:33", "Linux", 80
        ) == ("Linux", 80)

    def test_mobile_oui_overrides_a_weak_guess(self):
        assert wired._infer_os_from_mac(
            "EC:FA:BC:11:22:33", "Linux", 40
        ) == ("Android", 30)

    def test_missing_nmap_accuracy_becomes_zero(self):
        assert wired._infer_os_from_mac(
            "3c-07-54-11-22-33", "Linux", None
        ) == ("Apple iOS", 0)

    def test_negative_accuracy_is_capped_at_zero(self):
        assert wired._infer_os_from_mac(
            "EC:FA:BC:11:22:33", None, -5
        ) == ("Android", 0)


class TestGetTargetFromDb:
    def _patch_db(self, monkeypatch, fetch_val):
        monkeypatch.setattr(wired.db, "_initialized", True)
        monkeypatch.setattr(wired.db, "fetch_val", fetch_val)

    def test_returns_the_stored_target(self, monkeypatch):
        async def stored(*_a, **_k):
            return "10.5.0.0/24"

        self._patch_db(monkeypatch, stored)
        assert asyncio.run(wired.get_target_from_db()) == "10.5.0.0/24"

    def test_empty_setting_falls_back_to_config(self, monkeypatch):
        async def empty(*_a, **_k):
            return ""

        self._patch_db(monkeypatch, empty)
        assert asyncio.run(wired.get_target_from_db()) == wired.scan_cfg.target_network

    def test_database_failure_falls_back_to_config(self, monkeypatch):
        async def boom(*_a, **_k):
            raise RuntimeError("database is locked")

        self._patch_db(monkeypatch, boom)
        assert asyncio.run(wired.get_target_from_db()) == wired.scan_cfg.target_network


class RecordingDB:
    def __init__(self):
        self.inserts = []

    async def execute_returning(self, sql, params=()):
        self.inserts.append((sql, params))
        return {"id": len(self.inserts)}


class TestUpsertHosts:
    def test_routed_nmap_host_without_arp_is_persisted(self, monkeypatch):
        fake_db = RecordingDB()
        monkeypatch.setattr(wired, "db", fake_db)

        ids = asyncio.run(wired._upsert_hosts(
            [],
            [{"ip": "10.44.0.9", "hostname": "printer.lan", "os": []}],
        ))

        assert ids == {"10.44.0.9": 1}
        assert len(fake_db.inserts) == 1

    def test_unknown_mac_is_stored_as_null(self, monkeypatch):
        fake_db = RecordingDB()
        monkeypatch.setattr(wired, "db", fake_db)

        asyncio.run(wired._upsert_hosts(
            [{"ip": "10.44.0.9", "mac": "UNKNOWN"}], [],
        ))

        assert fake_db.inserts[0][1][1] is None

    def test_non_string_mac_is_not_bound_to_sqlite(self, monkeypatch):
        fake_db = RecordingDB()
        monkeypatch.setattr(wired, "db", fake_db)

        ids = asyncio.run(wired._upsert_hosts(
            [{"ip": "10.44.0.9", "mac": 12345}], [],
        ))

        assert ids == {"10.44.0.9": 1}
        assert fake_db.inserts[0][1][1] is None

    def test_os_mapping_is_not_indexed_as_a_list(self, monkeypatch):
        """A scanner returning one OS dict instead of a list must not crash."""
        fake_db = RecordingDB()
        monkeypatch.setattr(wired, "db", fake_db)

        ids = asyncio.run(wired._upsert_hosts(
            [], [{"ip": "10.44.0.9", "os": {"name": "Linux", "accuracy": 90}}],
        ))

        assert ids == {"10.44.0.9": 1}
        params = fake_db.inserts[0][1]
        assert params[3] == "Linux"
        assert params[4] == 90

    def test_hosts_without_a_usable_ip_are_skipped(self, monkeypatch):
        fake_db = RecordingDB()
        monkeypatch.setattr(wired, "db", fake_db)

        ids = asyncio.run(wired._upsert_hosts(
            [{"mac": "aa:bb:cc:dd:ee:ff"}, "junk", {"ip": 42}, {"ip": "   "}],
            [{"hostname": "no-ip"}, None, {"ip": ""}],
        ))

        assert ids == {}
        assert fake_db.inserts == []


class ScanDB:
    def __init__(self):
        self.executed = []

    async def execute_returning(self, sql, params=()):
        self.executed.append((sql, params))
        return {"id": 7}

    async def execute(self, sql, params=()):
        self.executed.append((sql, params))

    async def fetch_val(self, *_a, **_k):
        return ""


class TestRunScanMalformedResults:
    def test_malformed_scan_entry_does_not_fail_the_scan(self, monkeypatch):
        fake_db = ScanDB()
        monkeypatch.setattr(wired, "db", fake_db)

        async def hosts(_network):
            return [{"ip": "10.44.0.5", "mac": "AA:BB:CC:DD:EE:FF"}]

        async def scanned(_hosts):
            return [
                "junk",
                {"ip": "10.44.0.5", "hostname": "h", "os": [],
                 "ports": [{"port": 22, "protocol": "tcp",
                            "state": "open", "service": "ssh"}]},
            ]

        async def upsert(*_a, **_k):
            return {"10.44.0.5": 12}

        async def ports(*_a, **_k):
            return 1

        async def offline(*_a, **_k):
            return 0

        monkeypatch.setattr(wired, "discover_hosts", hosts)
        monkeypatch.setattr(wired, "scan_hosts_concurrent", scanned)
        monkeypatch.setattr(wired, "_upsert_hosts", upsert)
        monkeypatch.setattr(wired, "_upsert_ports", ports)
        monkeypatch.setattr(wired, "_mark_missing_hosts_offline", offline)

        result = asyncio.run(wired.run_scan("10.44.0.0/24"))

        assert result.errors == []
        assert [h.ip for h in result.hosts] == ["10.44.0.5"]
        assert any("status='DONE'" in sql for sql, _ in fake_db.executed)
        assert not any("status='FAILED'" in sql for sql, _ in fake_db.executed)
