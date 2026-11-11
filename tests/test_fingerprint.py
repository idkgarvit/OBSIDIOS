"""Tests for iris/fingerprint.py — device identity heuristics."""
import asyncio

import pytest

from iris import fingerprint as fp


class TestMacVendor:
    def test_zyxel_oui_is_recognised(self):
        assert fp.lookup_mac_vendor("14:33:75:aa:bb:cc") == "Zyxel"

    def test_randomised_mac_has_no_vendor(self):
        """Locally administered addresses must not borrow a real OUI."""
        assert fp.lookup_mac_vendor("B6:88:4E:DD:A1:A4") is None
        assert fp.lookup_mac_vendor("66:BD:48:A1:86:C6") is None

    def test_unknown_and_malformed_values_are_safe(self):
        for value in (None, "", "UNKNOWN", "NOPE", 123):
            assert fp.lookup_mac_vendor(value) is None

    def test_nmap_vendor_wins_over_the_local_table(self):
        assert fp.resolve_vendor(
            "14:33:75:aa:bb:cc", "Zyxel Communications") == "Zyxel Communications"

    def test_placeholder_nmap_vendor_falls_back_to_the_oui(self):
        assert fp.resolve_vendor("14:33:75:aa:bb:cc", "Unknown") == "Zyxel"


class TestHostnameClass:
    @pytest.mark.parametrize(("hostname", "expected"), [
        ("realme-NARZO-90x-5G", fp.PHONE),
        ("Galaxy-M02s", fp.PHONE),
        ("garvit-HP-Laptop-15-db0xxx", fp.LAPTOP),
        ("DESKTOP-4F2A9C", fp.DESKTOP),
        ("BRW-Printer", fp.PRINTER),
        ("OpenWrt", fp.ROUTER),
        ("diskstation", fp.NAS),
        ("LivingRoom-TV", fp.TV),
        ("front-door-camera", fp.CAMERA),
        ("espressif-01", fp.IOT),
        ("plex-server", fp.MEDIA),
        ("proxmox-01", fp.SERVER),
    ])
    def test_device_names_are_classified(self, hostname, expected):
        assert fp.infer_device(ip="192.168.1.20", hostname=hostname) == expected

    def test_unrecognised_names_are_not_guessed(self):
        assert fp.infer_device(ip="192.168.1.2", hostname="I2011") == fp.HOST
        assert fp.infer_device(
            ip="192.168.1.10", hostname="NARUTO", os_name="Linux") == fp.HOST


class TestGatewayRole:
    def test_router_vendor_at_the_gateway_address(self):
        assert fp.infer_device(
            ip="192.168.1.1", mac="14:33:75:aa:bb:cc",
            ports=[{"port": 80}, {"port": 443}]) == fp.ROUTER

    def test_gateway_with_router_services_and_randomised_mac(self):
        assert fp.infer_device(
            ip="192.168.1.1", mac="B6:88:4E:DD:A1:A4",
            ports=[{"port": 53}, {"port": 80}]) == fp.ROUTER

    def test_gateway_without_evidence_is_not_a_router(self):
        assert fp.infer_device(ip="192.168.1.1") == fp.HOST

    def test_end_device_hostname_beats_the_gateway_guess(self):
        assert fp.infer_device(
            ip="192.168.1.1", hostname="garvit-HP-Laptop",
            ports=[{"port": 80}]) == fp.LAPTOP

    def test_router_vendor_away_from_the_gateway(self):
        assert fp.infer_device(
            ip="192.168.1.2", mac="14:33:75:aa:bb:cc") == fp.ROUTER


class TestPortRoles:
    @pytest.mark.parametrize(("ports", "expected"), [
        ([515], fp.PRINTER),
        ([631], fp.PRINTER),
        ([9100], fp.PRINTER),
        ([554], fp.CAMERA),
        ([3389], fp.DESKTOP),
        ([5432], fp.SERVER),
        ([1883], fp.IOT),
        ([32400], fp.MEDIA),
        ([8008, 8009], fp.TV),
        ([22, 80, 443], fp.HOST),
    ])
    def test_open_ports_identify_the_role(self, ports, expected):
        assert fp.infer_device(
            ip="192.168.1.30", ports=[{"port": p} for p in ports]) == expected

    @pytest.mark.parametrize("entry", [
        None, "junk", {"port": "80"}, {"port": True}, {"port": 22},
    ])
    def test_malformed_port_entries_do_not_raise(self, entry):
        assert fp.infer_device(ip="192.168.1.31", ports=[entry]) == fp.HOST


class TestVendorAndOsFallback:
    def test_virtual_machine_vendor(self):
        assert fp.infer_device(
            ip="192.168.1.40", vendor="VMware, Inc.") == fp.VM

    def test_phone_vendor_without_a_hostname(self):
        assert fp.infer_device(
            ip="192.168.1.41", mac="EC:FA:BC:11:22:33") == fp.PHONE

    def test_os_fallback(self):
        assert fp.infer_device(
            ip="192.168.1.42", os_name="Windows 11") == fp.DESKTOP
        assert fp.infer_device(
            ip="192.168.1.43", os_name="Android 14") == fp.PHONE

    def test_cisco_ios_is_a_router_os_not_an_apple_phone(self):
        assert fp.infer_device(
            ip="192.168.1.44", os_name="Cisco IOS 15.2") == fp.ROUTER


class TestNmapOuiTable:
    def test_unknown_oui_falls_back_to_nmaps_prefix_list(
            self, monkeypatch, tmp_path):
        prefixes = tmp_path / "nmap-mac-prefixes"
        prefixes.write_text(
            "# OUI table\nA45046\tRealme\n00:1A:2B  Example Corp\n")
        monkeypatch.setattr(fp, "_nmap_prefixes", None)
        monkeypatch.setattr(fp, "_NMAP_PREFIX_FILES", (str(prefixes),))

        assert fp.lookup_mac_vendor("A4:50:46:11:22:33") == "Realme"
        assert fp._nmap_oui_vendor("00:1a:2b:11:22:33") == "Example Corp"

    def test_built_in_table_wins_over_nmap(self, monkeypatch):
        monkeypatch.setattr(fp, "_nmap_prefixes", {"143375": "Wrong Vendor"})
        assert fp.lookup_mac_vendor("14:33:75:aa:bb:cc") == "Zyxel"

    def test_randomised_mac_never_consults_the_nmap_table(self, monkeypatch):
        monkeypatch.setattr(fp, "_nmap_prefixes", {"B6884E": "Some Vendor"})
        assert fp.lookup_mac_vendor("B6:88:4E:DD:A1:A4") is None

    def test_missing_prefix_file_is_not_fatal(self, monkeypatch, tmp_path):
        monkeypatch.setattr(fp, "_nmap_prefixes", None)
        monkeypatch.setattr(
            fp, "_NMAP_PREFIX_FILES", (str(tmp_path / "absent"),))
        assert fp._load_nmap_prefixes() == {}


class TestHostnameCleaning:
    def test_local_suffix_is_removed(self):
        assert fp._clean_hostname("printer.lan") == "printer"
        assert fp._clean_hostname("nas.local.") == "nas"

    @pytest.mark.parametrize("value", [
        None, "", "192.168.1.5", "localhost", "(none)",
    ])
    def test_placeholders_are_rejected(self, value):
        assert fp._clean_hostname(value, "192.168.1.5") is None


class TestReverseDns:
    def test_getent_result_is_cleaned(self, monkeypatch):
        async def fake_getent(_ip, _timeout):
            return "I2011"

        def no_ptr(_ip):
            raise OSError("no PTR")

        monkeypatch.setattr(fp.socket, "gethostbyaddr", no_ptr)
        monkeypatch.setattr(fp, "_getent_hostname", fake_getent)
        assert asyncio.run(fp.reverse_dns("192.168.1.2")) == "I2011"

    def test_a_raising_lookup_returns_none(self, monkeypatch):
        async def boom(*_a, **_k):
            raise RuntimeError("nss exploded")

        def no_ptr(_ip):
            raise OSError("no PTR")

        monkeypatch.setattr(fp.socket, "gethostbyaddr", no_ptr)
        monkeypatch.setattr(fp, "_getent_hostname", boom)
        assert asyncio.run(fp.reverse_dns("192.168.1.2")) is None

    def test_batch_resolution_survives_one_failure(self, monkeypatch):
        async def fake(ip, _timeout):
            if ip.endswith(".2"):
                raise RuntimeError("boom")
            return "host-" + ip.rsplit(".", 1)[-1]

        monkeypatch.setattr(fp, "reverse_dns", fake)
        resolved = asyncio.run(fp.resolve_hostnames(
            ["10.0.0.2", "10.0.0.3", "10.0.0.3", None, ""]))
        assert resolved == {"10.0.0.3": "host-3"}
