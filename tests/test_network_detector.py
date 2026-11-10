"""config/network_detector.py regressions.

Auto-detection runs with operator-provided interface names and whatever the
host's routing table says. A mis-parse here can turn one detection into a
16-million-host scan or make the sensor watch the wrong link.
"""
import subprocess

import pytest

from config import network_detector as nd


class FakeSocket:
    def __init__(self, ip="10.0.0.5"):
        self.ip = ip
        self.closed = False
        self.timeout = None
        self.target = None

    def settimeout(self, value):
        self.timeout = value

    def connect(self, target):
        self.target = target

    def getsockname(self):
        return (self.ip, 12345)

    def close(self):
        self.closed = True


def _completed(stdout: str):
    return subprocess.CompletedProcess(
        args=["ip"], returncode=0, stdout=stdout, stderr=""
    )


class TestDefaultInterface:
    def test_veth_suffix_is_stripped(self, monkeypatch):
        monkeypatch.setattr(
            nd.subprocess, "run",
            lambda *a, **k: _completed(
                "default via 10.0.0.1 dev eth0@if42 proto dhcp src 10.0.0.5\n"
            ),
        )
        assert nd.get_default_interface() == "eth0"

    def test_no_default_route_falls_back(self, monkeypatch):
        monkeypatch.setattr(nd.subprocess, "run", lambda *a, **k: _completed(""))
        assert nd.get_default_interface() == "eth0"

    def test_command_failure_falls_back(self, monkeypatch):
        def boom(*_a, **_k):
            raise OSError("ip not installed")

        monkeypatch.setattr(nd.subprocess, "run", boom)
        assert nd.get_default_interface() == "eth0"


class TestLocalInterfaceAddress:
    @pytest.mark.parametrize("name", ["--all", "-o", "eth0;reboot", "-I", "eth0 -j DROP"])
    def test_unsafe_interface_names_are_rejected(self, name, monkeypatch):
        calls = []
        monkeypatch.setattr(nd.subprocess, "run", lambda *a, **k: calls.append(a))
        assert nd.get_local_ip(name) is None
        assert calls == []

    def test_interface_name_validator(self):
        for good in ("eth0", "wlan0", "br-abc123", "veth0.1"):
            assert nd._valid_iface(good) is True
        for bad in ("--all", "-o", "", None, "eth0 -j DROP", "a" * 65):
            assert nd._valid_iface(bad) is False

    def test_interface_without_ipv4_does_not_fall_back(self, monkeypatch):
        monkeypatch.setattr(
            nd.subprocess, "run",
            lambda *a, **k: _completed(
                "2: eth0: <UP>\n"
                "    inet6 fe80::1/64 scope link\n"
            ),
        )
        assert nd.get_local_ip("eth0") is None

    def test_interface_address_is_parsed(self, monkeypatch):
        monkeypatch.setattr(
            nd.subprocess, "run",
            lambda *a, **k: _completed("    inet 10.1.2.3/24 brd 10.1.2.255 scope global eth0\n"),
        )
        assert nd.get_local_ip("eth0") == "10.1.2.3"

    def test_route_lookup_socket_is_closed(self, monkeypatch):
        sock = FakeSocket("10.0.0.5")
        monkeypatch.setattr(nd.socket, "socket", lambda *_a: sock)
        assert nd.get_local_ip() == "10.0.0.5"
        assert sock.closed is True
        assert sock.timeout == 2.0

    def test_route_lookup_socket_is_closed_on_failure(self, monkeypatch):
        sock = FakeSocket()

        def no_route(_target):
            raise OSError("network unreachable")

        sock.connect = no_route
        monkeypatch.setattr(nd.socket, "socket", lambda *_a: sock)
        # No route to the internet: the offline fallback also finds nothing.
        monkeypatch.setattr(nd, "get_default_interface", lambda: "eth0")
        monkeypatch.setattr(nd, "_interface_ipv4", lambda _name: None)
        assert nd.get_local_ip() is None
        assert sock.closed is True

    def test_offline_host_falls_back_to_default_interface(self, monkeypatch):
        """An air-gapped sensor box still reports its own address."""
        sock = FakeSocket()

        def no_route(_target):
            raise OSError("network unreachable")

        sock.connect = no_route
        monkeypatch.setattr(nd.socket, "socket", lambda *_a: sock)
        monkeypatch.setattr(nd, "get_default_interface", lambda: "eth0")
        monkeypatch.setattr(nd, "_interface_ipv4", lambda name: (
            "192.168.9.7" if name == "eth0" else None))
        assert nd.get_local_ip() == "192.168.9.7"


class TestGatewayAndNetmask:
    def test_gateway_is_restricted_to_the_interface(self, monkeypatch):
        out = (
            "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"
            "default via 10.0.0.1 dev eth0 proto dhcp metric 100\n"
        )
        monkeypatch.setattr(nd.subprocess, "run", lambda *a, **k: _completed(out))
        assert nd._get_gateway("eth0") == "10.0.0.1"
        assert nd._get_gateway("wlan0") == "192.168.1.1"

    def test_unknown_interface_has_no_gateway(self, monkeypatch):
        monkeypatch.setattr(
            nd.subprocess, "run",
            lambda *a, **k: _completed("default via 10.0.0.1 dev eth0\n"),
        )
        assert nd._get_gateway("wlan9") is None

    def test_netmask_is_dotted_as_documented(self, monkeypatch):
        monkeypatch.setattr(
            nd.subprocess, "run",
            lambda *a, **k: _completed("    inet 10.20.30.40/24 brd 10.20.30.255\n"),
        )
        assert nd._get_netmask("eth0") == "255.255.255.0"

    def test_bogus_prefix_is_ignored(self, monkeypatch):
        monkeypatch.setattr(
            nd.subprocess, "run",
            lambda *a, **k: _completed("    inet 10.20.30.40/99 brd x\n"),
        )
        assert nd._get_netmask("eth0") is None

    @pytest.mark.parametrize("name", ["--all", "-o", "", "eth0 -j DROP"])
    def test_netmask_rejects_unsafe_interface_names(self, name, monkeypatch):
        calls = []
        monkeypatch.setattr(nd.subprocess, "run", lambda *a, **k: calls.append(a))
        assert nd._get_netmask(name) is None
        assert calls == []


class TestCidrGuessing:
    def test_guess_is_always_slash_24(self):
        assert nd._guess_cidr("10.20.30.40") == "10.20.30.0/24"
        assert nd._guess_cidr("172.16.5.4") == "172.16.5.0/24"

    def test_guess_handles_garbage(self):
        assert nd._guess_cidr("not-an-ip") == "192.168.1.0/24"

    def test_broad_netmask_is_clamped_to_24(self):
        assert nd._clamp_cidr("10.0.0.0/8", "10.20.30.40") == "10.20.30.0/24"

    def test_reasonable_netmask_is_preserved(self):
        assert nd._clamp_cidr("10.20.0.0/16", "10.20.30.40") == "10.20.0.0/16"
        assert nd._clamp_cidr("10.20.30.0/24", "10.20.30.40") == "10.20.30.0/24"


class TestDetectNetwork:
    def test_missing_local_ip_is_reported(self, monkeypatch):
        monkeypatch.setattr(nd, "get_default_interface", lambda: "eth0")
        monkeypatch.setattr(nd, "get_local_ip", lambda _name: None)
        result = nd.detect_network()
        assert result["interface"] == "eth0"
        assert result["cidr"] is None
        assert "error" in result

    def test_broad_netmask_is_clamped(self, monkeypatch):
        monkeypatch.setattr(nd, "get_default_interface", lambda: "eth0")
        monkeypatch.setattr(nd, "get_local_ip", lambda _name: "10.20.30.40")
        monkeypatch.setattr(nd, "_get_gateway", lambda _name: "10.20.0.1")
        monkeypatch.setattr(nd, "_get_netmask", lambda _name: "8")
        result = nd.detect_network()
        assert result["cidr"] == "10.20.30.0/24"
        assert result["gateway"] == "10.20.0.1"

    def test_missing_netmask_falls_back_to_slash_24(self, monkeypatch):
        monkeypatch.setattr(nd, "get_default_interface", lambda: "eth0")
        monkeypatch.setattr(nd, "get_local_ip", lambda _name: "192.168.7.9")
        monkeypatch.setattr(nd, "_get_gateway", lambda _name: "192.168.7.1")
        monkeypatch.setattr(nd, "_get_netmask", lambda _name: None)
        assert nd.detect_network()["cidr"] == "192.168.7.0/24"
