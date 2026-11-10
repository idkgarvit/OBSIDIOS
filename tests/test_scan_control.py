"""Scan-control regressions.

An operator's dashboard choices must reach the scanner without a restart, and
a cancelled scan must not persist a partial sweep as the network's truth.
"""
from __future__ import annotations

import asyncio

from config.settings import scan as scan_cfg
from iris import wired_scanner as wired


class _ProfileDB:
    _initialized = True

    def __init__(self, profile):
        self.profile = profile
        self.queries: list[str] = []

    async def fetch_val(self, sql, params=(), default=None):
        self.queries.append(sql)
        if "scan_profile" in sql:
            return self.profile
        return default


class _CancelDB:
    """Answers scan-status probes in the order run_scan makes them."""

    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.executed: list[tuple[str, tuple]] = []

    async def execute_returning(self, sql, params=()):
        self.executed.append((sql, params))
        return {"id": 7}

    async def execute(self, sql, params=()):
        self.executed.append((sql, params))

    async def fetch_val(self, sql, params=(), default=None):
        if "status FROM scans" in sql:
            return self.statuses.pop(0) if self.statuses else default
        return default


class TestProfileResolution:
    def test_dashboard_profile_beats_the_startup_default(self, monkeypatch):
        fake = _ProfileDB("STEALTH")
        monkeypatch.setattr(wired, "db", fake)
        monkeypatch.setattr(scan_cfg, "nmap_arguments", "")
        monkeypatch.setattr(scan_cfg, "scan_profile", "FAST")

        assert asyncio.run(wired._effective_nmap_args()) == (
            scan_cfg.SCAN_PROFILES["STEALTH"])

    def test_unknown_saved_profile_falls_back_to_the_startup_default(
            self, monkeypatch):
        fake = _ProfileDB("NOT-A-PROFILE")
        monkeypatch.setattr(wired, "db", fake)
        monkeypatch.setattr(scan_cfg, "nmap_arguments", "")
        monkeypatch.setattr(scan_cfg, "scan_profile", "STEALTH")

        assert asyncio.run(wired._effective_nmap_args()) == (
            scan_cfg.SCAN_PROFILES["STEALTH"])

    def test_explicit_nmap_arguments_remain_the_final_override(
            self, monkeypatch):
        fake = _ProfileDB("STEALTH")
        monkeypatch.setattr(wired, "db", fake)
        monkeypatch.setattr(scan_cfg, "nmap_arguments", "-sV -T4 --top-ports 10")
        monkeypatch.setattr(scan_cfg, "scan_profile", "FAST")

        assert asyncio.run(wired._effective_nmap_args()) == (
            "-sV -T4 --top-ports 10")

    def test_every_host_in_a_sweep_uses_the_resolved_profile(self, monkeypatch):
        captured = []

        def fake_nmap(ip, args):
            captured.append((ip, args))
            return {}

        async def resolved():
            return scan_cfg.SCAN_PROFILES["STEALTH"]

        monkeypatch.setattr(wired, "_nmap_scan_host", fake_nmap)
        monkeypatch.setattr(wired, "_effective_nmap_args", resolved)

        asyncio.run(wired.scan_hosts_concurrent(
            [{"ip": "10.44.0.5"}, {"ip": "10.44.0.6"}]))

        # Host scans run concurrently, so order is not part of the contract.
        assert sorted(captured) == sorted([
            ("10.44.0.5", scan_cfg.SCAN_PROFILES["STEALTH"]),
            ("10.44.0.6", scan_cfg.SCAN_PROFILES["STEALTH"]),
        ])


class TestCancellation:
    def _patch_notify(self, monkeypatch):
        async def noop(**_kwargs):
            return None

        monkeypatch.setattr(wired, "_notify_safe", noop)

    def test_cancel_before_host_scanning_skips_the_sweep(self, monkeypatch):
        fake = _CancelDB(["CANCELLED"])
        swept = []

        async def hosts(_target):
            return [{"ip": "10.44.0.5", "mac": "AA:BB:CC:DD:EE:01"}]

        async def scan(_hosts):
            swept.append(True)
            return []

        monkeypatch.setattr(wired, "db", fake)
        monkeypatch.setattr(wired, "discover_hosts", hosts)
        monkeypatch.setattr(wired, "scan_hosts_concurrent", scan)
        monkeypatch.setattr(wired, "get_target_from_db",
                            lambda: _value("10.44.0.0/24"))
        self._patch_notify(monkeypatch)

        result = asyncio.run(wired.run_scan())

        assert swept == []
        assert any("cancelled" in error.lower() for error in result.errors)

    def test_cancel_mid_sweep_discards_partial_results(self, monkeypatch):
        fake = _CancelDB(["RUNNING", "CANCELLED"])
        persisted = []

        async def hosts(_target):
            return [{"ip": "10.44.0.5", "mac": "AA:BB:CC:DD:EE:01"}]

        async def scan(_hosts):
            return [{"ip": "10.44.0.5", "ports": [
                {"port": 22, "protocol": "tcp", "state": "open"}]}]

        async def upsert(*_args, **_kwargs):
            persisted.append(True)
            return {}

        monkeypatch.setattr(wired, "db", fake)
        monkeypatch.setattr(wired, "discover_hosts", hosts)
        monkeypatch.setattr(wired, "scan_hosts_concurrent", scan)
        monkeypatch.setattr(wired, "_upsert_hosts", upsert)
        monkeypatch.setattr(wired, "get_target_from_db",
                            lambda: _value("10.44.0.0/24"))
        self._patch_notify(monkeypatch)

        result = asyncio.run(wired.run_scan())

        assert persisted == []
        assert any("cancelled" in error.lower() for error in result.errors)
        assert not any("status='DONE'" in sql for sql, _ in fake.executed)


async def _value(target):
    return target
