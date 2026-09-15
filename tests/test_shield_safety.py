"""SHIELD safety tests — dry-run default, allowlist, validation. No iptables touched."""
import asyncio
import os
import pytest

from shield import reconfigurer as sh
from config.settings import is_ip_allowlisted


class FakeDB:
    def __init__(self, count=0):
        self.count = count
        self.inserts = []

    async def fetch_val(self, sql, params=(), default=None):
        return self.count

    async def execute(self, sql, params=()):
        self.inserts.append((sql, params))

    async def execute_returning(self, sql, params=()):
        return {"id": 1}


@pytest.fixture
def dry_env(monkeypatch):
    monkeypatch.setenv("SHIELD_DRY_RUN", "1")
    monkeypatch.setenv("SHIELD_ALLOWLIST", "")
    monkeypatch.setenv("OBSIDIOS_GATEWAY", "192.168.1.1")
    # force dry-run even if settings object cached False
    monkeypatch.setattr(sh, "_shield_cfg", lambda: (None, None, None))


def test_dry_run_refuses_block(dry_env, monkeypatch):
    monkeypatch.setattr(sh, "db", FakeDB())
    res = asyncio.run(sh.block_ip("10.0.0.99", justification="test"))
    assert res["status"] == "refused"
    assert "DRY-RUN" in res["reason"]


def test_invalid_ip_rejected(dry_env, monkeypatch):
    monkeypatch.setattr(sh, "db", FakeDB())
    res = asyncio.run(sh.block_ip("not-an-ip", justification="t"))
    assert res["status"] == "rejected"


def test_allowlist_blocks_gateway(monkeypatch):
    monkeypatch.setenv("SHIELD_DRY_RUN", "0")
    monkeypatch.setenv("SHIELD_ALLOWLIST", "192.168.1.50")
    monkeypatch.setenv("OBSIDIOS_GATEWAY", "192.168.1.1")

    async def fake_guard(ip, action):
        from config.settings import parse_shield_allowlist, is_ip_allowlisted
        allow = parse_shield_allowlist("192.168.1.1")
        if is_ip_allowlisted(ip, allow):
            return False, "Allowlisted"
        return True, "ok"
    monkeypatch.setattr(sh, "_shield_guard", fake_guard)
    monkeypatch.setattr(sh, "db", FakeDB())
    res = asyncio.run(sh.block_ip("192.168.1.1", justification="t"))
    assert res["status"] == "refused"
    assert "Allowlist" in res["reason"] or "allowlist" in res["reason"].lower()


def test_quarantine_disabled_by_default(monkeypatch):
    monkeypatch.setenv("SHIELD_AUTO_QUARANTINE", "0")
    monkeypatch.setenv("SHIELD_DRY_RUN", "0")
    monkeypatch.setattr(sh, "db", FakeDB())
    res = asyncio.run(sh.quarantine_host("10.0.0.5", justification="t"))
    assert res["status"] == "refused"
    assert "auto-quarantine" in res["reason"]


def test_is_ip_allowlisted_unit():
    assert is_ip_allowlisted("127.0.0.1", ["127.0.0.1/32"]) is True
    assert is_ip_allowlisted("10.0.0.1", ["192.168.1.0/24"]) is False
    # unparseable -> fail closed (treated as protected)
    assert is_ip_allowlisted("garbage", ["192.168.1.0/24"]) is True
