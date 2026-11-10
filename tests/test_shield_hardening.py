"""SHIELD enforcement hardening regressions.

These tests never touch iptables: every command path is replaced, and the
assertions are about what SHIELD *decides* to do.
"""
import asyncio
import json

import pytest

from shield import reconfigurer as sh


class FakeDB:
    def __init__(self, row=None, count=0, fail=False):
        self.row = row
        self.count = count
        self.fail = fail
        self.calls = []

    async def fetch_val(self, sql, params=(), default=None):
        if self.fail:
            raise RuntimeError("database unavailable")
        return self.count

    async def fetch_one(self, sql, params=()):
        self.calls.append((sql, params))
        return self.row

    async def fetch_all(self, sql, params=()):
        self.calls.append((sql, params))
        return []

    async def execute(self, sql, params=()):
        self.calls.append((sql, params))

    async def execute_returning(self, sql, params=()):
        self.calls.append((sql, params))
        return {"id": 9}


class FakeCfg:
    max_actions_per_hour = 10
    dry_run = False


@pytest.fixture
def enforcing(monkeypatch):
    from config.settings import is_ip_allowlisted, parse_shield_allowlist

    monkeypatch.setenv("SHIELD_DRY_RUN", "0")
    monkeypatch.setenv("SHIELD_AUTO_QUARANTINE", "0")
    monkeypatch.setenv("SHIELD_ALLOWLIST", "")
    monkeypatch.setenv("OBSIDIOS_GATEWAY", "192.168.1.1")
    monkeypatch.setattr(
        sh, "_shield_cfg",
        lambda: (FakeCfg(), parse_shield_allowlist, is_ip_allowlisted),
    )


def test_rate_limit_check_failure_fails_closed(enforcing, monkeypatch):
    db = FakeDB(fail=True)
    monkeypatch.setattr(sh, "db", db)
    iptables_calls = []

    async def fake_iptables(*args, **_kwargs):
        iptables_calls.append(args)
        return True, ""

    monkeypatch.setattr(sh, "_run_iptables", fake_iptables)

    result = asyncio.run(sh.block_ip("10.20.0.5", justification="test"))
    assert result["status"] == "refused"
    assert "rate-limit" in result["reason"]
    assert iptables_calls == []


def test_block_path_dedupe_includes_protocol(enforcing, monkeypatch):
    db = FakeDB()
    monkeypatch.setattr(sh, "db", db)

    async def no_rule(_chain, _spec):
        return False

    async def applied(rules):
        return True, "ok"

    monkeypatch.setattr(sh, "_iptables_rule_exists", no_rule)
    monkeypatch.setattr(sh, "_apply_rules", applied)

    result = asyncio.run(
        sh.block_path("10.20.0.5", "10.20.0.9", 53, protocol="udp",
                      justification="dns tunnel")
    )
    assert result["status"] == "blocked"

    dedupe_sql, dedupe_params = next(
        (sql, params) for sql, params in db.calls if "FROM shield_actions" in sql
    )
    assert "rule_applied LIKE" in dedupe_sql
    assert dedupe_params[-1] == "%-p udp%"


def test_quarantine_dedupes_existing_rules(enforcing, monkeypatch):
    monkeypatch.setenv("SHIELD_AUTO_QUARANTINE", "1")
    monkeypatch.setattr(sh, "db", FakeDB())

    async def exists(_chain, _spec):
        return True

    async def applied(_rules):
        raise AssertionError("_apply_rules must not run for an existing quarantine")

    monkeypatch.setattr(sh, "_iptables_rule_exists", exists)
    monkeypatch.setattr(sh, "_apply_rules", applied)

    result = asyncio.run(sh.quarantine_host("10.20.0.7", justification="test"))
    assert result["status"] == "already_exists"


def test_revert_refused_row_never_removes_live_rules(monkeypatch):
    row = {
        "id": 1,
        "action_type": "BLOCK_IP",
        "target_ip": "10.20.0.5",
        "src_ip": None,
        "rule_applied": "REFUSED: DRY-RUN active",
        "is_active": 0,
    }
    monkeypatch.setattr(sh, "db", FakeDB(row=row))

    async def must_not_run(_rules):
        raise AssertionError("refused rows have no rules to remove")

    monkeypatch.setattr(sh, "_remove_rules", must_not_run)
    assert asyncio.run(sh.revert_action(1)) is False


def test_revert_block_ip_without_target_is_refused(monkeypatch):
    row = {
        "id": 2,
        "action_type": "BLOCK_IP",
        "target_ip": None,
        "src_ip": None,
        "rule_applied": "-I INPUT -s 10.20.0.5 -j DROP",
        "is_active": 1,
    }
    monkeypatch.setattr(sh, "db", FakeDB(row=row))
    assert asyncio.run(sh.revert_action(2)) is False


def test_revert_block_path_reconstructs_udp_rule(monkeypatch):
    row = {
        "id": 3,
        "action_type": "BLOCK_PATH",
        "target_ip": "10.20.0.9",
        "src_ip": "10.20.0.5",
        "target_port": 53,
        "rule_applied": "-A FORWARD -s 10.20.0.5 -d 10.20.0.9 -p udp --dport 53 -j DROP",
        "is_active": 1,
    }
    db = FakeDB(row=row)
    monkeypatch.setattr(sh, "db", db)
    captured = {}

    async def fake_delete(chain, spec, max_tries=5):
        captured["chain"] = chain
        captured["spec"] = spec
        return True

    monkeypatch.setattr(sh, "_delete_rule", fake_delete)

    assert asyncio.run(sh.revert_action(3)) is True
    assert captured["chain"] == "FORWARD"
    assert captured["spec"] == (
        "-s", "10.20.0.5", "-d", "10.20.0.9", "-p", "udp",
        "--dport", "53", "-j", "DROP",
    )
    assert any("is_active=0" in sql for sql, _ in db.calls)


def test_close_phantom_paths_ignores_malformed_steps(monkeypatch):
    class FakeDB:
        async def fetch_all(self, *_a, **_k):
            return [
                {"id": 1, "attacker_roi": 9.0, "path_json": json.dumps([1, 2])},
                {"id": 2, "attacker_roi": 5.0, "path_json": json.dumps([
                    {"ip": "10.20.0.5"},
                    {"ip": "10.20.0.9", "technique": "T1021.004"},
                ])},
            ]

    monkeypatch.setattr(sh, "db", FakeDB())
    calls = []

    async def fake_block_path(**kwargs):
        calls.append(kwargs)
        return {"status": "blocked"}

    monkeypatch.setattr(sh, "block_path", fake_block_path)
    actions = asyncio.run(sh.close_phantom_paths())

    assert len(actions) == 1
    assert len(calls) == 1
    assert calls[0]["dst_port"] == 22
    assert calls[0]["trigger_id"] == 2


def test_close_phantom_paths_escapes_untrusted_markup(monkeypatch, capsys):
    """path_json is untrusted; a `[/]` in an address must not abort SHIELD.

    The malformed address is rejected by block_path(), but the result was then
    printed through Rich markup, which raised MarkupError and skipped every
    remaining path.
    """
    class DB:
        async def fetch_all(self, *_a, **_k):
            return [{
                "id": 1,
                "attacker_roi": 9.0,
                "path_json": json.dumps([
                    {"ip": "10.20.0.5"},
                    {"ip": "10.20.0.9[/]", "technique": "T1021.004"},
                ]),
            }]

    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setattr(sh, "db", DB())

    actions = asyncio.run(sh.close_phantom_paths())

    assert len(actions) == 1
    assert actions[0]["status"] == "rejected"
    out = capsys.readouterr().out
    assert "10.20.0.9[/]" in out


def test_respond_normalizes_protocol_case(monkeypatch):
    seen = {}

    async def fake_block_path(**kwargs):
        seen.update(kwargs)
        return {"status": "blocked"}

    monkeypatch.setattr(sh, "block_path", fake_block_path)
    result = asyncio.run(sh.respond_to_sentinel_alert({
        "src_ip": "10.20.0.5",
        "dst_ip": "10.20.0.9",
        "dst_port": 443,
        "protocol": "TCP",
        "predicted": True,
    }))
    assert result == {"status": "blocked"}
    assert seen["protocol"] == "tcp"


def test_allowlist_unavailable_fails_closed(monkeypatch):
    """If the allowlist cannot be imported, SHIELD must not enforce anything."""
    monkeypatch.setenv("SHIELD_DRY_RUN", "0")
    monkeypatch.setattr(sh, "_shield_cfg", lambda: (None, None, None))
    monkeypatch.setattr(sh, "db", FakeDB())

    async def must_not_run(*_a, **_k):
        raise AssertionError("iptables must not run without an allowlist")

    monkeypatch.setattr(sh, "_run_iptables", must_not_run)

    result = asyncio.run(sh.block_ip("10.20.0.5", justification="test"))
    assert result["status"] == "refused"
    assert "Allowlist unavailable" in result["reason"]


def test_revert_block_path_without_structured_columns_is_graceful(monkeypatch):
    """A legacy BLOCK_PATH row must not crash the revert endpoint."""
    row = {
        "id": 4,
        "action_type": "BLOCK_PATH",
        "target_ip": "10.20.0.9",
        "src_ip": None,
        "target_port": 445,
        "rule_applied": "legacy unparseable rule",
        "is_active": 1,
    }
    monkeypatch.setattr(sh, "db", FakeDB(row=row))

    async def must_not_run(*_args, **_kwargs):
        raise AssertionError("nothing can be deleted without a rule spec")

    monkeypatch.setattr(sh, "_delete_rule", must_not_run)
    assert asyncio.run(sh.revert_action(4)) is False


def test_revert_block_path_legacy_dash_a_rule_is_parsed(monkeypatch):
    row = {
        "id": 5,
        "action_type": "BLOCK_PATH",
        "target_ip": "10.20.0.9",
        "src_ip": None,
        "target_port": None,
        "rule_applied": "-A FORWARD -s 10.20.0.5 -d 10.20.0.9 -p tcp -j DROP",
        "is_active": 1,
    }
    db = FakeDB(row=row)
    monkeypatch.setattr(sh, "db", db)
    captured = {}

    async def fake_delete(chain, spec, max_tries=5):
        captured["chain"] = chain
        captured["spec"] = spec
        return True

    monkeypatch.setattr(sh, "_delete_rule", fake_delete)
    assert asyncio.run(sh.revert_action(5)) is True
    assert captured["chain"] == "FORWARD"
    assert captured["spec"] == (
        "-s", "10.20.0.5", "-d", "10.20.0.9", "-p", "tcp", "-j", "DROP",
    )


def test_revert_block_path_null_port_uses_recorded_dport(monkeypatch):
    """A NULL target_port must not turn a ported revert into a portless one.

    block_path() records the exact `-A` line. Rebuilding from columns without
    the port produced a different spec, so _delete_rule found nothing to
    delete while the live `--dport 22` DROP rule stayed up and the row was
    marked reverted.
    """
    row = {
        "id": 6,
        "action_type": "BLOCK_PATH",
        "target_ip": "10.20.0.9",
        "src_ip": "10.20.0.5",
        "target_port": None,
        "rule_applied": (
            "-A FORWARD -s 10.20.0.5 -d 10.20.0.9 -p tcp --dport 22 -j DROP"
        ),
        "is_active": 1,
    }
    db = FakeDB(row=row)
    monkeypatch.setattr(sh, "db", db)
    captured = {}

    async def fake_delete(chain, spec, max_tries=5):
        captured["chain"] = chain
        captured["spec"] = spec
        return True

    monkeypatch.setattr(sh, "_delete_rule", fake_delete)

    assert asyncio.run(sh.revert_action(6)) is True
    assert captured["chain"] == "FORWARD"
    assert captured["spec"] == (
        "-s", "10.20.0.5", "-d", "10.20.0.9", "-p", "tcp",
        "--dport", "22", "-j", "DROP",
    )
    assert any("is_active=0" in sql for sql, _ in db.calls)


def test_revert_block_path_unparseable_ported_row_is_refused(monkeypatch):
    """Never report a ported rule reverted when its port cannot be recovered."""
    row = {
        "id": 7,
        "action_type": "BLOCK_PATH",
        "target_ip": "10.20.0.9",
        "src_ip": "10.20.0.5",
        "target_port": None,
        "rule_applied": "legacy unparseable rule",
        "is_active": 1,
    }
    db = FakeDB(row=row)
    monkeypatch.setattr(sh, "db", db)

    async def must_not_run(*_args, **_kwargs):
        raise AssertionError("a portless tcp rebuild cannot match the live rule")

    monkeypatch.setattr(sh, "_delete_rule", must_not_run)

    assert asyncio.run(sh.revert_action(7)) is False
    assert not any("is_active=0" in sql for sql, _ in db.calls)


class FailingWriteDB(FakeDB):
    def __init__(self, exc=RuntimeError("disk I/O error")):
        super().__init__()
        self.exc = exc

    async def execute_returning(self, sql, params=()):
        self.calls.append((sql, params))
        raise self.exc


class MissingIdDB(FakeDB):
    async def execute_returning(self, sql, params=()):
        self.calls.append((sql, params))
        return None


class TestRevertSharedRules:
    """QUARANTINE_HOST and BLOCK_IP install overlapping INPUT/FORWARD drops.

    Because _apply_rules skips rules that already exist, one action can be
    recorded without owning every rule in its template. Reverting it used to
    delete rules the other active action still relied on, while that row stayed
    is_active=1 — the dashboard advertised a block with no kernel rule behind it.
    """

    class DB:
        def __init__(self, row, other):
            self.row = row
            self.other = other
            self.calls = []

        async def fetch_one(self, sql, params=()):
            self.calls.append((sql, params))
            return self.row

        async def fetch_all(self, sql, params=()):
            self.calls.append((sql, params))
            return self.other

        async def execute(self, sql, params=()):
            self.calls.append((sql, params))

    def test_reverting_quarantine_keeps_the_active_block_ip_rules(self, monkeypatch):
        row = {
            "id": 11,
            "action_type": "QUARANTINE_HOST",
            "target_ip": "10.20.0.5",
            "src_ip": None,
            "rule_applied": "QUARANTINE 10.20.0.5 (INPUT/OUTPUT/FORWARD DROP)",
            "is_active": 1,
        }
        other = [{
            "action_type": "BLOCK_IP",
            "target_ip": "10.20.0.5",
            "rule_applied": "-I INPUT -s 10.20.0.5 -j DROP",
        }]
        db = self.DB(row, other)
        deleted = []

        async def fake_remove(rules):
            deleted.extend(rules)
            return True

        monkeypatch.setattr(sh, "db", db)
        monkeypatch.setattr(sh, "_remove_rules", fake_remove)

        assert asyncio.run(sh.revert_action(11)) is True
        # BLOCK_IP's inbound drops stay installed.
        assert ("INPUT", ("-s", "10.20.0.5", "-j", "DROP")) not in deleted
        assert ("FORWARD", ("-s", "10.20.0.5", "-j", "DROP")) not in deleted
        # Only the outbound half that quarantine alone installed is removed.
        assert ("OUTPUT", ("-d", "10.20.0.5", "-j", "DROP")) in deleted
        assert ("FORWARD", ("-d", "10.20.0.5", "-j", "DROP")) in deleted
        assert any("is_active=0" in sql for sql, _ in db.calls)

    def test_reverting_block_ip_keeps_the_active_quarantine_rules(self, monkeypatch):
        row = {
            "id": 12,
            "action_type": "BLOCK_IP",
            "target_ip": "10.20.0.6",
            "src_ip": None,
            "rule_applied": "-I INPUT -s 10.20.0.6 -j DROP",
            "is_active": 1,
        }
        other = [{
            "action_type": "QUARANTINE_HOST",
            "target_ip": "10.20.0.6",
        }]
        db = self.DB(row, other)
        deleted = []

        async def fake_remove(rules):
            deleted.extend(rules)
            return True

        monkeypatch.setattr(sh, "db", db)
        monkeypatch.setattr(sh, "_remove_rules", fake_remove)

        assert asyncio.run(sh.revert_action(12)) is True
        assert deleted == []
        assert any("is_active=0" in sql for sql, _ in db.calls)


class TestBlockIpStateDrift:
    def test_stale_db_row_is_refreshed_instead_of_duplicated(
            self, enforcing, monkeypatch):
        """A drift re-block must not add a second active row for the same IP."""
        db = FakeDB(row={"id": 42})

        async def no_rule(_chain, _spec):
            return False

        applied = []

        async def apply(rules):
            applied.extend(rules)
            return True, "ok"

        monkeypatch.setattr(sh, "db", db)
        monkeypatch.setattr(sh, "_iptables_rule_exists", no_rule)
        monkeypatch.setattr(sh, "_apply_rules", apply)

        result = asyncio.run(sh.block_ip("10.20.0.5", justification="drift"))

        assert result["status"] == "blocked"
        assert result["action_id"] == 42
        assert applied == sh._block_ip_rules("10.20.0.5")
        # The existing audit row is refreshed; no second "active block" row.
        assert not any(
            "INSERT INTO shield_actions" in sql for sql, _ in db.calls)
        assert any(
            "UPDATE shield_actions" in sql for sql, _ in db.calls)


class TestClosePort:
    """CLOSE_PORT blocks one port network-wide and stays reversible.

    The action was documented and offered by the responder, but it had no
    implementation: nothing installed a rule, and revert_action() only logged
    "not implemented". Any rule it ever installed would have been permanent.
    """

    def test_dry_run_refuses_and_audits_the_port(self, monkeypatch):
        monkeypatch.setenv("SHIELD_DRY_RUN", "1")
        db = FakeDB()
        monkeypatch.setattr(sh, "db", db)

        async def must_not_run(_rules):
            raise AssertionError("dry-run must not touch iptables")

        monkeypatch.setattr(sh, "_apply_rules", must_not_run)

        result = asyncio.run(sh.close_port(8080, justification="test"))

        assert result["status"] == "refused"
        assert "DRY-RUN" in result["reason"]
        audit = next(
            params for sql, params in db.calls
            if "INSERT INTO shield_actions" in sql)
        assert audit[0] == "CLOSE_PORT"
        assert audit[3] == 8080
        assert str(audit[4]).startswith("REFUSED")

    def test_applies_input_and_forward_drops(self, enforcing, monkeypatch):
        db = FakeDB()
        monkeypatch.setattr(sh, "db", db)
        applied = []

        async def no_rule(_chain, _spec):
            return False

        async def apply(rules):
            applied.extend(rules)
            return True, "ok"

        monkeypatch.setattr(sh, "_iptables_rule_exists", no_rule)
        monkeypatch.setattr(sh, "_apply_rules", apply)

        result = asyncio.run(sh.close_port(
            8080, protocol="TCP", justification="exposed proxy"))

        assert result["status"] == "closed"
        assert result["protocol"] == "tcp"
        assert result["action_id"] == 9
        assert applied == [
            ("INPUT",   ("-p", "tcp", "--dport", "8080", "-j", "DROP")),
            ("FORWARD", ("-p", "tcp", "--dport", "8080", "-j", "DROP")),
        ]
        insert_sql, insert_params = next(
            (sql, params) for sql, params in db.calls
            if "INSERT INTO shield_actions" in sql)
        assert insert_params[0] == "CLOSE_PORT"
        assert insert_params[1] == 8080
        assert "--dport 8080" in insert_params[2]

    @pytest.mark.parametrize("port,protocol", [
        (0, "tcp"), (65536, "tcp"), (-1, "tcp"),
        ("not-a-port", "tcp"), (None, "tcp"), (22, "icmp"),
    ])
    def test_rejects_invalid_port_or_protocol(
            self, port, protocol, monkeypatch):
        db = FakeDB()
        monkeypatch.setattr(sh, "db", db)

        async def must_not_run(_rules):
            raise AssertionError("invalid input must not touch iptables")

        monkeypatch.setattr(sh, "_apply_rules", must_not_run)

        result = asyncio.run(sh.close_port(port, protocol=protocol))

        assert result["status"] == "rejected"
        assert db.calls == []

    def test_dedupe_includes_protocol(self, enforcing, monkeypatch):
        db = FakeDB()
        monkeypatch.setattr(sh, "db", db)

        async def no_rule(_chain, _spec):
            return False

        async def apply(_rules):
            return True, "ok"

        monkeypatch.setattr(sh, "_iptables_rule_exists", no_rule)
        monkeypatch.setattr(sh, "_apply_rules", apply)

        result = asyncio.run(sh.close_port(53, protocol="udp"))
        assert result["status"] == "closed"

        sql, params = next(
            (sql, params) for sql, params in db.calls
            if "FROM shield_actions" in sql and "CLOSE_PORT" in sql)
        assert "target_port IS ?" in sql
        assert params == (53, "%-p udp%")

    def test_existing_rules_are_not_reapplied(self, enforcing, monkeypatch):
        monkeypatch.setattr(sh, "db", FakeDB())

        async def exists(_chain, _spec):
            return True

        async def applied(_rules):
            raise AssertionError("existing rules must not be reapplied")

        monkeypatch.setattr(sh, "_iptables_rule_exists", exists)
        monkeypatch.setattr(sh, "_apply_rules", applied)

        result = asyncio.run(sh.close_port(8080))
        assert result["status"] == "already_exists"

    def test_stale_row_is_refreshed_instead_of_duplicated(
            self, enforcing, monkeypatch):
        """A drift re-close must not add a second active row for the port."""
        db = FakeDB(row={"id": 42})
        monkeypatch.setattr(sh, "db", db)
        applied = []

        async def no_rule(_chain, _spec):
            return False

        async def apply(rules):
            applied.extend(rules)
            return True, "ok"

        monkeypatch.setattr(sh, "_iptables_rule_exists", no_rule)
        monkeypatch.setattr(sh, "_apply_rules", apply)

        result = asyncio.run(sh.close_port(8080, justification="drift"))

        assert result["status"] == "closed"
        assert result["action_id"] == 42
        assert applied == sh._close_port_rules(8080)
        assert not any(
            "INSERT INTO shield_actions" in sql for sql, _ in db.calls)
        assert any(
            "UPDATE shield_actions" in sql for sql, _ in db.calls)

    def test_revert_removes_input_and_forward_rules(self, monkeypatch):
        row = {
            "id": 21,
            "action_type": "CLOSE_PORT",
            "target_ip": None,
            "src_ip": None,
            "target_port": 8080,
            "rule_applied": (
                "-I INPUT -p tcp --dport 8080 -j DROP; "
                "-I FORWARD -p tcp --dport 8080 -j DROP"
            ),
            "is_active": 1,
        }
        db = FakeDB(row=row)
        removed = []

        async def fake_remove(rules):
            removed.extend(rules)
            return True

        monkeypatch.setattr(sh, "db", db)
        monkeypatch.setattr(sh, "_remove_rules", fake_remove)

        assert asyncio.run(sh.revert_action(21)) is True
        assert removed == sh._close_port_rules(8080, "tcp")
        assert any("is_active=0" in sql for sql, _ in db.calls)

    def test_revert_reconstructs_udp_rules_from_the_record(self, monkeypatch):
        row = {
            "id": 22,
            "action_type": "CLOSE_PORT",
            "target_ip": None,
            "src_ip": None,
            "target_port": 53,
            "rule_applied": (
                "-I INPUT -p udp --dport 53 -j DROP; "
                "-I FORWARD -p udp --dport 53 -j DROP"
            ),
            "is_active": 1,
        }
        removed = []

        async def fake_remove(rules):
            removed.extend(rules)
            return True

        monkeypatch.setattr(sh, "db", FakeDB(row=row))
        monkeypatch.setattr(sh, "_remove_rules", fake_remove)

        assert asyncio.run(sh.revert_action(22)) is True
        assert removed == sh._close_port_rules(53, "udp")

    def test_revert_without_a_port_is_refused(self, monkeypatch):
        row = {
            "id": 23,
            "action_type": "CLOSE_PORT",
            "target_ip": None,
            "src_ip": None,
            "target_port": None,
            "rule_applied": "-I INPUT -p tcp --dport 8080 -j DROP",
            "is_active": 1,
        }
        db = FakeDB(row=row)
        monkeypatch.setattr(sh, "db", db)

        async def must_not_run(_rules):
            raise AssertionError("a portless close has no rule to remove")

        monkeypatch.setattr(sh, "_remove_rules", must_not_run)

        assert asyncio.run(sh.revert_action(23)) is False
        assert not any("is_active=0" in sql for sql, _ in db.calls)

    def test_revert_keeps_rules_another_close_still_uses(self, monkeypatch):
        class DB(FakeDB):
            def __init__(self, row, other):
                super().__init__(row=row)
                self.other = other

            async def fetch_all(self, sql, params=()):
                self.calls.append((sql, params))
                return self.other

        row = {
            "id": 24,
            "action_type": "CLOSE_PORT",
            "target_ip": None,
            "src_ip": None,
            "target_port": 8080,
            "rule_applied": (
                "-I INPUT -p tcp --dport 8080 -j DROP; "
                "-I FORWARD -p tcp --dport 8080 -j DROP"
            ),
            "is_active": 1,
        }
        other = [{
            "action_type": "CLOSE_PORT",
            "target_ip": None,
            "target_port": 8080,
            "rule_applied": "-I INPUT -p tcp --dport 8080 -j DROP",
        }]
        db = DB(row, other)
        removed = []

        async def fake_remove(rules):
            removed.extend(rules)
            return True

        monkeypatch.setattr(sh, "db", db)
        monkeypatch.setattr(sh, "_remove_rules", fake_remove)

        assert asyncio.run(sh.revert_action(24)) is True
        assert removed == []
        assert any("is_active=0" in sql for sql, _ in db.calls)

    def test_revert_does_not_keep_the_other_protocol_on_same_port(
            self, monkeypatch):
        class DB(FakeDB):
            def __init__(self, row, other):
                super().__init__(row=row)
                self.other = other

            async def fetch_all(self, sql, params=()):
                self.calls.append((sql, params))
                return self.other

        row = {
            "id": 25,
            "action_type": "CLOSE_PORT",
            "target_ip": None,
            "src_ip": None,
            "target_port": 53,
            "rule_applied": "-I INPUT -p udp --dport 53 -j DROP",
            "is_active": 1,
        }
        other = [{
            "action_type": "CLOSE_PORT",
            "target_ip": None,
            "target_port": 53,
            "rule_applied": "-I INPUT -p tcp --dport 53 -j DROP",
        }]
        db = DB(row, other)
        removed = []

        async def fake_remove(rules):
            removed.extend(rules)
            return True

        monkeypatch.setattr(sh, "db", db)
        monkeypatch.setattr(sh, "_remove_rules", fake_remove)

        assert asyncio.run(sh.revert_action(25)) is True
        assert removed == sh._close_port_rules(53, "udp")


class TestUntrackedRuleRollback:
    """An applied rule that cannot be recorded must not stay in the firewall.

    Every guard and revert path keys off the `shield_actions` row. A rule with
    no row is an operator-invisible block that survives `revert_action()`.
    """

    @staticmethod
    def _patched(monkeypatch):
        removed = []

        async def applied(_rules):
            return True, "ok"

        async def remove(rules):
            removed.append(list(rules))
            return True

        monkeypatch.setattr(sh, "_apply_rules", applied)
        monkeypatch.setattr(sh, "_remove_rules", remove)
        return removed

    def test_block_ip_rolls_back_when_insert_fails(self, enforcing, monkeypatch):
        monkeypatch.setattr(sh, "db", FailingWriteDB())
        removed = self._patched(monkeypatch)

        result = asyncio.run(sh.block_ip("10.20.0.5", justification="test"))

        assert result["status"] == "failed"
        assert result["action_id"] is None
        assert removed == [[
            ("INPUT",   ("-s", "10.20.0.5", "-j", "DROP")),
            ("FORWARD", ("-s", "10.20.0.5", "-j", "DROP")),
        ]]

    def test_block_ip_rolls_back_when_no_id_is_returned(self, enforcing, monkeypatch):
        monkeypatch.setattr(sh, "db", MissingIdDB())
        removed = self._patched(monkeypatch)

        result = asyncio.run(sh.block_ip("10.20.0.5", justification="test"))
        assert result["status"] == "failed"
        assert len(removed) == 1

    def test_block_path_rolls_back_when_insert_fails(self, enforcing, monkeypatch):
        monkeypatch.setattr(sh, "db", FailingWriteDB())
        removed = self._patched(monkeypatch)

        result = asyncio.run(
            sh.block_path("10.20.0.5", "10.20.0.9", 22, justification="test"))

        assert result["status"] == "failed"
        assert removed == [[
            ("FORWARD", ("-s", "10.20.0.5", "-d", "10.20.0.9",
                         "-p", "tcp", "--dport", "22", "-j", "DROP")),
        ]]

    def test_quarantine_rolls_back_when_insert_fails(self, enforcing, monkeypatch):
        monkeypatch.setenv("SHIELD_AUTO_QUARANTINE", "1")
        monkeypatch.setattr(sh, "db", FailingWriteDB())
        removed = self._patched(monkeypatch)

        result = asyncio.run(
            sh.quarantine_host("10.20.0.7", justification="test"))

        assert result["status"] == "failed"
        assert len(removed[0]) == 4
        assert [c for c, _s in removed[0]] == \
            ["INPUT", "OUTPUT", "FORWARD", "FORWARD"]

    def test_successful_action_is_not_rolled_back(self, enforcing, monkeypatch):
        monkeypatch.setattr(sh, "db", FakeDB())
        removed = self._patched(monkeypatch)

        result = asyncio.run(sh.block_ip("10.20.0.5", justification="test"))
        assert result["status"] == "blocked"
        assert result["action_id"] == 9
        assert removed == []


class TestInconclusiveIptablesChecks:
    """'Could not check' must never be reported as 'rule is gone'."""

    def test_absent_rule_is_reported_gone(self, monkeypatch):
        async def absent(_args, **_kwargs):
            return False, "iptables: Bad rule (does a matching rule exist in that chain?)."

        monkeypatch.setattr(sh, "_run_iptables", absent)
        assert asyncio.run(sh._delete_rule("INPUT", ("-s", "10.0.0.1"))) is True

    def test_permission_error_is_not_treated_as_gone(self, monkeypatch):
        async def denied(_args, **_kwargs):
            return False, "iptables v1.8.9 (legacy): Permission denied (you must be root)"

        monkeypatch.setattr(sh, "_run_iptables", denied)
        assert asyncio.run(sh._delete_rule("INPUT", ("-s", "10.0.0.1"))) is False

    def test_missing_binary_is_not_treated_as_gone(self, monkeypatch):
        async def missing(_args, **_kwargs):
            return False, "SIMULATION"

        monkeypatch.setattr(sh, "_run_iptables", missing)
        assert asyncio.run(sh._delete_rule("INPUT", ("-s", "10.0.0.1"))) is False

    def test_revert_keeps_action_active_when_delete_is_unverified(self, monkeypatch):
        row = {
            "id": 8,
            "action_type": "BLOCK_IP",
            "target_ip": "10.20.0.5",
            "src_ip": None,
            "rule_applied": "-I INPUT -s 10.20.0.5 -j DROP",
            "is_active": 1,
        }

        async def unverified(_rules):
            return False

        db = FakeDB(row=row)
        monkeypatch.setattr(sh, "db", db)
        monkeypatch.setattr(sh, "_remove_rules", unverified)

        assert asyncio.run(sh.revert_action(8)) is False
        assert not any("is_active=0" in sql for sql, _ in db.calls)


class TestBlockPathStateDrift:
    def test_stale_db_row_reapplies_the_missing_rule(self, enforcing, monkeypatch):
        """After a reboot the DB still says blocked but the kernel rule is gone."""
        db = FakeDB(row={"id": 42})
        monkeypatch.setattr(sh, "db", db)

        async def no_rule(_chain, _spec):
            return False

        applied = []

        async def apply(rules):
            applied.extend(rules)
            return True, "ok"

        monkeypatch.setattr(sh, "_iptables_rule_exists", no_rule)
        monkeypatch.setattr(sh, "_apply_rules", apply)

        result = asyncio.run(sh.block_path(
            "10.20.0.5", "10.20.0.9", 22, justification="drift test"))

        assert result["status"] == "blocked"
        assert result["reapplied"] is True
        assert result["action_id"] == 42
        assert applied
        assert any("UPDATE shield_actions" in sql for sql, _ in db.calls)

    def test_existing_kernel_rule_is_still_already_exists(self, enforcing, monkeypatch):
        db = FakeDB(row=None)
        monkeypatch.setattr(sh, "db", db)

        async def exists(_chain, _spec):
            return True

        async def must_not_apply(_rules):
            raise AssertionError("nothing to apply")

        monkeypatch.setattr(sh, "_iptables_rule_exists", exists)
        monkeypatch.setattr(sh, "_apply_rules", must_not_apply)

        result = asyncio.run(sh.block_path(
            "10.20.0.5", "10.20.0.9", 22, justification="dedupe"))
        assert result["status"] == "already_exists"


class TestProactiveBlockRobustness:
    def test_unreadable_roi_skips_that_path_not_the_rest(self, monkeypatch):
        class FakeDB:
            async def fetch_all(self, *_a, **_k):
                return [
                    {"id": 1, "attacker_roi": "not-a-number", "path_json":
                     json.dumps([{"ip": "10.0.0.1"},
                                 {"ip": "10.0.0.2", "technique": "T1021.004"}])},
                    {"id": 2, "attacker_roi": 9.0, "path_json":
                     json.dumps([{"ip": "10.0.0.3"},
                                 {"ip": "10.0.0.4", "technique": "T1021.002"}])},
                ]

        monkeypatch.setattr(sh, "db", FakeDB())
        calls = []

        async def fake_block_path(**kwargs):
            calls.append(kwargs)
            return {"status": "blocked"}

        monkeypatch.setattr(sh, "block_path", fake_block_path)

        actions = asyncio.run(sh.close_phantom_paths())
        assert [c["trigger_id"] for c in calls] == [2]
        assert len(actions) == 1

    def test_one_failing_block_does_not_abort_the_rest(self, monkeypatch):
        class FakeDB:
            async def fetch_all(self, *_a, **_k):
                return [
                    {"id": 1, "attacker_roi": 9.0, "path_json":
                     json.dumps([{"ip": "10.0.0.1"},
                                 {"ip": "10.0.0.2", "technique": "T1021.004"}])},
                    {"id": 2, "attacker_roi": 8.0, "path_json":
                     json.dumps([{"ip": "10.0.0.3"},
                                 {"ip": "10.0.0.4", "technique": "T1021.002"}])},
                ]

        monkeypatch.setattr(sh, "db", FakeDB())
        seen = []

        async def sometimes_fails(**kwargs):
            seen.append(kwargs["trigger_id"])
            if kwargs["trigger_id"] == 1:
                raise RuntimeError("iptables exploded")
            return {"status": "blocked"}

        monkeypatch.setattr(sh, "block_path", sometimes_fails)

        actions = asyncio.run(sh.close_phantom_paths())
        assert seen == [1, 2]
        assert [a["status"] for a in actions] == ["failed", "blocked"]


def test_string_false_predicted_flag_is_not_high_confidence(monkeypatch):
    """`predicted="0"` from a serialized payload must not trigger a block."""
    called = []

    async def fake_block_path(**kwargs):
        called.append(kwargs)
        return {"status": "blocked"}

    monkeypatch.setattr(sh, "block_path", fake_block_path)
    result = asyncio.run(sh.respond_to_sentinel_alert({
        "src_ip": "10.20.0.5",
        "dst_ip": "10.20.0.9",
        "dst_port": 443,
        "protocol": "tcp",
        "predicted": "0",
    }))
    assert result is None
    assert called == []


class RowLike:
    """Minimal ``sqlite3.Row`` stand-in: indexing works, ``.get()`` does not."""

    def __init__(self, data):
        self._data = data

    def __getitem__(self, key):
        return self._data[key]

    def __contains__(self, value):
        return value in self._data.values()

    def keys(self):
        return self._data.keys()


class TestSqliteRowRobustness:
    def test_unreadable_roi_on_a_real_row_does_not_abort_other_paths(
            self, monkeypatch):
        """aiosqlite returns sqlite3.Row; it has no .get().

        The ROI fallback logged ``path.get('id')``, which raised AttributeError
        inside the error handler and skipped every later attack path.
        """
        class FakeDB:
            async def fetch_all(self, *_a, **_k):
                return [
                    RowLike({"id": 1, "attacker_roi": "not-a-number",
                             "path_json": json.dumps([
                                 {"ip": "10.0.0.1"},
                                 {"ip": "10.0.0.2", "technique": "T1021.004"},
                             ])}),
                    RowLike({"id": 2, "attacker_roi": 9.0,
                             "path_json": json.dumps([
                                 {"ip": "10.0.0.3"},
                                 {"ip": "10.0.0.4", "technique": "T1021.002"},
                             ])}),
                ]

        monkeypatch.setattr(sh, "db", FakeDB())
        calls = []

        async def fake_block_path(**kwargs):
            calls.append(kwargs)
            return {"status": "blocked"}

        monkeypatch.setattr(sh, "block_path", fake_block_path)

        actions = asyncio.run(sh.close_phantom_paths())

        assert [c["trigger_id"] for c in calls] == [2]
        assert len(actions) == 1

    def test_unhashable_technique_is_skipped_not_fatal(self, monkeypatch):
        """``path_json`` is untrusted graph data; a list must not raise."""
        class FakeDB:
            async def fetch_all(self, *_a, **_k):
                return [
                    RowLike({"id": 1, "attacker_roi": 9.0,
                             "path_json": json.dumps([
                                 {"ip": "10.0.0.1"},
                                 {"ip": "10.0.0.2",
                                  "technique": ["T1021.004"]},
                             ])}),
                    RowLike({"id": 2, "attacker_roi": 9.0,
                             "path_json": json.dumps([
                                 {"ip": "10.0.0.3"},
                                 {"ip": "10.0.0.4", "technique": "T1021.002"},
                             ])}),
                ]

        monkeypatch.setattr(sh, "db", FakeDB())
        calls = []

        async def fake_block_path(**kwargs):
            calls.append(kwargs)
            return {"status": "blocked"}

        monkeypatch.setattr(sh, "block_path", fake_block_path)

        actions = asyncio.run(sh.close_phantom_paths())

        assert [c["trigger_id"] for c in calls] == [2]
        assert len(actions) == 1


class TestAnomalyConfidenceSafety:
    @pytest.mark.parametrize("confidence", [
        float("nan"), float("inf"), float("-inf"), "high", None, object(),
    ])
    def test_unusable_confidence_never_quarantines(self, confidence, monkeypatch):
        monkeypatch.setattr(sh, "db", FakeDB(row={"ip": "10.20.0.5"}))

        async def must_not_quarantine(**_kwargs):
            raise AssertionError(
                "a host must not be quarantined without a usable confidence")

        monkeypatch.setattr(sh, "quarantine_host", must_not_quarantine)

        assert asyncio.run(
            sh.respond_to_anomaly(1, 2, confidence)) is None

    def test_numeric_string_confidence_is_handled(self, monkeypatch):
        seen = {}

        async def fake_quarantine(**kwargs):
            seen.update(kwargs)
            return {"status": "quarantined"}

        monkeypatch.setattr(sh, "db", FakeDB(row={"ip": "10.20.0.5"}))
        monkeypatch.setattr(sh, "quarantine_host", fake_quarantine)

        result = asyncio.run(sh.respond_to_anomaly(1, 2, "0.99"))

        assert result == {"status": "quarantined"}
        assert seen["confidence"] == 0.99


def test_runtime_rate_limit_env_beats_a_stale_settings_object(monkeypatch):
    """The guard's own comment promises env is authoritative.

    ``ShieldSettings`` is built at import; an operator (or test) changing
    ``SHIELD_MAX_ACTIONS_PER_HOUR`` at runtime must take effect immediately.
    """
    from config.settings import is_ip_allowlisted, parse_shield_allowlist

    monkeypatch.setenv("SHIELD_DRY_RUN", "0")
    monkeypatch.setenv("SHIELD_MAX_ACTIONS_PER_HOUR", "2")

    class StaleCfg:
        dry_run = False
        max_actions_per_hour = 10

    monkeypatch.setattr(
        sh, "_shield_cfg",
        lambda: (StaleCfg(), parse_shield_allowlist, is_ip_allowlisted),
    )
    monkeypatch.setattr(sh, "db", FakeDB(count=2))

    allowed, reason = asyncio.run(
        sh._shield_guard("10.20.0.5", "BLOCK_IP"))

    assert allowed is False
    assert "2/2" in reason


class TestIptablesRunner:
    """Every command failure must come back as (False, reason), never raise."""

    def test_timeout_race_with_an_already_dead_child_returns_timeout(self, monkeypatch):
        class Proc:
            def kill(self):
                raise ProcessLookupError

            async def wait(self):
                raise ProcessLookupError

            async def communicate(self):
                return b"", b""

        async def spawn(*_args, **_kwargs):
            return Proc()

        async def time_out(awaitable, **_kwargs):
            awaitable.close()
            raise TimeoutError

        monkeypatch.setattr(sh.asyncio, "create_subprocess_exec", spawn)
        monkeypatch.setattr(sh.asyncio, "wait_for", time_out)

        ok, output = asyncio.run(sh._run_iptables(["-C", "INPUT"]))

        assert ok is False
        assert output == "iptables timed out"

    def test_missing_binary_is_reported_as_simulation(self, monkeypatch):
        async def spawn(*_args, **_kwargs):
            raise FileNotFoundError

        monkeypatch.setattr(sh.asyncio, "create_subprocess_exec", spawn)

        assert asyncio.run(sh._run_iptables(["-C", "INPUT"])) == (False, "SIMULATION")

    def test_unexpected_exec_error_is_reported(self, monkeypatch):
        async def spawn(*_args, **_kwargs):
            raise PermissionError("not permitted")

        monkeypatch.setattr(sh.asyncio, "create_subprocess_exec", spawn)

        ok, output = asyncio.run(sh._run_iptables(["-C", "INPUT"]))

        assert ok is False
        assert "not permitted" in output
