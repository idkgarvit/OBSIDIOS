"""Regression tests for FORGE rule delivery.

The invariant: OBSIDIOS never hands Suricata a malformed rule, and never
reports a rule as deployed unless a ruleset containing it was actually written.
A single bad rule makes Suricata reject the entire ruleset, so a broken write
is a silent detection outage, not a cosmetic error.
"""
from __future__ import annotations

import asyncio
import json
import sys

import pytest

from chronicle.models import AttackStep, ForgeRule
from dashboard.app import app
from forge import rule_generator as rg
from forge.rule_generator import (
    RuleDelivery,
    _generate_rules_for_step,
    _persist_rule,
    _valid_address,
    validate_rule,
    write_rules_file,
)

# A real template: the vsftpd rule contains `content:":)"`, i.e. a closing
# parenthesis inside a quoted string, which naive counting gets wrong.
VALID = rg._rule_exploit_ftp_backdoor("192.168.1.10", 9_000_001, 3, 2)


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key-for-auth-hardening-32+"
    with app.test_client() as c:
        yield c


def _auth(client):
    rv = client.post("/api/v2/login",
                     json={"username": "admin", "password": "obsidios123"})
    assert rv.status_code == 200, rv.data[:200]
    return {"Authorization": f"Bearer {json.loads(rv.data)['token']}"}


# ── Address validation ──────────────────────────────────────────────────────

class TestAddressValidation:
    @pytest.mark.parametrize("value,expected", [
        ("192.168.1.10", "192.168.1.10"),
        ("10.0.0.0/24", "10.0.0.0/24"),
        ("10.1.2.3/8", "10.0.0.0/8"),          # normalised
        ("any", "any"),
        ("!10.0.0.0/8", "!10.0.0.0/8"),
        ("$HOME_NET", "$HOME_NET"),
    ])
    def test_accepts_addresses(self, value, expected):
        assert _valid_address(value) == expected

    @pytest.mark.parametrize("value", [
        "", "   ", None, 12345, "hostname", "1.2.3.4/99", "192.168.1.10; drop",
        "192.168.1.10 -> 10.0.0.1", "a" * 65, "192.168.1.10\ndrop tables",
    ])
    def test_rejects_everything_else(self, value):
        assert _valid_address(value) is None

    def test_generation_refuses_poisoned_address(self):
        step = AttackStep(
            host_id=1, ip="192.168.1.10; drop", technique="T1021.002",
            tactic="Lateral Movement",
        )
        assert asyncio.run(_generate_rules_for_step(step, None, 1, 1)) == []

    def test_generation_refuses_poisoned_previous_hop(self):
        prev = AttackStep(host_id=1, ip="10.0.0.1\ndrop", technique="T1021.002",
                          tactic="Lateral Movement")
        step = AttackStep(host_id=2, ip="192.168.1.10", technique="T1021.002",
                          tactic="Lateral Movement")
        assert asyncio.run(_generate_rules_for_step(step, prev, 1, 2)) == []

    def test_generated_rules_pass_validation(self):
        step = AttackStep(host_id=2, ip="192.168.1.10", technique="T1021.002",
                          tactic="Lateral Movement")
        rules = asyncio.run(_generate_rules_for_step(step, None, 7, 1))
        assert rules
        for rule in rules:
            # SIDs are placeholders until _persist_rule assigns one.
            assert validate_rule(rg._replace_sid(rule.rule_text, 9_000_010)) == []


# ── Rule syntax validation ──────────────────────────────────────────────────

class TestValidateRule:
    def test_accepts_real_template(self):
        assert validate_rule(VALID) == []

    def test_rejects_empty(self):
        assert validate_rule("") == ["empty rule"]
        assert validate_rule(None) == ["empty rule"]

    @pytest.mark.parametrize("rule,needle", [
        (VALID + "\n; rm -rf /", "newline"),
        (VALID.replace("sid:9000001;", "sid:1234;"), "outside the OBSIDIOS range"),
        (VALID.replace("rev:1;", ""), "missing rev"),
        (VALID.replace('-> 192.168.1.10";', '-> 192.168.1.10;'), "unbalanced quotes"),
        (VALID.replace("alert tcp", "log tcp"), "unknown action"),
        (VALID.replace("alert tcp", "alert tcp6"), "unknown protocol"),
        (VALID.replace("192.168.1.10 21", "192.168.1.10; drop 21"), "invalid address"),
        (VALID.replace("classtype:", "x("), "unbalanced parentheses"),
        (VALID.replace("rev:1;", "rev:;"), "missing rev"),
    ])
    def test_rejects_malformed(self, rule, needle):
        problems = validate_rule(rule)
        assert problems, rule
        assert any(needle in p for p in problems), (needle, problems)

    def test_rejects_trailing_whitespace(self):
        assert "leading or trailing whitespace" in validate_rule(VALID + " ")

    def test_accepts_paren_inside_quoted_content(self):
        # The vsftpd trigger is `content:":)"` — must not look unbalanced.
        assert 'content:":)"' in VALID
        assert validate_rule(VALID) == []

    def test_direction_operator_inside_msg_does_not_mask_a_broken_header(self):
        rule = ('alert tcp any any 192.168.1.10 21 '
                '(msg:"-> disguised"; sid:9000001; rev:1;)')
        assert "missing direction operator" in validate_rule(rule)


# ── Persistence ─────────────────────────────────────────────────────────────

class TestPersistRule:
    def test_refuses_invalid_rule_before_insert(self, monkeypatch):
        inserted = []

        async def fake_fetch_all(sql, params=()):
            return []

        async def fake_execute_returning(sql, params=()):
            inserted.append(sql)
            return {"sid": 9_000_001, "id": 1}

        monkeypatch.setattr(rg.db, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(rg.db, "execute_returning", fake_execute_returning)

        rule = ForgeRule(rule_sid=0, attack_path_id=1,
                         rule_text=VALID.replace("rev:1;", ""),
                         rule_category="EXPLOITATION")
        assert asyncio.run(_persist_rule(rule)) is None
        assert not any("INSERT INTO forge_rules" in s for s in inserted)

    def test_refuses_to_reuse_out_of_range_sid(self, monkeypatch):
        reactivated = []

        async def fake_fetch_all(sql, params=()):
            return [{"id": 5, "rule_sid": 1234,
                     "rule_text": VALID.replace("sid:9000001;", "sid:1234;"),
                     "is_active": 0}]

        async def fake_execute(sql, params=()):
            reactivated.append((sql, params))

        monkeypatch.setattr(rg.db, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(rg.db, "execute", fake_execute)

        rule = ForgeRule(rule_sid=0, attack_path_id=1, rule_text=VALID,
                         rule_category="EXPLOITATION")
        assert asyncio.run(_persist_rule(rule)) is None
        assert reactivated == []

    def test_legacy_row_with_unusable_sid_gets_a_fresh_sid(self, monkeypatch):
        inserted = {}

        async def fake_fetch_all(sql, params=()):
            return [{"id": 5, "rule_sid": "not-a-number",
                     "rule_text": VALID, "is_active": 1}]

        async def fake_execute_returning(sql, params=()):
            inserted["params"] = params
            return {"id": 6}

        async def fake_next_sid():
            return 9_000_321

        monkeypatch.setattr(rg.db, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(rg.db, "execute_returning", fake_execute_returning)
        monkeypatch.setattr(rg, "_next_sid", fake_next_sid)

        rule = ForgeRule(rule_sid=0, attack_path_id=1, rule_text=VALID,
                         rule_category="EXPLOITATION")

        assert asyncio.run(_persist_rule(rule)) == 6
        assert inserted["params"][0] == 9_000_321


# ── Delivery result ─────────────────────────────────────────────────────────

class TestDeliveryState:
    @pytest.mark.parametrize("kwargs,state", [
        ({"ok": False, "error": "boom"}, "FAILED"),
        ({"ok": True, "rule_count": 0}, "EMPTY"),
        ({"ok": True, "rule_count": 4, "reload_ok": None}, "WRITTEN"),
        ({"ok": True, "rule_count": 4, "reload_ok": False}, "WRITTEN_NO_RELOAD"),
        ({"ok": True, "rule_count": 4, "reload_ok": True}, "DEPLOYED"),
    ])
    def test_state_labels_are_truthful(self, kwargs, state):
        assert RuleDelivery(**kwargs).state == state


def _fake_db(monkeypatch, rows):
    calls: list[tuple[str, tuple]] = []

    async def fake_fetch_all(sql, params=()):
        return rows

    async def fake_execute(sql, params=()):
        calls.append((sql, tuple(params)))

    monkeypatch.setattr(rg.db, "fetch_all", fake_fetch_all)
    monkeypatch.setattr(rg.db, "execute", fake_execute)
    return calls


class TestWriteRulesFile:
    def test_writes_valid_rules_and_records_delivery(self, tmp_path, monkeypatch):
        monkeypatch.delenv("FORGE_RELOAD_CMD", raising=False)
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        calls = _fake_db(monkeypatch, [{
            "rule_text": VALID, "rule_category": "EXPLOITATION",
            "mitre_technique": "T1210", "rule_sid": 9_000_001,
        }])

        out = tmp_path / "suricata.rules"
        delivery = asyncio.run(write_rules_file(str(out)))

        assert delivery.ok is True
        assert delivery.rule_count == 1
        assert delivery.reload_ok is None
        assert delivery.state == "WRITTEN"
        assert out.exists()
        assert "sid:9000001" in out.read_text()
        # Local copy for reports is written too.
        assert (tmp_path / "obsidios.rules").exists()
        assert any("delivered_at" in sql for sql, _ in calls)
        assert any("forge_delivery" in sql for sql, _ in calls)

    def test_invalid_rule_aborts_and_keeps_previous_ruleset(self, tmp_path, monkeypatch):
        monkeypatch.delenv("FORGE_RELOAD_CMD", raising=False)
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        good = {"rule_text": VALID, "rule_category": "EXPLOITATION",
                "mitre_technique": "T1210", "rule_sid": 9_000_001}
        bad = {"rule_text": VALID.replace("sid:9000001;", "sid:1;"),
               "rule_category": "EXPLOITATION",
               "mitre_technique": "T1210", "rule_sid": 1}
        calls = _fake_db(monkeypatch, [good, bad])

        out = tmp_path / "suricata.rules"
        out.write_text("# previous known-good ruleset\n")

        delivery = asyncio.run(write_rules_file(str(out)))

        assert delivery.ok is False
        assert "refused to write" in delivery.error
        assert delivery.quarantined == [1]
        assert delivery.rule_count == 2
        # The known-good file must survive untouched.
        assert out.read_text() == "# previous known-good ruleset\n"
        assert any("is_active=0" in sql for sql, _ in calls)
        assert any("forge_delivery" in sql for sql, _ in calls)

    def test_write_failure_is_reported(self, tmp_path, monkeypatch):
        monkeypatch.delenv("FORGE_RELOAD_CMD", raising=False)
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        _fake_db(monkeypatch, [{
            "rule_text": VALID, "rule_category": "EXPLOITATION",
            "mitre_technique": "T1210", "rule_sid": 9_000_001,
        }])

        blocked = tmp_path / "blocked"
        blocked.write_text("not a directory")

        delivery = asyncio.run(write_rules_file(str(blocked / "rules")))

        assert delivery.ok is False
        assert delivery.error
        assert delivery.state == "FAILED"

    def test_no_rules_does_not_claim_a_deployment(self, tmp_path, monkeypatch):
        monkeypatch.delenv("FORGE_RELOAD_CMD", raising=False)
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        _fake_db(monkeypatch, [])

        out = tmp_path / "rules"
        delivery = asyncio.run(write_rules_file(str(out)))

        assert delivery.ok is True
        assert delivery.rule_count == 0
        assert delivery.state == "EMPTY"
        # An empty ruleset must still be written: Suricata loads the file.
        assert out.exists()
        text = out.read_text()
        assert "Total     : 0 unique rules" in text
        assert "sid:" not in text

    def test_empty_ruleset_replaces_stale_rules_on_disk(self, tmp_path, monkeypatch):
        """Retiring every path must remove its rules from the sensor file."""
        monkeypatch.delenv("FORGE_RELOAD_CMD", raising=False)
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        _fake_db(monkeypatch, [])

        out = tmp_path / "suricata.rules"
        out.write_text("alert tcp any any -> any any (sid:9000001;)\n")

        delivery = asyncio.run(write_rules_file(str(out)))

        assert delivery.state == "EMPTY"
        text = out.read_text()
        assert "sid:9000001" not in text
        assert "Total     : 0 unique rules" in text


class TestEnsureRulesFile:
    def test_creates_a_loadable_placeholder(self, tmp_path):
        out = tmp_path / "suricata.rules"

        assert rg.ensure_rules_file(str(out)) == str(out)
        assert out.exists()
        assert "no rules generated yet" in out.read_text()

    def test_existing_ruleset_is_never_overwritten(self, tmp_path):
        out = tmp_path / "suricata.rules"
        out.write_text("alert tcp any any -> any any (sid:9000001;)\n")

        rg.ensure_rules_file(str(out))

        assert "sid:9000001" in out.read_text()

    def test_invalid_rule_with_unusable_sid_is_quarantined_by_row_id(
            self, tmp_path, monkeypatch):
        monkeypatch.delenv("FORGE_RELOAD_CMD", raising=False)
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        bad = {"id": 42, "rule_text": VALID.replace("rev:1;", ""),
               "rule_category": "EXPLOITATION", "mitre_technique": "T1210",
               "rule_sid": "not-a-number"}
        calls = _fake_db(monkeypatch, [bad])

        out = tmp_path / "suricata.rules"
        out.write_text("# previous known-good ruleset\n")

        delivery = asyncio.run(write_rules_file(str(out)))

        assert delivery.ok is False
        assert delivery.quarantined == []
        assert "refused to write" in delivery.error
        assert out.read_text() == "# previous known-good ruleset\n"
        updates = [params for sql, params in calls if "is_active=0" in sql]
        assert updates == [(42,)]


class TestAtomicWrite:
    def test_cleanup_error_does_not_mask_the_write_error(self, tmp_path, monkeypatch):
        def fail_chmod(*_args, **_kwargs):
            raise OSError("chmod failed")

        def fail_unlink(*_args, **_kwargs):
            raise OSError("unlink failed")

        monkeypatch.setattr(rg.os, "chmod", fail_chmod)
        monkeypatch.setattr(rg.os, "unlink", fail_unlink)

        with pytest.raises(OSError, match="chmod failed"):
            rg._atomic_write(str(tmp_path / "rules"), "payload")


class TestReloadHook:
    def _rules(self):
        return [{"rule_text": VALID, "rule_category": "EXPLOITATION",
                 "mitre_technique": "T1210", "rule_sid": 9_000_001}]

    def test_successful_reload_marks_deployed(self, tmp_path, monkeypatch):
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        monkeypatch.setenv(
            "FORGE_RELOAD_CMD",
            f'{sys.executable} -c "print(\'reloaded 1 ruleset\')"',
        )
        _fake_db(monkeypatch, self._rules())

        delivery = asyncio.run(write_rules_file(str(tmp_path / "rules")))

        assert delivery.reload_ok is True
        assert "reloaded 1 ruleset" in delivery.reload_output
        assert delivery.state == "DEPLOYED"

    def test_failed_reload_is_not_reported_as_deployed(self, tmp_path, monkeypatch):
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        monkeypatch.setenv(
            "FORGE_RELOAD_CMD",
            f'{sys.executable} -c "import sys; sys.exit(3)"',
        )
        _fake_db(monkeypatch, self._rules())

        delivery = asyncio.run(write_rules_file(str(tmp_path / "rules")))

        assert delivery.ok is True          # the file was written
        assert delivery.reload_ok is False  # but the sensor did not load it
        assert delivery.state == "WRITTEN_NO_RELOAD"

    def test_missing_command_is_unknown_not_success(self, tmp_path, monkeypatch):
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        monkeypatch.delenv("FORGE_RELOAD_CMD", raising=False)
        _fake_db(monkeypatch, self._rules())

        delivery = asyncio.run(write_rules_file(str(tmp_path / "rules")))

        assert delivery.reload_ok is None
        assert "not configured" in delivery.reload_output

    def test_missing_reload_binary_is_reported_not_raised(self, tmp_path, monkeypatch):
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        monkeypatch.setenv("FORGE_RELOAD_CMD", "/nonexistent/obsidios-reload")
        _fake_db(monkeypatch, self._rules())

        delivery = asyncio.run(write_rules_file(str(tmp_path / "rules")))

        assert delivery.ok is True
        assert delivery.reload_ok is False
        assert "could not run reload command" in delivery.reload_output


# ── Dashboard surface ───────────────────────────────────────────────────────

class TestForgeEndpoints:
    def test_rules_include_delivery_state(self, client, monkeypatch):
        h = _auth(client)
        monkeypatch.setattr("dashboard.app.db.fetch_all", lambda *a, **k: [{
            "id": 1, "rule_sid": 9_000_001, "rule_text": VALID,
            "rule_category": "EXPLOITATION", "mitre_technique": "T1210",
            "is_deployed": 1, "is_active": 1, "delivered_at": 1000.0,
            "true_positives": 0, "false_positives": 0, "created_at": 900.0,
        }])
        monkeypatch.setattr("dashboard.app.db.fetch_one", lambda *a, **k: {
            "attempted_at": 1000.0, "ok": 1, "rule_count": 1,
            "path": "/app/forge/rules/suricata.rules", "error": None,
            "reload_ok": 1, "reload_output": "done",
        })
        rv = client.get("/api/v2/forge/rules", headers=h)
        assert rv.status_code == 200
        d = json.loads(rv.data)
        assert d["data"][0]["delivered_at"] == 1000.0
        assert d["delivery"]["state"] == "DEPLOYED"
        assert d["delivery"]["reload_ok"] is True

    def test_never_delivered_is_null(self, client, monkeypatch):
        h = _auth(client)
        monkeypatch.setattr("dashboard.app.db.fetch_all", lambda *a, **k: [])
        monkeypatch.setattr("dashboard.app.db.fetch_one", lambda *a, **k: None)
        d = json.loads(client.get("/api/v2/forge/rules", headers=h).data)
        assert d["delivery"] is None

    def test_deploy_rewrites_the_ruleset(self, client, monkeypatch):
        h = _auth(client)
        monkeypatch.setattr("dashboard.app.db.fetch_one",
                            lambda *a, **k: {"is_active": 1})
        updates = []
        monkeypatch.setattr("dashboard.app.db.execute",
                            lambda sql, params=(): updates.append((sql, params)))

        async def fake_write():
            return RuleDelivery(ok=True, rule_count=3, path="/x/rules",
                                written_at=1000.0, reload_ok=True)

        monkeypatch.setattr("forge.rule_generator.write_rules_file", fake_write)

        rv = client.post("/api/v2/forge/deploy/1", headers=h)

        assert rv.status_code == 200
        d = json.loads(rv.data)
        assert d["is_active"] is False
        assert d["delivery"]["state"] == "DEPLOYED"
        # (is_active, operator_excluded, rule id): an explicit exclusion is
        # recorded so regeneration cannot silently re-enable the rule.
        assert updates[0][1] == (0, 1, 1)

    def test_failed_delivery_rolls_back_the_toggle(self, client, monkeypatch):
        h = _auth(client)
        monkeypatch.setattr("dashboard.app.db.fetch_one",
                            lambda *a, **k: {"is_active": 1})
        updates = []
        monkeypatch.setattr("dashboard.app.db.execute",
                            lambda sql, params=(): updates.append((sql, params)))

        async def fake_write():
            return RuleDelivery(ok=False, rule_count=3,
                                error="could not write /x/rules: denied")

        monkeypatch.setattr("forge.rule_generator.write_rules_file", fake_write)

        rv = client.post("/api/v2/forge/deploy/1", headers=h)

        assert rv.status_code == 500
        d = json.loads(rv.data)
        assert d["delivery"]["state"] == "FAILED"
        # The DB must match the ruleset that is still live on disk.
        forge_updates = [p for sql, p in updates if "UPDATE forge_rules" in sql]
        assert forge_updates == [(0, 1, 1), (1, 0, 1)]
        # Rolling back is an operator action worth auditing, including failure.
        assert any("audit_log" in sql and "FORGE_RULE_EDIT" in p
                   for sql, p in updates)

    def test_failed_activation_restores_the_original_exclusion(self, client, monkeypatch):
        """A failed include must not mark a merely inactive rule as excluded.

        The old rollback derived `operator_excluded` from the toggle direction,
        so a write failure could silently ban the rule from future regeneration.
        """
        h = _auth(client)
        monkeypatch.setattr("dashboard.app.db.fetch_one", lambda *a, **k: {
            "is_active": 0, "operator_excluded": 0})
        updates = []
        monkeypatch.setattr("dashboard.app.db.execute",
                            lambda sql, params=(): updates.append((sql, params)))

        async def fake_write():
            return RuleDelivery(ok=False, rule_count=0, error="denied")

        monkeypatch.setattr("forge.rule_generator.write_rules_file", fake_write)

        rv = client.post("/api/v2/forge/deploy/1", headers=h)

        assert rv.status_code == 500
        forge_updates = [p for sql, p in updates if "UPDATE forge_rules" in sql]
        # Attempted include (1, 0), then restore the original state (0, 0).
        assert forge_updates == [(1, 0, 1), (0, 0, 1)]

    def test_rewrite_endpoint(self, client, monkeypatch):
        h = _auth(client)

        async def fake_write():
            return RuleDelivery(ok=True, rule_count=2, written_at=1.0,
                                reload_ok=False, reload_output="suricatasc: no socket")

        monkeypatch.setattr("forge.rule_generator.write_rules_file", fake_write)
        rv = client.post("/api/v2/forge/rewrite", headers=h)
        assert rv.status_code == 200
        d = json.loads(rv.data)
        assert d["delivery"]["state"] == "WRITTEN_NO_RELOAD"

    def test_rewrite_requires_operator(self, client):
        rv = client.post("/api/v2/forge/rewrite")
        assert rv.status_code == 401


class TestOperatorExclusion:
    """An operator's exclusion must survive rule regeneration."""

    def _rule(self):
        return ForgeRule(rule_sid=0, attack_path_id=1, rule_text=VALID,
                         rule_category="EXPLOITATION")

    def test_excluded_rule_is_not_reactivated_by_regeneration(self, monkeypatch):
        updates = []

        async def fake_fetch_all(sql, params=()):
            return [{"id": 5, "rule_sid": 9_000_001, "rule_text": VALID,
                     "is_active": 0, "operator_excluded": 1}]

        async def fake_execute(sql, params=()):
            updates.append((sql, params))

        monkeypatch.setattr(rg.db, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(rg.db, "execute", fake_execute)

        assert asyncio.run(_persist_rule(self._rule())) is None
        assert updates == []

    def test_automatically_retired_rule_is_reactivated(self, monkeypatch):
        updates = []

        async def fake_fetch_all(sql, params=()):
            return [{"id": 5, "rule_sid": 9_000_001, "rule_text": VALID,
                     "is_active": 0, "operator_excluded": 0}]

        async def fake_execute(sql, params=()):
            updates.append((sql, params))

        monkeypatch.setattr(rg.db, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(rg.db, "execute", fake_execute)

        assert asyncio.run(_persist_rule(self._rule())) == 5
        assert updates == [("UPDATE forge_rules SET is_active=1 WHERE id=?", (5,))]

    def test_row_without_the_column_is_treated_as_not_excluded(self, monkeypatch):
        """Older databases (pre-migration rows) must keep regenerating."""
        async def fake_fetch_all(sql, params=()):
            return [{"id": 5, "rule_sid": 9_000_001, "rule_text": VALID,
                     "is_active": 0}]

        async def fake_execute(sql, params=()):
            return None

        monkeypatch.setattr(rg.db, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(rg.db, "execute", fake_execute)
        assert asyncio.run(_persist_rule(self._rule())) == 5


class TestOperatorExclusionMigration:
    def test_column_is_added_to_an_existing_database(self, tmp_path):
        import aiosqlite

        from chronicle import db as cdb

        path = tmp_path / "old.db"

        async def scenario():
            conn = await aiosqlite.connect(path)
            try:
                await conn.execute(
                    "CREATE TABLE forge_rules (id INTEGER PRIMARY KEY,"
                    " rule_text TEXT)"
                )
                await cdb._apply_column_migrations(conn)
                async with conn.execute("PRAGMA table_info(forge_rules)") as cur:
                    return {row[1] for row in await cur.fetchall()}
            finally:
                await conn.close()

        columns = asyncio.run(scenario())
        assert "operator_excluded" in columns
        assert "delivered_at" in columns


# ── Notification and persistence failures ──────────────────────────────────

class TestSideChannelFailures:
    """Notification is side channel: it must never abort rule generation."""

    def test_exploit_buffer_failure_does_not_lose_the_rule(self, monkeypatch):
        from alerts import notifier

        async def exploding(*_args, **_kwargs):
            raise RuntimeError("notifier is down")

        monkeypatch.setattr(notifier, "buffer_alert", exploding)

        async def fake_fetch_all(_sql, _params=()):
            return []

        monkeypatch.setattr(rg.db, "fetch_all", fake_fetch_all)

        step = AttackStep(host_id=2, ip="192.168.1.20", technique="T1210",
                          tactic="Execution", cve_id="CVE-2011-2523")
        rules = asyncio.run(
            _generate_rules_for_step(step, None, path_id=3, step_num=2)
        )

        assert [r.rule_category for r in rules] == ["EXPLOITATION"]
        assert "vsftpd" in rules[0].rule_text.lower()

    def test_ssh_lookup_tolerates_rows_without_a_port(self, monkeypatch):
        async def weird_rows(_sql, _params=()):
            return [{}, {"port": None}, {"host": "x"}]

        monkeypatch.setattr(rg.db, "fetch_all", weird_rows)

        step = AttackStep(host_id=2, ip="192.168.1.20", technique="T1021.004",
                          tactic="Lateral Movement")
        rules = asyncio.run(
            _generate_rules_for_step(step, None, path_id=3, step_num=2)
        )
        assert rules == []

    def test_summary_delivery_failure_does_not_fail_the_run(self, monkeypatch):
        from alerts import notifier

        async def exploding(*_args, **_kwargs):
            raise RuntimeError("webhook unreachable")

        monkeypatch.setattr(notifier, "send_alert", exploding)

        path = _simulated_path()
        rule = ForgeRule(rule_sid=0, attack_path_id=path.id, rule_text=VALID,
                         rule_category="EXPLOITATION")

        async def generate(*_args, **_kwargs):
            return [rule]

        async def persist(candidate):
            candidate.id = 11
            return 11

        async def retire():
            return None

        async def delivery(*_args, **_kwargs):
            return RuleDelivery(ok=True, rule_count=1, reload_ok=True)

        monkeypatch.setattr(rg, "_generate_rules_for_step", generate)
        monkeypatch.setattr(rg, "_persist_rule", persist)
        monkeypatch.setattr(rg, "_retire_stale_rules", retire)
        monkeypatch.setattr(rg, "write_rules_file", delivery)
        monkeypatch.setattr(rg, "_print_rules_summary", lambda _rules: None)

        assert asyncio.run(rg.run_forge(_simulation([path]))) == 1

    def test_one_unwritable_rule_does_not_stop_the_others(self, monkeypatch):
        path = _simulated_path()
        first = ForgeRule(rule_sid=0, attack_path_id=path.id, rule_text=VALID,
                          rule_category="EXPLOITATION")
        second = ForgeRule(rule_sid=0, attack_path_id=path.id,
                           rule_text=VALID.replace("Path#", "Path#alt"),
                           rule_category="EXPLOITATION")

        async def generate(*_args, **_kwargs):
            return [first, second]

        async def persist(candidate):
            if candidate is first:
                raise RuntimeError("database is locked")
            candidate.id = 12
            return 12

        async def retire():
            return None

        async def delivery(*_args, **_kwargs):
            return RuleDelivery(ok=True, rule_count=1, reload_ok=True)

        monkeypatch.setattr(rg, "_generate_rules_for_step", generate)
        monkeypatch.setattr(rg, "_persist_rule", persist)
        monkeypatch.setattr(rg, "_retire_stale_rules", retire)
        monkeypatch.setattr(rg, "write_rules_file", delivery)
        monkeypatch.setattr(rg, "_print_rules_summary", lambda _rules: None)

        async def fake_execute(_sql, _params=()):
            return None

        monkeypatch.setattr(rg.db, "execute", fake_execute)

        assert asyncio.run(rg.run_forge(_simulation([path]))) == 1


def _simulated_path(host_id: int = 2):
    from chronicle.models import AttackPath

    return AttackPath(id=7, entry_host_id=1, target_host_id=host_id, steps=[
        AttackStep(host_id=2, ip="192.168.1.20", technique="T1210",
                   tactic="Execution", cve_id="CVE-2011-2523"),
    ])


def _simulation(paths):
    from phantom.path_finder import SimulationResult

    return SimulationResult(paths=list(paths), total_paths=len(paths))


class TestPersistRetryValidation:
    def test_unique_retry_never_inserts_an_invalid_sid(self, monkeypatch):
        attempts = []

        async def no_existing(_sql, _params=()):
            return []

        sids = iter([9_000_001, 1])

        async def next_sid():
            return next(sids)

        async def unique_conflict(_sql, _params=()):
            attempts.append(_params)
            raise Exception("UNIQUE constraint failed: forge_rules.rule_sid")

        monkeypatch.setattr(rg.db, "fetch_all", no_existing)
        monkeypatch.setattr(rg.db, "execute_returning", unique_conflict)
        monkeypatch.setattr(rg, "_next_sid", next_sid)

        rule = ForgeRule(rule_sid=0, attack_path_id=1, rule_text=VALID,
                         rule_category="EXPLOITATION")

        assert asyncio.run(_persist_rule(rule)) is None
        # Only the first candidate reached the DB; the retry was rejected.
        assert len(attempts) == 1
