"""FORGE technique dispatch and failure-path coverage.

Every supported MITRE technique must emit a valid Suricata rule for the right
port, and a failure in a side channel (notification, local copy, bookkeeping)
must never take down the ruleset that protects the network.
"""
from __future__ import annotations

import asyncio

import pytest

from chronicle.models import AttackPath, AttackStep, ForgeRule
from forge import rule_generator as rg

VALID = rg._rule_exploit_ftp_backdoor("192.168.1.10", 9_000_001, 3, 2)


def _step(technique, cve_id=None, ip="192.168.1.20"):
    return AttackStep(host_id=2, ip=ip, technique=technique,
                      tactic="Lateral Movement", cve_id=cve_id)


def _generate(monkeypatch, step, ports=(), port_hits=(), step_num=2):
    async def fetch_all(_sql, _params=()):
        return [{"port": port} for port in ports]

    async def fetch_one(_sql, params=()):
        return {"id": 1} if params[-1] in port_hits else None

    monkeypatch.setattr(rg.db, "fetch_all", fetch_all)
    monkeypatch.setattr(rg.db, "fetch_one", fetch_one)
    return asyncio.run(
        rg._generate_rules_for_step(step, None, path_id=7, step_num=step_num))


def _assert_valid(rules):
    for rule in rules:
        assert rg.validate_rule(
            rg._replace_sid(rule.rule_text, 9_000_001)) == []


class TestTechniqueDispatch:
    def test_samba_cve_generates_exploitation_rule(self, monkeypatch):
        rules = _generate(monkeypatch, _step("T1210", "CVE-2007-2447"))
        assert [r.rule_category for r in rules] == ["EXPLOITATION"]
        assert "Samba" in rules[0].rule_text
        _assert_valid(rules)

    def test_ssh_and_telnet_follow_open_ports(self, monkeypatch):
        rules = _generate(
            monkeypatch, _step("T1021.004"), ports=[22, 23, 9999])
        assert len(rules) == 2
        assert " 22 " in rules[0].rule_text
        assert " 23 " in rules[1].rule_text
        assert all(r.rule_category == "LATERAL_MOVEMENT" for r in rules)
        _assert_valid(rules)

    def test_rdp_rule(self, monkeypatch):
        rules = _generate(monkeypatch, _step("T1021.001"))
        assert len(rules) == 1
        assert " 3389 " in rules[0].rule_text
        assert rules[0].mitre_technique == "T1021.001"
        _assert_valid(rules)

    def test_web_rule_uses_each_open_http_port(self, monkeypatch):
        rules = _generate(
            monkeypatch, _step("T1190"), port_hits={443, 8080})
        assert len(rules) == 2
        assert all(r.rule_category == "INITIAL_ACCESS" for r in rules)
        used = [port for port in (80, 443, 8080, 8180, 8443)
                if any(f" {port} " in rule.rule_text for rule in rules)]
        assert used == [443, 8080]
        _assert_valid(rules)

    def test_rservices_rule(self, monkeypatch):
        rules = _generate(monkeypatch, _step("T1021"))
        assert [r.rule_category for r in rules] == ["LATERAL_MOVEMENT"]
        assert "[512,513,514]" in rules[0].rule_text
        _assert_valid(rules)

    def test_c2_rule_uses_negated_home_net(self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_TARGET", "10.44.0.0/24")
        rules = _generate(monkeypatch, _step("T1071"))
        assert [r.rule_category for r in rules] == ["C2"]
        assert "!10.44.0.0/24" in rules[0].rule_text
        _assert_valid(rules)

    def test_c2_invalid_network_falls_back_to_suricata_variable(
            self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_TARGET", "not-a-network")
        rule = rg._rule_c2_beacon("10.0.0.5", 9_000_001, 1)
        assert "!$HOME_NET" in rule
        assert rg.validate_rule(rule) == []

    def test_c2_unset_env_uses_scan_settings(self, monkeypatch):
        from config import settings

        monkeypatch.delenv("OBSIDIOS_TARGET", raising=False)
        monkeypatch.setattr(settings.scan, "target_network", "10.44.0.0/24")
        rule = rg._rule_c2_beacon("10.0.0.5", 9_000_001, 1)
        assert "!10.44.0.0/24" in rule

    def test_c2_settings_import_failure_uses_lab_default(self, monkeypatch):
        import sys

        monkeypatch.delenv("OBSIDIOS_TARGET", raising=False)
        monkeypatch.setitem(sys.modules, "config", None)

        rule = rg._rule_c2_beacon("10.0.0.5", 9_000_001, 1)

        assert "!192.168.1.0/24" in rule


class TestValidationEdges:
    def test_empty_option_block_is_rejected(self):
        rule = "alert tcp any any -> 192.168.1.10 21 ()"
        assert "empty option block" in rg.validate_rule(rule)

    def test_missing_rule_header_is_rejected(self):
        rule = 'alert (msg:"x"; sid:9000001; rev:1;)'
        assert "missing rule header" in rg.validate_rule(rule)

    def test_missing_sid_is_rejected(self):
        assert "missing sid" in rg.validate_rule(
            VALID.replace("sid:9000001;", ""))

    def test_escaped_quote_does_not_terminate_the_string(self):
        stripped, unterminated = rg._strip_quoted(r'"say \"hi\""')
        assert unterminated is False
        assert stripped == '""'


class TestPersistBranches:
    @staticmethod
    def _rule():
        return ForgeRule(rule_sid=0, attack_path_id=1, rule_text=VALID,
                         rule_category="EXPLOITATION")

    def test_existing_row_with_different_text_gets_a_fresh_rule(
            self, monkeypatch):
        stored = VALID.replace("Path#3", "Path#99")
        inserted = []

        async def fetch_all(_sql, _params=()):
            return [{"id": 5, "rule_sid": 9_000_001, "rule_text": stored,
                     "is_active": 1}]

        async def next_sid():
            return 9_000_555

        async def execute_returning(_sql, params=()):
            inserted.append(params)
            return {"id": 8}

        monkeypatch.setattr(rg.db, "fetch_all", fetch_all)
        monkeypatch.setattr(rg.db, "execute_returning", execute_returning)
        monkeypatch.setattr(rg, "_next_sid", next_sid)

        assert asyncio.run(rg._persist_rule(self._rule())) == 8
        assert inserted[0][0] == 9_000_555

    def test_non_unique_database_error_is_not_swallowed(self, monkeypatch):
        async def fetch_all(_sql, _params=()):
            return []

        async def next_sid():
            return 9_000_001

        async def execute_returning(_sql, _params=()):
            raise RuntimeError("disk I/O error")

        monkeypatch.setattr(rg.db, "fetch_all", fetch_all)
        monkeypatch.setattr(rg.db, "execute_returning", execute_returning)
        monkeypatch.setattr(rg, "_next_sid", next_sid)

        with pytest.raises(RuntimeError, match="disk I/O"):
            asyncio.run(rg._persist_rule(self._rule()))

    def test_unique_race_retries_with_a_fresh_valid_sid(self, monkeypatch):
        sids = iter([9_000_001, 9_000_002])
        attempts = []

        async def fetch_all(_sql, _params=()):
            return []

        async def next_sid():
            return next(sids)

        async def execute_returning(_sql, params=()):
            attempts.append(params)
            if len(attempts) == 1:
                raise Exception(
                    "UNIQUE constraint failed: forge_rules.rule_sid")
            return {"id": 77}

        monkeypatch.setattr(rg.db, "fetch_all", fetch_all)
        monkeypatch.setattr(rg.db, "execute_returning", execute_returning)
        monkeypatch.setattr(rg, "_next_sid", next_sid)

        rule = self._rule()
        assert asyncio.run(rg._persist_rule(rule)) == 77
        assert rule.rule_sid == 9_000_002
        assert attempts[-1][0] == 9_000_002

    def test_unique_race_is_bounded(self, monkeypatch):
        attempts = []
        sids = iter([9_000_001, 9_000_002, 9_000_003])

        async def fetch_all(_sql, _params=()):
            return []

        async def next_sid():
            return next(sids)

        async def execute_returning(_sql, params=()):
            attempts.append(params)
            raise Exception("UNIQUE constraint failed")

        monkeypatch.setattr(rg.db, "fetch_all", fetch_all)
        monkeypatch.setattr(rg.db, "execute_returning", execute_returning)
        monkeypatch.setattr(rg, "_next_sid", next_sid)

        assert asyncio.run(rg._persist_rule(self._rule())) is None
        assert len(attempts) == 3


class TestSidSequence:
    def test_missing_sequence_row_falls_back_to_max_rule_sid(self, monkeypatch):
        async def execute_returning(_sql, _params=()):
            return None

        async def fetch_val(_sql, _params=(), default=None):
            return 9_000_100

        monkeypatch.setattr(rg.db, "execute_returning", execute_returning)
        monkeypatch.setattr(rg.db, "fetch_val", fetch_val)

        assert asyncio.run(rg._next_sid()) == 9_000_101

    def test_empty_rules_table_starts_at_the_base(self, monkeypatch):
        async def execute_returning(_sql, _params=()):
            return None

        async def fetch_val(_sql, _params=(), default=None):
            return None

        monkeypatch.setattr(rg.db, "execute_returning", execute_returning)
        monkeypatch.setattr(rg.db, "fetch_val", fetch_val)

        assert asyncio.run(rg._next_sid()) == 9_000_000


class TestRulesOutputPath:
    def test_env_override_is_used(self, monkeypatch):
        monkeypatch.setenv("FORGE_RULES_PATH", "/tmp/custom.rules")
        assert rg._rules_output_path() == "/tmp/custom.rules"

    def test_default_points_at_the_forge_ruleset(self, monkeypatch):
        monkeypatch.delenv("FORGE_RULES_PATH", raising=False)
        assert rg._rules_output_path().endswith(
            "forge/rules/suricata.rules")



    def test_missing_settings_fall_back_to_the_repository_path(
            self, monkeypatch):
        import sys

        monkeypatch.delenv("FORGE_RULES_PATH", raising=False)
        monkeypatch.setitem(sys.modules, "config", None)
        assert rg._rules_output_path() == "forge/rules/suricata.rules"


class TestReloadFailureModes:
    def test_unbalanced_quoting_is_reported(self, monkeypatch):
        monkeypatch.setenv("FORGE_RELOAD_CMD", "'unterminated")
        ok, output = asyncio.run(rg._run_reload())
        assert ok is False
        assert "invalid FORGE_RELOAD_CMD" in output

    def test_timeout_kills_the_child(self, monkeypatch):
        class FakeProc:
            returncode = None

            def __init__(self):
                self.killed = False

            async def communicate(self):
                raise TimeoutError

            def kill(self):
                self.killed = True

        proc = FakeProc()

        async def spawn(*_args, **_kwargs):
            return proc

        monkeypatch.setattr(rg.asyncio, "create_subprocess_exec", spawn)
        monkeypatch.setenv("FORGE_RELOAD_CMD", "suricatasc -c reload-rules")

        ok, output = asyncio.run(rg._run_reload())

        assert ok is False
        assert "timed out" in output
        assert proc.killed is True

    def test_timeout_tolerates_a_child_that_already_exited(
            self, monkeypatch):
        class FakeProc:
            returncode = None

            async def communicate(self):
                raise TimeoutError

            def kill(self):
                raise ProcessLookupError

        async def spawn(*_args, **_kwargs):
            return FakeProc()

        monkeypatch.setattr(rg.asyncio, "create_subprocess_exec", spawn)
        monkeypatch.setenv("FORGE_RELOAD_CMD", "suricatasc -c reload-rules")

        ok, output = asyncio.run(rg._run_reload())

        assert ok is False
        assert "timed out" in output

    def test_empty_argv_is_never_executed(self, monkeypatch):
        async def spawn(*_args, **_kwargs):
            raise AssertionError("must not spawn with an empty argv")

        monkeypatch.setattr(rg.shlex, "split", lambda _cmd: [])
        monkeypatch.setattr(rg.asyncio, "create_subprocess_exec", spawn)
        monkeypatch.setenv("FORGE_RELOAD_CMD", "suricatasc -c reload-rules")

        ok, output = asyncio.run(rg._run_reload())

        assert ok is None
        assert "not configured" in output


GOOD_RULE = {
    "rule_text": VALID,
    "rule_category": "EXPLOITATION",
    "mitre_technique": "T1210",
    "rule_sid": 9_000_001,
}


def _db(monkeypatch, rows, execute=None):
    async def fetch_all(_sql, _params=()):
        return rows

    async def default_execute(_sql, _params=()):
        return None

    monkeypatch.setattr(rg.db, "fetch_all", fetch_all)
    monkeypatch.setattr(rg.db, "execute", execute or default_execute)


class TestWriteRuleFailures:
    def test_quarantine_db_failure_still_refuses_to_write(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        bad = {"id": 42, "rule_text": VALID.replace("rev:1;", ""),
               "rule_category": "EXPLOITATION",
               "mitre_technique": "T1210", "rule_sid": 9_000_001}

        async def execute(sql, _params=()):
            if "is_active=0" in sql:
                raise RuntimeError("database is locked")

        _db(monkeypatch, [bad], execute)
        out = tmp_path / "suricata.rules"

        delivery = asyncio.run(rg.write_rules_file(str(out)))

        assert delivery.ok is False
        assert "refused to write" in delivery.error
        assert not out.exists()

    def test_local_copy_falls_back_when_config_is_unavailable(
            self, tmp_path, monkeypatch):
        import sys

        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        _db(monkeypatch, [GOOD_RULE])
        written = []
        monkeypatch.setattr(
            rg, "_atomic_write",
            lambda path, _content, mode=0o644: written.append(str(path)))
        monkeypatch.setitem(sys.modules, "config", None)

        delivery = asyncio.run(
            rg.write_rules_file(str(tmp_path / "suricata.rules")))

        assert delivery.ok is True
        assert "reports/output/obsidios.rules" in written

    def test_local_copy_failure_does_not_block_the_sensor_file(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)
        _db(monkeypatch, [GOOD_RULE])
        real_write = rg._atomic_write

        def flaky(path, content, mode=0o644):
            if str(path) == str(tmp_path / "obsidios.rules"):
                raise OSError("read-only mount")
            return real_write(path, content, mode)

        monkeypatch.setattr(rg, "_atomic_write", flaky)
        out = tmp_path / "suricata.rules"

        delivery = asyncio.run(rg.write_rules_file(str(out)))

        assert delivery.ok is True
        assert out.exists()

    def test_bookkeeping_failure_does_not_undo_the_write(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr("config.settings.REPORTS_DIR", tmp_path)

        async def execute(sql, _params=()):
            if "delivered_at" in sql:
                raise RuntimeError("database is locked")

        _db(monkeypatch, [GOOD_RULE], execute)

        delivery = asyncio.run(
            rg.write_rules_file(str(tmp_path / "suricata.rules")))

        assert delivery.ok is True

    def test_delivery_record_failure_is_swallowed(self, monkeypatch):
        async def execute(_sql, _params=()):
            raise RuntimeError("database is locked")

        monkeypatch.setattr(rg.db, "execute", execute)

        asyncio.run(rg._persist_delivery(rg.RuleDelivery(ok=True)))

    def test_retire_failure_is_non_fatal(self, monkeypatch):
        async def execute(_sql, _params=()):
            raise RuntimeError("database is locked")

        monkeypatch.setattr(rg.db, "execute", execute)

        asyncio.run(rg._retire_stale_rules())


def _simulation(paths):
    from phantom.path_finder import SimulationResult

    return SimulationResult(paths=list(paths), total_paths=len(paths))


class TestRunForgeEdges:
    def test_empty_simulation_retires_and_rewrites_the_ruleset(self, monkeypatch):
        retired, delivered = [], []

        async def retire():
            retired.append(True)

        async def delivery():
            delivered.append(True)
            return rg.RuleDelivery(ok=True, rule_count=0)

        monkeypatch.setattr(rg, "_retire_stale_rules", retire)
        monkeypatch.setattr(rg, "write_rules_file", delivery)

        assert asyncio.run(rg.run_forge(_simulation([]))) == 0
        assert retired == [True]
        # The rewrite is what removes retired rules from the sensor.
        assert delivered == [True]

    def test_path_without_an_id_is_skipped(self, monkeypatch):
        retired, delivered = [], []

        async def retire():
            retired.append(True)

        async def delivery():
            delivered.append(True)
            return rg.RuleDelivery(ok=True, rule_count=0)

        monkeypatch.setattr(rg, "_retire_stale_rules", retire)
        monkeypatch.setattr(rg, "write_rules_file", delivery)
        monkeypatch.setattr(rg, "_print_rules_summary", lambda _rules: None)

        path = AttackPath(id=None, steps=[_step("T1021.002")])

        assert asyncio.run(rg.run_forge(_simulation([path]))) == 0
        assert retired == [True]
        assert delivered == [True]

    def test_prune_failure_does_not_abort_the_run(self, monkeypatch):
        path = AttackPath(id=7, steps=[_step("T1021.002")])
        rule = ForgeRule(rule_sid=0, attack_path_id=7, rule_text=VALID,
                         rule_category="EXPLOITATION")

        async def generate(*_args, **_kwargs):
            return [rule]

        async def persist(candidate):
            candidate.id = 11
            return 11

        async def retire():
            return None

        async def delivery():
            return rg.RuleDelivery(ok=True, rule_count=1, reload_ok=True)

        async def execute(sql, _params=()):
            if "id NOT IN" in sql:
                raise RuntimeError("database is locked")

        monkeypatch.setattr(rg, "_generate_rules_for_step", generate)
        monkeypatch.setattr(rg, "_persist_rule", persist)
        monkeypatch.setattr(rg, "_retire_stale_rules", retire)
        monkeypatch.setattr(rg, "write_rules_file", delivery)
        monkeypatch.setattr(rg, "_print_rules_summary", lambda _rules: None)
        monkeypatch.setattr(rg.db, "execute", execute)

        assert asyncio.run(rg.run_forge(_simulation([path]))) == 1

    def test_failed_delivery_is_logged_but_rules_still_count(
            self, monkeypatch):
        path = AttackPath(id=7, steps=[_step("T1021.002")])
        rule = ForgeRule(rule_sid=0, attack_path_id=7, rule_text=VALID,
                         rule_category="EXPLOITATION")

        async def generate(*_args, **_kwargs):
            return [rule]

        async def persist(candidate):
            candidate.id = 11
            return 11

        async def retire():
            return None

        async def delivery():
            return rg.RuleDelivery(
                ok=False, rule_count=1, error="disk full")

        monkeypatch.setattr(rg, "_generate_rules_for_step", generate)
        monkeypatch.setattr(rg, "_persist_rule", persist)
        monkeypatch.setattr(rg, "_retire_stale_rules", retire)
        monkeypatch.setattr(rg, "write_rules_file", delivery)
        monkeypatch.setattr(rg, "_print_rules_summary", lambda _rules: None)

        assert asyncio.run(rg.run_forge(_simulation([path]))) == 1


def test_print_rules_summary_renders_known_and_unknown_categories(capsys):
    rules = [
        ForgeRule(rule_sid=1, attack_path_id=1, rule_text=VALID,
                  rule_category="EXPLOITATION", mitre_technique="T1210"),
        ForgeRule(rule_sid=2, attack_path_id=1, rule_text=VALID,
                  rule_category="CUSTOM", mitre_technique="T9999"),
    ]

    rg._print_rules_summary(rules)

    output = capsys.readouterr().out
    assert "EXPLOITATION" in output
    assert "CUSTOM" in output
