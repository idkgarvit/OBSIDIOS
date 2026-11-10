"""CLI hardening regressions.

The local CLI is an operator interface to the same state the dashboard serves:
a target it accepts must be one IRIS will actually scan, every change belongs in
the audit trail, and a CLI scan must be visible as a completed scan to ORACLE.
"""
from __future__ import annotations

import asyncio
import io

import pytest
from click.testing import CliRunner

import obsidios
from config.settings import scan as scan_cfg
from config.settings import validate_nmap_arguments


class FakeDB:
    """Records writes and answers the handful of reads the CLI performs."""

    def __init__(self, rows=None, scan_id=42):
        self.executed: list[tuple[str, tuple]] = []
        self.rows = rows or []
        self.responses: dict[str, list] = {}
        self.scan_id = scan_id
        self.running_scans = 0
        self.scan_status = ""
        self.closed = False
        self.fail_audit = False

    async def init(self):
        return None

    async def close(self):
        self.closed = True

    async def execute(self, sql, params=()):
        if self.fail_audit and "audit_log" in sql:
            raise RuntimeError("audit disk full")
        self.executed.append((sql, params))

    async def execute_returning(self, sql, params=()):
        self.executed.append((sql, params))
        return {"id": self.scan_id} if self.scan_id is not None else None

    async def fetch_all(self, sql, params=()):
        for needle, rows in self.responses.items():
            if needle in sql:
                return rows
        return self.rows

    async def fetch_val(self, sql, params=(), default=None):
        if "status='RUNNING'" in sql:
            return self.running_scans
        if "SELECT status FROM scans" in sql:
            return self.scan_status
        return default


@pytest.fixture
def fake_db(monkeypatch):
    fake = FakeDB()

    async def init():
        return None

    async def close():
        await fake.close()

    async def execute(sql, params=()):
        await fake.execute(sql, params)

    async def execute_returning(sql, params=()):
        return await fake.execute_returning(sql, params)

    async def fetch_all(sql, params=()):
        return await fake.fetch_all(sql, params)

    async def fetch_val(sql, params=(), default=None):
        return await fake.fetch_val(sql, params, default)

    monkeypatch.setattr(obsidios.db, "init", init)
    monkeypatch.setattr(obsidios.db, "close", close)
    monkeypatch.setattr(obsidios.db, "execute", execute)
    monkeypatch.setattr(obsidios.db, "execute_returning", execute_returning)
    monkeypatch.setattr(obsidios.db, "fetch_all", fetch_all)
    monkeypatch.setattr(obsidios.db, "fetch_val", fetch_val)
    return fake


class TestTargetGuardrails:
    """The CLI used to persist any string the operator typed."""

    @pytest.mark.parametrize("cidr", [
        "0.0.0.0/0",      # internet-wide
        "10.0.0.0/8",     # broader than /16
        "garbage",
        "",
    ])
    def test_invalid_target_is_refused_before_any_write(self, monkeypatch, cidr):
        called = []

        async def never(*_args, **_kwargs):
            called.append(True)

        monkeypatch.setattr(obsidios.db, "init", never)
        result = CliRunner().invoke(obsidios.cli, ["config", "set-target", cidr])

        assert result.exit_code == 2
        assert "BLOCKED target" in result.output
        assert called == [], "validation must happen before the DB is touched"

    def test_public_range_requires_explicit_opt_in(self, monkeypatch):
        monkeypatch.delenv("OBSIDIOS_ALLOW_PUBLIC_SCAN", raising=False)
        target, error = obsidios.normalize_target_cidr("8.8.8.8/32")
        assert target is None
        assert "public range" in error

    def test_host_bits_are_normalised_before_storage(self, fake_db):
        result = CliRunner().invoke(
            obsidios.cli, ["config", "set-target", "192.168.1.7/24"])

        assert result.exit_code == 0, result.output
        stored = [p for sql, p in fake_db.executed if "target_network" in sql]
        assert stored == [("192.168.1.0/24",)]
        assert "192.168.1.0/24" in result.output

    def test_target_change_is_audited(self, fake_db, monkeypatch):
        monkeypatch.setenv("USER", "alice")

        result = CliRunner().invoke(
            obsidios.cli, ["config", "set-target", "10.20.30.0/24"])

        assert result.exit_code == 0, result.output
        audits = [p for sql, p in fake_db.executed if "audit_log" in sql]
        assert audits == [(
            "alice", "operator", "TARGET_UPDATE", "10.20.30.0/24",
            "source=cli", "local", "success",
        )]

    def test_single_scan_refuses_an_unsafe_target_before_the_db(self, monkeypatch):
        called = []

        async def never(*_args, **_kwargs):
            called.append(True)

        monkeypatch.setattr(obsidios.db, "init", never)
        result = CliRunner().invoke(
            obsidios.cli, ["scan", "--target", "0.0.0.0/0"])

        assert result.exit_code == 2
        assert "BLOCKED target" in result.output
        assert called == [], "validation must happen before the DB is touched"

    def test_single_scan_normalises_a_host_address(self, fake_db, monkeypatch):
        started = []

        async def no_hosts(_target):
            started.append(_target)
            return []

        monkeypatch.setattr(
            "iris.wired_scanner.discover_hosts", no_hosts)

        result = CliRunner().invoke(
            obsidios.cli, ["scan", "--target", "192.168.1.7/24"])

        assert result.exit_code == 0, result.output
        assert started == ["192.168.1.0/24"]

    def test_a_failed_audit_write_does_not_undo_the_change(self, fake_db):
        fake_db.fail_audit = True

        result = CliRunner().invoke(
            obsidios.cli, ["config", "set-target", "10.20.30.0/24"])

        assert result.exit_code == 0, result.output
        assert any("target_network" in sql for sql, _ in fake_db.executed)
        assert "Target Updated" in result.output


class TestProfileGuardrails:
    def test_unknown_profile_is_refused_before_any_write(self, monkeypatch):
        called = []

        async def never(*_args, **_kwargs):
            called.append(True)

        monkeypatch.setattr(obsidios.db, "init", never)
        result = CliRunner().invoke(
            obsidios.cli, ["config", "set-profile", "TURBO"])

        assert result.exit_code == 2
        assert "BLOCKED profile" in result.output
        assert called == []

    def test_profile_is_canonicalised_and_audited(self, fake_db):
        result = CliRunner().invoke(
            obsidios.cli, ["config", "set-profile", "stealth"])

        assert result.exit_code == 0, result.output
        stored = [p for sql, p in fake_db.executed if "scan_profile" in sql]
        assert stored == [("STEALTH",)]
        audits = [p for sql, p in fake_db.executed if "audit_log" in sql]
        assert audits[0][2] == "PROFILE_UPDATE"
        assert audits[0][3] == "STEALTH"

    def test_every_shipped_profile_has_a_valid_name(self):
        assert set(scan_cfg.SCAN_PROFILES) == {
            "FAST", "STEALTH", "GHOST", "STEALTH_IDLE"}

    @pytest.mark.parametrize("state,stored,label", [
        ("on", "1", "ONLINE"),
        ("off", "0", "PAUSED"),
        ("ON", "1", "ONLINE"),
    ])
    def test_scanner_switch_is_persisted_and_audited(
            self, fake_db, state, stored, label):
        result = CliRunner().invoke(
            obsidios.cli, ["config", "set-scanner", state])

        assert result.exit_code == 0, result.output
        values = [p for sql, p in fake_db.executed if "scanner_enabled" in sql]
        assert values == [(stored,)]
        audits = [p for sql, p in fake_db.executed if "audit_log" in sql]
        assert audits[0][2] == "SCANNER_UPDATE"
        assert label in result.output

    def test_unknown_scanner_state_is_refused(self, fake_db):
        result = CliRunner().invoke(
            obsidios.cli, ["config", "set-scanner", "maybe"])

        assert result.exit_code != 0
        assert not any("scanner_enabled" in sql for sql, _ in fake_db.executed)


class TestNmapGuardBypass:
    """A space was the only thing the deny-list understood."""

    def test_attached_input_list_is_rejected(self):
        ok, reason = validate_nmap_arguments("-sS -iL/etc/passwd")
        assert ok is False
        assert "-iL" in reason

    def test_random_target_sweep_is_rejected(self):
        ok, _reason = validate_nmap_arguments("-sS -iR100")
        assert ok is False

    def test_spaced_forms_are_still_rejected(self):
        assert validate_nmap_arguments("-sS -iL /etc/passwd")[0] is False
        assert validate_nmap_arguments("-sS -iR 100")[0] is False

    def test_all_shipped_profiles_stay_valid(self):
        for name, args in scan_cfg.SCAN_PROFILES.items():
            assert validate_nmap_arguments(args)[0] is True, name

    def test_ordinary_options_are_not_over_blocked(self):
        assert validate_nmap_arguments(
            "-sV -O -T4 --version-light -p 22,80")[0] is True


class TestScanLifecycle:
    """A CLI scan must leave a `scans` row ORACLE and the dashboard can see."""

    def _patch_discovery(self, monkeypatch, behaviour):
        from iris import wired_scanner

        monkeypatch.setattr(wired_scanner, "discover_hosts", behaviour)

    def test_empty_discovery_still_finishes_the_scan_row(self, fake_db, monkeypatch):
        async def no_hosts(_target):
            return []

        self._patch_discovery(monkeypatch, no_hosts)

        result = asyncio.run(obsidios._scan_pipeline("10.0.0.0/24"))

        assert result == (None, None, 0)
        assert any(
            "INSERT INTO scans" in sql and "RUNNING" in sql
            for sql, _ in fake_db.executed
        )
        final = [p for sql, p in fake_db.executed if "finished_at" in sql]
        assert final
        # (finished_at, hosts_found, ports_found, cves_found, scan_id)
        assert final[0][1:4] == (0, 0, 0)
        assert final[0][4] == 42
        # The finaliser only touches a row that is still RUNNING and marks it DONE.
        assert any(
            "status='DONE'" in sql and "status='RUNNING'" in sql
            for sql, _ in fake_db.executed if "finished_at" in sql
        )

    def test_cancelled_scan_never_starts_host_scanning(
            self, fake_db, monkeypatch):
        from iris import wired_scanner

        fake_db.scan_status = "CANCELLED"
        scanned = []

        async def one_host(_target):
            return [{"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:01"}]

        async def scan(_hosts):
            scanned.append(True)
            return []

        self._patch_discovery(monkeypatch, one_host)
        monkeypatch.setattr(wired_scanner, "scan_hosts_concurrent", scan)

        result, data, count = asyncio.run(
            obsidios._scan_pipeline("10.0.0.0/24"))

        assert scanned == []
        assert data is None and count == 0
        assert any("cancelled" in error.lower() for error in result.errors)

    def test_cancelled_mid_sweep_discards_partial_results(
            self, fake_db, monkeypatch):
        from iris import wired_scanner

        checks = iter([False, True])
        persisted = []

        async def cancelled(_scan_id):
            return next(checks)

        async def one_host(_target):
            return [{"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:01"}]

        async def scan(_hosts):
            return [{"ip": "10.0.0.5", "ports": [
                {"port": 22, "protocol": "tcp", "state": "open"}]}]

        async def upsert(*_args, **_kwargs):
            persisted.append(True)
            return {"10.0.0.5": 7}

        self._patch_discovery(monkeypatch, one_host)
        monkeypatch.setattr(wired_scanner, "scan_hosts_concurrent", scan)
        monkeypatch.setattr(wired_scanner, "_scan_cancelled", cancelled)
        monkeypatch.setattr(wired_scanner, "_upsert_hosts", upsert)

        result, data, count = asyncio.run(
            obsidios._scan_pipeline("10.0.0.0/24"))

        assert persisted == []
        assert data is None and count == 0
        assert any("cancelled" in error.lower() for error in result.errors)

    def test_finished_scan_records_counts_and_done_status(self, fake_db, monkeypatch):
        from iris import (
            cve_mapper,
            graph_builder,
            nuclei_scanner,
            osint_scanner,
            wired_scanner,
        )

        async def one_host(_target):
            return [{"ip": "10.0.0.5"}, "not-a-host", {}]

        async def scanned(_hosts):
            return [
                # Malformed records must be counted as absent, not crash.
                "not-a-host",
                {"ip": None},
                {"ip": "10.0.0.5", "os": [{"name": "Linux"}],
                 "ports": [
                     {"port": 22, "protocol": "tcp", "state": "open"},
                     {"port": 443, "protocol": "tcp", "state": "open"},
                     # One unmodellable port must not discard the valid ones.
                     {"port": "not-a-port"},
                 ]},
                # A null port list used to blow up the live display, and an OS
                # mapping must not be indexed as if it were a list.
                {"ip": "10.0.0.6", "ports": None,
                 "os": {"name": "Linux"}},
            ]

        class Display:
            def __init__(self):
                self.scanning = []
                self.done = []
                self.arp = []

            def start_arp(self, _target): pass
            def finish_arp(self, ips): self.arp = ips
            def start_nmap(self, _count): pass
            def host_scanning(self, ip): self.scanning.append(ip)
            def host_done(self, ip, ports, os_name):
                self.done.append((ip, ports, os_name))
            def start_cve_lookup(self, _count): pass
            def finish_cve(self, _count): pass
            def start_graph(self): pass
            def finish_graph(self, _nodes, _edges): pass

        async def upsert_hosts(_hosts, _scan_data):
            return {"10.0.0.5": 7}

        async def upsert_ports(_scan_data, _host_map, _started):
            return None

        async def no_cves(_result):
            return {}, {}

        async def persist(_cve_map, _result, _aff_map):
            return None

        async def no_osint(_ips):
            return None

        async def no_nuclei(_ips):
            return None

        async def graph():
            return type("Graph", (), {
                "number_of_nodes": lambda self: 1,
                "number_of_edges": lambda self: 0,
            })()

        monkeypatch.setattr(wired_scanner, "discover_hosts", one_host)
        monkeypatch.setattr(wired_scanner, "scan_hosts_concurrent", scanned)
        monkeypatch.setattr(wired_scanner, "_upsert_hosts", upsert_hosts)
        monkeypatch.setattr(wired_scanner, "_upsert_ports", upsert_ports)
        monkeypatch.setattr(cve_mapper, "map_cves_for_scan", no_cves)
        monkeypatch.setattr(cve_mapper, "persist_cves", persist)
        monkeypatch.setattr(osint_scanner, "run_osint_scan", no_osint)
        monkeypatch.setattr(nuclei_scanner, "run_nuclei_scan", no_nuclei)
        monkeypatch.setattr(graph_builder, "rebuild_graph", graph)

        display = Display()
        asyncio.run(obsidios._scan_pipeline("10.0.0.0/24", display))

        assert display.arp == ["10.0.0.5"]
        assert display.scanning == ["10.0.0.5"]
        assert display.done == [
            ("10.0.0.5", 3, "Linux"),
            ("10.0.0.6", 0, "Linux"),
        ]

        final = [p for sql, p in fake_db.executed if "finished_at" in sql]
        assert final
        _finished_at, hosts, ports, cves, scan_id = final[0]
        assert (hosts, ports, cves, scan_id) == (1, 2, 0, 42)

    def test_cli_scan_marks_unseen_hosts_offline(self, fake_db, monkeypatch):
        """A CLI scan must reconcile host liveness like the daemon scan does."""
        from iris import (
            cve_mapper,
            graph_builder,
            nuclei_scanner,
            osint_scanner,
            wired_scanner,
        )

        async def one_host(_target):
            return [{"ip": "10.0.0.5"}, "not-a-host", {}]

        async def scanned(_hosts):
            return [{"ip": "10.0.0.5", "ports": []}]

        async def upsert_hosts(_hosts, _scan_data):
            return {"10.0.0.5": 7}

        async def upsert_ports(_scan_data, _host_map, _started):
            return None

        async def no_cves(_result):
            return {}, {}

        async def persist(_cve_map, _result, _aff_map):
            return None

        async def no_ips(_ips):
            return None

        async def graph():
            return type("Graph", (), {
                "number_of_nodes": lambda self: 0,
                "number_of_edges": lambda self: 0,
            })()

        seen = {}

        async def offline(ips):
            seen["ips"] = ips
            return 0

        monkeypatch.setattr(wired_scanner, "discover_hosts", one_host)
        monkeypatch.setattr(wired_scanner, "scan_hosts_concurrent", scanned)
        monkeypatch.setattr(wired_scanner, "_upsert_hosts", upsert_hosts)
        monkeypatch.setattr(wired_scanner, "_upsert_ports", upsert_ports)
        monkeypatch.setattr(
            wired_scanner, "_mark_missing_hosts_offline", offline)
        monkeypatch.setattr(cve_mapper, "map_cves_for_scan", no_cves)
        monkeypatch.setattr(cve_mapper, "persist_cves", persist)
        monkeypatch.setattr(osint_scanner, "run_osint_scan", no_ips)
        monkeypatch.setattr(nuclei_scanner, "run_nuclei_scan", no_ips)
        monkeypatch.setattr(graph_builder, "rebuild_graph", graph)

        asyncio.run(obsidios._scan_pipeline("10.0.0.0/24"))

        assert seen["ips"] == ["10.0.0.5"]

    def test_scan_failure_is_recorded_then_reraised(self, fake_db, monkeypatch):
        async def exploding(_target):
            raise RuntimeError("nmap vanished")

        self._patch_discovery(monkeypatch, exploding)

        with pytest.raises(RuntimeError, match="nmap vanished"):
            asyncio.run(obsidios._scan_pipeline("10.0.0.0/24"))

        assert any(
            "status='FAILED'" in sql and p[1] == 42
            for sql, p in fake_db.executed
        )

    def test_no_scan_row_means_no_bookkeeping(self, fake_db, monkeypatch):
        fake_db.scan_id = None

        async def no_hosts(_target):
            return []

        self._patch_discovery(monkeypatch, no_hosts)
        asyncio.run(obsidios._scan_pipeline("10.0.0.0/24"))

        # execute_returning still ran, but a missing id must not produce an
        # UPDATE with a None id.
        assert not any("finished_at" in sql for sql, _ in fake_db.executed)


class TestTriggerTruthfulness:
    """`trigger` printed success even when the scan refused to run."""

    def _invoke(self, monkeypatch):
        monkeypatch.setattr(
            obsidios.uvloop, "run", lambda coroutine: asyncio.run(coroutine))
        return CliRunner().invoke(obsidios.cli, ["trigger"])

    def test_refused_scan_is_incomplete_and_closes_the_db(self, fake_db, monkeypatch):
        from chronicle.models import ScanResult
        from iris import wired_scanner

        async def refused():
            return ScanResult(target="10.0.0.0/24", errors=["no hosts discovered"])

        monkeypatch.setattr(wired_scanner, "run_scan", refused)

        result = self._invoke(monkeypatch)

        assert result.exit_code == 1
        assert "no hosts discovered" in result.output
        assert "incomplete" in result.output.lower()
        assert "cycle complete" not in result.output.lower()
        assert fake_db.closed is True

    def test_successful_scan_reports_completion(self, fake_db, monkeypatch):
        from chronicle.models import Host, ScanResult
        from iris import cve_mapper, graph_builder, wired_scanner

        calls = []

        async def scanned():
            return ScanResult(
                target="10.0.0.0/24",
                hosts=[Host(id=1, ip="10.0.0.5")],
            )

        async def no_cves(_result):
            return {}, {}

        async def persist(_cve_map, _result, _aff_map):
            calls.append("persist")
            return None

        async def graph():
            calls.append("graph")

        monkeypatch.setattr(wired_scanner, "run_scan", scanned)
        monkeypatch.setattr(cve_mapper, "map_cves_for_scan", no_cves)
        monkeypatch.setattr(cve_mapper, "persist_cves", persist)
        monkeypatch.setattr(graph_builder, "rebuild_graph", graph)

        result = self._invoke(monkeypatch)

        assert result.exit_code == 0, result.output
        assert "cycle complete" in result.output.lower()
        assert calls == ["persist", "graph"]
        assert fake_db.closed is True

    def test_scan_exception_still_closes_the_db(self, fake_db, monkeypatch):
        from iris import wired_scanner

        async def exploding():
            raise RuntimeError("nmap vanished")

        monkeypatch.setattr(wired_scanner, "run_scan", exploding)

        result = self._invoke(monkeypatch)

        assert result.exit_code != 0
        assert "cycle complete" not in result.output.lower()
        assert fake_db.closed is True

    def test_running_scan_returns_early_without_scanning(self, fake_db, monkeypatch):
        from iris import wired_scanner

        fake_db.running_scans = 1
        called = []

        async def scanned():
            called.append(True)

        monkeypatch.setattr(wired_scanner, "run_scan", scanned)

        result = self._invoke(monkeypatch)

        assert result.exit_code == 0, result.output
        assert "already in progress" in result.output
        assert called == []
        assert fake_db.closed is True


class TestMonthlySchedule:
    """The dashboard accepts `monthly`; the scheduler used to ignore it."""

    class OneShot:
        def __init__(self):
            self.calls = 0

        def is_set(self):
            self.calls += 1
            return self.calls > 1

    class FakeScheduler:
        def __init__(self):
            self.jobs = []
            self.removed = []
            self.shutdown_calls = []

        def start(self):
            return None

        def shutdown(self, wait=True):
            self.shutdown_calls.append(wait)

        def add_job(self, func, trigger, **kwargs):
            job = type("Job", (), {
                "id": f"job{len(self.jobs)}", "next_run_time": "later"})()
            self.jobs.append((trigger, kwargs))
            return job

        def remove_job(self, job_id):
            self.removed.append(job_id)

    def test_monthly_frequency_registers_a_cron_job(self, monkeypatch):
        scheduler = self.FakeScheduler()
        settings = {
            "schedule_frequency": "monthly",
            "schedule_time": "02:30",
            "schedule_enabled": "1",
        }

        async def fake_fetch_val(sql, params=(), default=None):
            for key, value in settings.items():
                if key in sql:
                    return value
            return default

        async def no_sleep(_seconds):
            return None

        monkeypatch.setattr("chronicle.db.fetch_val", fake_fetch_val)
        monkeypatch.setattr(obsidios, "AsyncIOScheduler", lambda: scheduler)
        monkeypatch.setattr(obsidios, "_shutdown", self.OneShot())
        monkeypatch.setattr(obsidios.asyncio, "sleep", no_sleep)

        asyncio.run(obsidios.run_scheduler())

        assert ("cron", {"day": 1, "hour": 2, "minute": 30}) in scheduler.jobs
        assert scheduler.shutdown_calls == [False]


class TestPhantomRendering:
    def test_model_markup_cannot_crash_the_panel(self, fake_db):
        fake_db.rows = [{
            "attacker_roi": 9.5,
            "path_json": '[{"ip": "10.0.0.9"}, 5, null]',
            "narrative": "close [/] and [bold not a tag and \x1b[31mred",
        }]

        result = CliRunner().invoke(obsidios.cli, ["phantom"])

        assert result.exit_code == 0, result.output
        assert "10.0.0.9" in result.output

    def test_non_list_path_still_renders(self, fake_db):
        fake_db.rows = [{
            "attacker_roi": None,
            "path_json": "42",
            "narrative": None,
        }]

        result = CliRunner().invoke(obsidios.cli, ["phantom"])

        assert result.exit_code == 0, result.output
        assert "Unknown Path" in result.output
        assert "No narrative available" in result.output


class TestWarRoomRendering:
    """War Room panels must survive markup from command output and DB rows.

    `obsidios hub` renders subprocess output and database fields as Rich markup.
    A stray `[/]` used to raise MarkupError inside the render loop and kill the
    whole TUI, so an operator watching a scan could lose the console because a
    hostname or SSID contained brackets.
    """

    @staticmethod
    def _render(panel) -> str:
        from rich.console import Console

        console = Console(record=True, width=120, file=io.StringIO())
        console.print(panel)
        return console.export_text()

    def test_feed_renders_hostile_output_literally(self):
        tui = obsidios.WarRoomTUI()
        tui.make_layout()
        tui.log_history.append("> nmap says [/] done")

        tui.update_feed()

        assert "[/] done" in self._render(tui.layout["feed"])

    def test_intel_panel_escapes_database_values(self):
        tui = obsidios.WarRoomTUI()
        tui.make_layout()

        tui.update_intel(
            [{"target_ip": "10.0.0.9 [bold"}],
            [{"finding_type": "ssid [/] leaked"}],
        )

        text = self._render(tui.layout["intel"])
        assert "10.0.0.9 [bold" in text
        assert "ssid [/] leaked" in text


class TestDbAlwaysCloses:
    """A command body that raises must still release the SQLite connection.

    These commands used to call `await db.close()` only on the happy path, so a
    failed read left the connection (and its write lock) alive until process
    exit. Keeping it in `finally` also makes the failure mode identical for
    long-lived CLI callers such as the interactive shell.
    """

    def _invoke(self, monkeypatch, args):
        monkeypatch.setattr(
            obsidios.uvloop, "run", lambda coroutine: asyncio.run(coroutine))
        return CliRunner().invoke(obsidios.cli, args)

    @pytest.mark.parametrize(("args", "module", "attr"), [
        (["echo"], "echo.drift_detector", "run_echo"),
        (["sentinel"], "sentinel.runner", "start_sentinel"),
        (["status"], "oracle.posture_score", "calculate_posture_score"),
        (["audit"], "oracle.compliance_mapper", "map_compliance"),
        (["remediation"], "oracle.patch_prioritizer",
         "generate_patch_priority"),
    ])
    def test_failing_backend_closes_the_db(
            self, fake_db, monkeypatch, args, module, attr):
        import importlib

        async def boom(*_args, **_kwargs):
            raise RuntimeError("backend unavailable")

        monkeypatch.setattr(importlib.import_module(module), attr, boom)

        result = self._invoke(monkeypatch, args)

        assert result.exit_code != 0
        assert isinstance(result.exception, RuntimeError)
        assert fake_db.closed is True

    def test_failing_scan_pipeline_closes_the_db(self, fake_db, monkeypatch):
        import iris.live_display as live

        class Display:
            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                return False

            def print_final_summary(self):
                pass

        async def boom(*_args, **_kwargs):
            raise RuntimeError("scan failed")

        monkeypatch.setattr(live, "ScanDisplay", lambda _target: Display())
        monkeypatch.setattr(obsidios, "_scan_pipeline", boom)

        result = self._invoke(monkeypatch, ["scan"])

        assert result.exit_code != 0
        assert isinstance(result.exception, RuntimeError)
        assert fake_db.closed is True

    @pytest.mark.parametrize("args", [
        ["shield"],
        ["iris"],
        ["phantom"],
        ["config", "show"],
    ])
    def test_failing_read_closes_the_db(self, fake_db, monkeypatch, args):
        async def boom(*_args, **_kwargs):
            raise RuntimeError("db read failed")

        # config show reads fetch_val; the others read fetch_all.
        fake_db.fetch_all = boom
        fake_db.fetch_val = boom

        result = self._invoke(monkeypatch, args)

        assert result.exit_code != 0
        assert isinstance(result.exception, RuntimeError)
        assert fake_db.closed is True

    @pytest.mark.parametrize("args", [
        ["config", "set-target", "10.20.30.0/24"],
        ["config", "set-profile", "stealth"],
    ])
    def test_failing_write_closes_the_db(self, fake_db, monkeypatch, args):
        async def boom(*_args, **_kwargs):
            raise RuntimeError("disk full")

        fake_db.execute = boom

        result = self._invoke(monkeypatch, args)

        assert result.exit_code != 0
        assert isinstance(result.exception, RuntimeError)
        assert fake_db.closed is True


class TestOrchestratorCleanup:
    """`obsidios run` must shut down cleanly when startup fails part-way."""

    def test_setup_failure_closes_the_db(self, fake_db):
        from config.settings import scan as scan_cfg

        async def boom(*_args, **_kwargs):
            raise RuntimeError("settings write failed")

        fake_db.execute = boom
        old_target = scan_cfg.target_network
        old_interval = scan_cfg.scan_interval_seconds
        try:
            with pytest.raises(RuntimeError, match="settings write failed"):
                asyncio.run(obsidios._run_all("10.0.0.0/24", 60))
        finally:
            scan_cfg.target_network = old_target
            scan_cfg.scan_interval_seconds = old_interval

        assert fake_db.closed is True

    def test_setup_failure_cancels_tasks_already_started(
            self, fake_db, monkeypatch):
        from config.settings import scan as scan_cfg

        real_create_task = asyncio.create_task
        started = []
        calls = {"n": 0}

        def flaky_create_task(coro, **kwargs):
            calls["n"] += 1
            if calls["n"] == 3:
                coro.close()
                raise RuntimeError("scheduler unavailable")
            task = real_create_task(coro, **kwargs)
            started.append(task)
            return task

        monkeypatch.setattr(obsidios.asyncio, "create_task", flaky_create_task)
        old_target = scan_cfg.target_network
        old_interval = scan_cfg.scan_interval_seconds
        try:
            with pytest.raises(RuntimeError, match="scheduler unavailable"):
                asyncio.run(obsidios._run_all("10.0.0.0/24", 60))
        finally:
            scan_cfg.target_network = old_target
            scan_cfg.scan_interval_seconds = old_interval

        assert fake_db.closed is True
        assert started, "the first two loops should have been scheduled"
        # No task may be left pending. The scan wrapper deliberately swallows
        # CancelledError to break its retry loop, so `done()` is the invariant.
        assert all(task.done() for task in started)
        assert started[0].cancelled()


class TestAuditFramework:
    """An unknown framework used to raise KeyError after a successful DB open."""

    def _invoke(self, monkeypatch, framework):
        monkeypatch.setattr(
            obsidios.uvloop, "run", lambda coroutine: asyncio.run(coroutine))
        return CliRunner().invoke(
            obsidios.cli, ["audit", framework])

    def test_unknown_framework_is_blocked_with_the_valid_list(
            self, fake_db, monkeypatch):
        result = self._invoke(monkeypatch, "ISO27001")

        assert result.exit_code == 2, result.output
        assert "BLOCKED framework 'ISO27001'" in result.output
        assert "Unknown framework" in result.output
        assert "PCI-DSS" in result.output
        assert fake_db.closed is True

    def test_known_framework_renders_the_report(self, fake_db, monkeypatch):
        result = self._invoke(monkeypatch, "pci-dss")

        assert result.exit_code == 0, result.output
        assert "Compliance Audit: PCI-DSS" in result.output
        assert "Requirement" in result.output or "COMPLIANT" in result.output
        assert fake_db.closed is True


class TestShieldRelease:
    """Releasing a block must never claim success while a rule is still live."""

    def _invoke(self, monkeypatch, release="10.44.0.9"):
        monkeypatch.setattr(
            obsidios.uvloop, "run", lambda coroutine: asyncio.run(coroutine))
        return CliRunner().invoke(
            obsidios.cli, ["shield", "--release", release])

    def test_no_active_block_is_reported_plainly(self, fake_db, monkeypatch):
        fake_db.rows = []

        result = self._invoke(monkeypatch)

        assert result.exit_code == 0, result.output
        assert "No active SHIELD block for 10.44.0.9" in result.output
        assert fake_db.closed is True

    def test_all_blocks_released_confirms(self, fake_db, monkeypatch):
        fake_db.rows = [{"id": 1}, {"id": 2}]

        async def ok(_action_id, reverted_by="HUMAN"):
            return True

        monkeypatch.setattr("shield.reconfigurer.revert_action", ok)

        result = self._invoke(monkeypatch)

        assert result.exit_code == 0, result.output
        assert "RELEASED" in result.output
        assert fake_db.closed is True

    def test_partial_failure_exits_non_zero(self, fake_db, monkeypatch):
        fake_db.rows = [{"id": 1}, {"id": 2}, {"id": 3}]

        async def flaky(action_id, reverted_by="HUMAN"):
            if action_id == 2:
                return False
            if action_id == 3:
                raise RuntimeError("iptables locked")
            return True

        monkeypatch.setattr("shield.reconfigurer.revert_action", flaky)

        result = self._invoke(monkeypatch)

        assert result.exit_code == 1, result.output
        assert "Released 1/3 block(s)" in result.output
        assert "2 could not be removed" in result.output
        assert "may still be live" in result.output
        assert fake_db.closed is True

    def test_active_blocks_are_listed(self, fake_db, monkeypatch):
        fake_db.rows = [{
            "id": 1, "taken_at": 0, "target_ip": "10.44.0.9",
            "action_type": "BLOCK_IP", "justification": "port scan",
        }]

        result = CliRunner().invoke(obsidios.cli, ["shield"])

        assert result.exit_code == 0, result.output
        assert "10.44.0.9" in result.output
        assert "BLOCK_IP" in result.output
        assert "port scan" in result.output


class TestDashStartup:
    """Container startup must fail closed and surface gunicorn's exit code."""

    def test_prod_config_errors_block_startup(self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_ENV", "prod")
        import config.settings as settings_mod

        monkeypatch.setattr(
            settings_mod, "validate_prod_config",
            lambda: ["SECRET_KEY is the default", "weak operator password"])
        launched = []
        monkeypatch.setattr(
            obsidios.subprocess, "run",
            lambda *args, **kwargs: launched.append(args))

        result = CliRunner().invoke(obsidios.cli, ["dash"])

        assert result.exit_code == 2, result.output
        assert "BLOCKED: SECRET_KEY is the default" in result.output
        assert "weak operator password" in result.output
        assert launched == []

    def test_gunicorn_failure_is_propagated(self, monkeypatch):
        monkeypatch.delenv("OBSIDIOS_ENV", raising=False)

        class Proc:
            returncode = 3

        monkeypatch.setattr(
            obsidios.subprocess, "run", lambda *args, **kwargs: Proc())

        result = CliRunner().invoke(obsidios.cli, ["dash"])

        assert result.exit_code == 3


class TestRunCommandValidation:
    """`run` used to accept anything and silently fall back to FAST."""

    def _invoke_without_starting(self, args, monkeypatch):
        def must_not_start(_coroutine):
            raise AssertionError("the scan must not start")

        monkeypatch.setattr(obsidios.uvloop, "run", must_not_start)
        monkeypatch.setattr(obsidios.settings.scan, "scan_profile", "FAST")
        return CliRunner().invoke(obsidios.cli, ["run", *args])

    def test_unknown_profile_is_refused(self, monkeypatch):
        result = self._invoke_without_starting(
            ["--profile", "GHOSTY"], monkeypatch)

        assert result.exit_code == 2, result.output
        assert "BLOCKED profile" in result.output

    def test_non_positive_interval_is_refused(self, monkeypatch):
        result = self._invoke_without_starting(
            ["--interval", "0"], monkeypatch)

        assert result.exit_code == 2, result.output
        assert "BLOCKED interval" in result.output

    def test_lowercase_profile_is_canonicalised(self, monkeypatch):
        captured = {}

        def fake_run(coroutine):
            coroutine.close()
            captured["profile"] = obsidios.settings.scan.scan_profile

        monkeypatch.setattr(obsidios.uvloop, "run", fake_run)
        monkeypatch.setattr(obsidios.settings.scan, "scan_profile", "FAST")

        result = CliRunner().invoke(obsidios.cli, ["run", "--profile", "ghost"])

        assert result.exit_code == 0, result.output
        assert captured["profile"] == "GHOST"


class TestUntrustedTextRendering:
    """Scan data and operator input are literal text, never Rich markup."""

    def _invoke(self, monkeypatch, args):
        monkeypatch.setattr(
            obsidios.uvloop, "run", lambda coroutine: asyncio.run(coroutine))
        return CliRunner().invoke(obsidios.cli, args)

    def test_hostile_wifi_ssid_renders_literally(self, fake_db, monkeypatch):
        """A nearby AP controls its SSID; '[/]' must not crash the iris view."""
        fake_db.responses = {
            "osint_findings": [],
            "wireless_threats": [{
                "ssid": "evil[/]office",
                "threat_type": "ROGUE_AP",
                "signal_strength": -42,
            }],
        }

        result = self._invoke(monkeypatch, ["iris"])

        assert result.exit_code == 0, result.output
        assert "evil[/]office" in result.output
        assert "ROGUE_AP" in result.output
        assert fake_db.closed is True


class TestShellResilience:
    def test_a_command_failure_does_not_exit_the_shell(self, monkeypatch):
        """A refused command raises SystemExit; the interactive shell must live."""
        answers = iter(["config set-profile NOT-A-PROFILE", "exit"])
        monkeypatch.setattr(
            obsidios.console, "input", lambda *_a, **_k: next(answers))

        result = CliRunner().invoke(obsidios.cli, ["shell"])

        assert result.exit_code == 0, result.output
        assert "BLOCKED profile" in result.output

    def test_markup_in_an_unknown_command_does_not_kill_the_shell(
            self, monkeypatch):
        """Rich parses console.print, so a stray '[/]' used to raise MarkupError."""
        answers = iter(["bogus[/]cmd", "exit"])
        monkeypatch.setattr(
            obsidios.console, "input", lambda *_a, **_k: next(answers))

        result = CliRunner().invoke(obsidios.cli, ["shell"])

        assert result.exit_code == 0, result.output
        assert "Unknown command: bogus[/]cmd" in result.output
