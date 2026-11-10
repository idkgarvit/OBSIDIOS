"""Orchestrator regressions: notifications must never stop the scanner.

The daemon's job is to scan, simulate and block. A Discord webhook that is
down, a malformed schedule entry or a failed gunicorn bind must not silently
disable any of that, and the CLI must never claim a block was released while
the kernel rule is still installed.
"""
from __future__ import annotations

import asyncio
import sqlite3
import time

from click.testing import CliRunner

import obsidios
from chronicle.models import ScanResult
from config import settings
from phantom.path_finder import SimulationResult


class _DBRecorder:
    def __init__(self, manual: str = "1"):
        self.manual = manual
        self.executed: list[tuple[str, tuple]] = []

    async def execute(self, sql, params=()):
        self.executed.append((sql, tuple(params)))

    async def fetch_val(self, sql, params=(), default=None):
        if "manual_trigger" in sql:
            value = self.manual
            self.manual = "0" if self.manual == "1" else self.manual
            return value
        if "scanner_enabled" in sql:
            return "1"
        if "_paused_alert_sent" in sql:
            return "0"
        if "retention_days" in sql:
            return "30"
        if "FROM scans" in sql:
            return None
        return default


def test_notify_swallows_a_dead_webhook(monkeypatch):
    from alerts import notifier

    async def exploding(**_kwargs):
        raise RuntimeError("webhook unreachable")

    monkeypatch.setattr(notifier, "send_alert", exploding)
    asyncio.run(obsidios._notify("test", "message"))


def test_a_dead_webhook_does_not_skip_the_scan(monkeypatch):
    """Every notification in a cycle used to abort the scan before it ran."""
    from alerts import notifier
    from iris import cve_mapper, exploit_validator, graph_builder, nuclei_scanner, osint_scanner, wired_scanner
    from oracle import claude_client, tagnn
    from phantom import path_finder

    scans = []

    async def exploding(**_kwargs):
        raise RuntimeError("webhook unreachable")

    async def fake_scan():
        scans.append(True)
        obsidios._shutdown.set()
        return ScanResult(target="10.0.0.0/24", scan_id=1)

    monkeypatch.setattr(notifier, "send_alert", exploding)
    monkeypatch.setattr(wired_scanner, "run_scan", fake_scan)
    monkeypatch.setattr(cve_mapper, "map_cves_for_scan", _empty_cve_map)
    monkeypatch.setattr(cve_mapper, "persist_cves", _noop)
    monkeypatch.setattr(exploit_validator, "validate_exploits", _exploit_stats)
    monkeypatch.setattr(osint_scanner, "run_osint_scan", _noop_args)
    monkeypatch.setattr(nuclei_scanner, "run_nuclei_scan", _noop_args)
    monkeypatch.setattr(wired_scanner, "run_wireless_scan", _noop)
    monkeypatch.setattr(graph_builder, "rebuild_graph", _graph)
    monkeypatch.setattr(tagnn, "run_tagnn_prediction", _noop)
    monkeypatch.setattr(path_finder, "run_simulation", _simulation)
    monkeypatch.setattr(claude_client, "generate_report", _report)
    monkeypatch.setattr("forge.rule_generator.run_forge", _forge_noop)
    monkeypatch.setattr(obsidios, "scan_counter", 0)

    fake_db = _DBRecorder(manual="1")
    monkeypatch.setattr("chronicle.db.execute", fake_db.execute)
    monkeypatch.setattr("chronicle.db.fetch_val", fake_db.fetch_val)
    monkeypatch.setattr(settings.scan, "scan_interval_seconds", 0)

    obsidios._shutdown.clear()
    asyncio.run(obsidios.scan_cycle(asyncio.Event()))

    assert scans == [True]
    assert any("scan_phase" in sql for sql, _ in fake_db.executed)


async def _empty_cve_map(_result):
    return {}, {}


async def _noop(*_args, **_kwargs):
    return None


async def _noop_args(*_args, **_kwargs):
    return None


async def _exploit_stats():
    return {"validated": 0, "msf_count": 0, "edb_count": 0}


async def _graph():
    import networkx as nx
    return nx.DiGraph()


async def _simulation(max_paths=10):
    return SimulationResult()


async def _report():
    return "reports/output/latest.pdf"


async def _forge_noop(_simulation):
    return 0


class TestCliTruthfulness:
    def test_release_removes_the_kernel_rule(self, monkeypatch):
        from shield import reconfigurer

        reverted = []

        async def fake_init():
            return None

        async def fake_fetch_all(_sql, _params=()):
            return [{"id": 4}, {"id": 9}]

        async def fake_revert(action_id, reverted_by="HUMAN"):
            reverted.append((action_id, reverted_by))
            return True

        monkeypatch.setattr(obsidios.db, "init", fake_init)
        monkeypatch.setattr(obsidios.db, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(reconfigurer, "revert_action", fake_revert)

        result = CliRunner().invoke(obsidios.cli, ["shield", "--release", "10.0.0.5"])

        assert result.exit_code == 0, result.output
        assert reverted == [(4, "CLI"), (9, "CLI")]
        assert "RELEASED" in result.output

    def test_release_reports_a_rule_it_could_not_remove(self, monkeypatch):
        from shield import reconfigurer

        async def fake_init():
            return None

        async def fake_fetch_all(_sql, _params=()):
            return [{"id": 4}]

        async def fake_revert(_action_id, reverted_by="HUMAN"):
            return False

        monkeypatch.setattr(obsidios.db, "init", fake_init)
        monkeypatch.setattr(obsidios.db, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(reconfigurer, "revert_action", fake_revert)

        result = CliRunner().invoke(obsidios.cli, ["shield", "--release", "10.0.0.5"])

        # A partial release is a failure: automation must not treat the IP as
        # unblocked while a DROP rule is still installed.
        assert result.exit_code == 1, result.output
        assert "may still be live" in result.output
        assert "RELEASED" not in result.output

    def test_failed_gunicorn_bind_exits_non_zero(self, monkeypatch):
        class Failed:
            returncode = 9

        monkeypatch.setattr(obsidios.subprocess, "run", lambda *_a, **_k: Failed())
        monkeypatch.setenv("OBSIDIOS_ENV", "dev")

        result = CliRunner().invoke(obsidios.cli, ["dash", "--port", "8099"])

        assert result.exit_code == 9


class TestScheduledScanTruthfulness:
    """A scheduled scan must not log success when the sweep was refused."""

    class _Logger:
        def __init__(self):
            self.events = []

        def _record(self, level, message):
            self.events.append((level, message))

        def error(self, message): self._record("error", message)
        def warning(self, message): self._record("warning", message)
        def success(self, message): self._record("success", message)
        def info(self, message): self._record("info", message)

    def test_refused_sweep_logs_incomplete(self, monkeypatch):
        from iris import cve_mapper, graph_builder, wired_scanner

        calls = []
        sink = self._Logger()

        async def refused():
            return ScanResult(
                target="10.0.0.0/24", errors=["no hosts discovered"])

        async def persist(*_args, **_kwargs):
            calls.append("persist")

        async def rebuild():
            calls.append("graph")

        async def enabled(_sql, _params=(), default=None):
            return "1"

        monkeypatch.setattr("chronicle.db.fetch_val", enabled)
        monkeypatch.setattr(wired_scanner, "run_scan", refused)
        monkeypatch.setattr(cve_mapper, "persist_cves", persist)
        monkeypatch.setattr(graph_builder, "rebuild_graph", rebuild)
        monkeypatch.setattr(obsidios, "logger", sink)
        monkeypatch.setattr(obsidios, "_scan_busy", False)

        asyncio.run(obsidios._scheduled_scan_cycle())

        assert calls == []
        assert sink.events and sink.events[0][0] == "error"
        assert "incomplete" in sink.events[0][1].lower()
        assert "no hosts discovered" in sink.events[0][1]

    def test_successful_sweep_logs_the_host_count(self, monkeypatch):
        from chronicle.models import Host
        from iris import cve_mapper, graph_builder, wired_scanner

        sink = self._Logger()
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

        async def rebuild():
            calls.append("graph")

        async def enabled(_sql, _params=(), default=None):
            return "1"

        monkeypatch.setattr("chronicle.db.fetch_val", enabled)
        monkeypatch.setattr(wired_scanner, "run_scan", scanned)
        monkeypatch.setattr(cve_mapper, "map_cves_for_scan", no_cves)
        monkeypatch.setattr(cve_mapper, "persist_cves", persist)
        monkeypatch.setattr(graph_builder, "rebuild_graph", rebuild)
        monkeypatch.setattr(obsidios, "logger", sink)
        monkeypatch.setattr(obsidios, "_scan_busy", False)

        asyncio.run(obsidios._scheduled_scan_cycle())

        assert calls == ["persist", "graph"]
        assert sink.events and sink.events[-1][0] == "success"
        assert "1 host" in sink.events[-1][1]

    def test_paused_scanner_skips_the_scheduled_sweep(self, monkeypatch):
        """The dashboard pause switch must silence cron scans, not just the loop."""
        from iris import wired_scanner

        ran = []
        sink = self._Logger()

        async def scanned():
            ran.append(True)
            return ScanResult(target="10.0.0.0/24")

        async def disabled(_sql, _params=(), default=None):
            return "0"

        monkeypatch.setattr("chronicle.db.fetch_val", disabled)
        monkeypatch.setattr(wired_scanner, "run_scan", scanned)
        monkeypatch.setattr(obsidios, "logger", sink)
        monkeypatch.setattr(obsidios, "_scan_busy", False)

        asyncio.run(obsidios._scheduled_scan_cycle())

        assert ran == []
        assert any("paused" in message.lower() for _level, message in sink.events)

    def test_overlapping_scheduled_sweep_is_skipped(self, monkeypatch):
        from iris import wired_scanner

        ran = []
        sink = self._Logger()

        async def scanned():
            ran.append(True)
            return ScanResult(target="10.0.0.0/24")

        async def enabled(_sql, _params=(), default=None):
            return "1"

        monkeypatch.setattr("chronicle.db.fetch_val", enabled)
        monkeypatch.setattr(wired_scanner, "run_scan", scanned)
        monkeypatch.setattr(obsidios, "logger", sink)
        monkeypatch.setattr(obsidios, "_scan_busy", True)

        asyncio.run(obsidios._scheduled_scan_cycle())

        assert ran == []
        assert any("another scan is running" in message.lower()
                   for _level, message in sink.events)


class TestHubSnapshot:
    """The War Room's DB reader swallowed Ctrl-C and leaked connections."""

    def _seed(self, path):
        import sqlite3

        conn = sqlite3.connect(path)
        conn.executescript("""
            CREATE TABLE posture_scores (
                overall_score INTEGER, active_alerts INTEGER, recorded_at REAL);
            CREATE TABLE hosts (is_active INTEGER);
            CREATE TABLE shield_actions (target_ip TEXT, is_active INTEGER);
            CREATE TABLE osint_findings (finding_type TEXT, discovered_at REAL);
        """)
        conn.executemany(
            "INSERT INTO posture_scores VALUES (?, ?, ?)",
            [(40, 2, 1.0), (77, 5, 2.0)],
        )
        conn.executemany(
            "INSERT INTO hosts VALUES (?)", [(1,), (1,), (0,)])
        conn.executemany(
            "INSERT INTO shield_actions VALUES (?, ?)",
            [("10.0.0.9", 1), ("10.0.0.10", 0)],
        )
        conn.executemany(
            "INSERT INTO osint_findings VALUES (?, ?)",
            [("EMAIL", 1.0), ("SUBDOMAIN", 2.0)],
        )
        conn.commit()
        conn.close()

    def test_reads_latest_posture_and_active_rows(self, tmp_path):
        path = tmp_path / "hub.db"
        self._seed(path)

        posture, assets, threats, blocks, osint = obsidios._read_hub_snapshot(path)

        assert posture == 77
        assert assets == 2
        assert threats == 5
        assert blocks == [{"target_ip": "10.0.0.9"}]
        assert osint == [
            {"finding_type": "SUBDOMAIN"},
            {"finding_type": "EMAIL"},
        ]

    def test_missing_database_returns_zero_tiles(self, tmp_path):
        missing = tmp_path / "no-such-dir" / "hub.db"

        assert obsidios._read_hub_snapshot(missing) == (0, 0, 0, [], [])

    def test_old_schema_returns_zero_tiles_instead_of_raising(self, tmp_path):
        import sqlite3

        path = tmp_path / "old.db"
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE unrelated (id INTEGER)")
        conn.commit()
        conn.close()

        assert obsidios._read_hub_snapshot(path) == (0, 0, 0, [], [])


def test_scan_cycle_does_not_claim_success_for_a_refused_scan(monkeypatch):
    from iris import (
        cve_mapper,
        exploit_validator,
        graph_builder,
        nuclei_scanner,
        osint_scanner,
        wired_scanner,
    )
    from oracle import claude_client, tagnn
    from phantom import path_finder

    class Sink:
        def __init__(self):
            self.events = []

        def _record(self, level, message):
            self.events.append((level, message))

        def debug(self, message): self._record("debug", message)
        def info(self, message): self._record("info", message)
        def warning(self, message): self._record("warning", message)
        def success(self, message): self._record("success", message)
        def error(self, message): self._record("error", message)
        def exception(self, message): self._record("exception", message)

    sink = Sink()

    async def refused():
        obsidios._shutdown.set()
        return ScanResult(
            target="10.0.0.0/24", errors=["no hosts discovered"])

    async def notify(*_args, **_kwargs):
        return None

    monkeypatch.setattr(obsidios, "logger", sink)
    monkeypatch.setattr(obsidios, "_notify", notify)
    monkeypatch.setattr(obsidios, "scan_counter", 0)
    monkeypatch.setattr(wired_scanner, "run_scan", refused)
    monkeypatch.setattr(wired_scanner, "run_wireless_scan", _noop)
    monkeypatch.setattr(cve_mapper, "map_cves_for_scan", _empty_cve_map)
    monkeypatch.setattr(cve_mapper, "persist_cves", _noop)
    monkeypatch.setattr(exploit_validator, "validate_exploits", _exploit_stats)
    monkeypatch.setattr(osint_scanner, "run_osint_scan", _noop_args)
    monkeypatch.setattr(nuclei_scanner, "run_nuclei_scan", _noop_args)
    monkeypatch.setattr(graph_builder, "rebuild_graph", _graph)
    monkeypatch.setattr(tagnn, "run_tagnn_prediction", _noop)
    monkeypatch.setattr(path_finder, "run_simulation", _simulation)
    monkeypatch.setattr(claude_client, "generate_report", _report)
    monkeypatch.setattr("forge.rule_generator.run_forge", _forge_noop)

    fake_db = _DBRecorder(manual="1")
    monkeypatch.setattr("chronicle.db.execute", fake_db.execute)
    monkeypatch.setattr("chronicle.db.fetch_val", fake_db.fetch_val)
    monkeypatch.setattr(settings.scan, "scan_interval_seconds", 0)

    obsidios._shutdown.clear()
    asyncio.run(obsidios.scan_cycle(asyncio.Event()))

    assert any(
        level == "warning" and "incomplete" in message.lower()
        for level, message in sink.events
    )
    assert not any(
        level == "success" and "scan cycle complete" in message.lower()
        for level, message in sink.events
    )


def test_auto_prune_ages_scans_that_never_finished(monkeypatch):
    """Cancelled/failed scans have no finished_at and were retained forever.

    A crashed RUNNING row is included: ageing it by started_at clears the
    `is_scanning` lock instead of blocking every future scan trigger.
    """
    from iris import (
        cve_mapper,
        exploit_validator,
        graph_builder,
        nuclei_scanner,
        osint_scanner,
        wired_scanner,
    )
    from oracle import claude_client, tagnn
    from phantom import path_finder

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY, scan_type TEXT, target TEXT,
            started_at REAL, finished_at REAL, hosts_found INTEGER DEFAULT 0,
            ports_found INTEGER DEFAULT 0, cves_found INTEGER DEFAULT 0,
            status TEXT, error TEXT);
        CREATE TABLE scan_diffs (
            id INTEGER PRIMARY KEY, scan_id INTEGER, diff_type TEXT, detail TEXT,
            severity TEXT DEFAULT 'INFO', created_at REAL DEFAULT 0);
        CREATE TABLE behavioral_events (id INTEGER PRIMARY KEY, ts REAL);
        CREATE TABLE anomalies (
            id INTEGER PRIMARY KEY, acknowledged INTEGER DEFAULT 0,
            detected_at REAL);
        CREATE TABLE system_settings (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE hosts (id INTEGER PRIMARY KEY, is_active INTEGER);
        CREATE TABLE ports (id INTEGER PRIMARY KEY);
        CREATE TABLE cves (id INTEGER PRIMARY KEY);
    """)
    now = time.time()
    old = now - 40 * 86400
    conn.executemany(
        "INSERT INTO scans (id, scan_type, target, started_at, finished_at, status) "
        "VALUES (?, 'FULL', '10.0.0.0/24', ?, ?, ?)",
        [
            (1, old, old + 60, 'DONE'),
            (2, old, None, 'CANCELLED'),
            (3, old, None, 'FAILED'),
            (4, old, None, 'RUNNING'),
            (5, now, None, 'RUNNING'),
        ],
    )
    conn.executemany(
        "INSERT INTO scan_diffs (scan_id, diff_type, detail) VALUES (?, 'NEW_HOST', 'x')",
        [(1,), (2,), (3,), (4,), (5,)],
    )
    conn.executemany(
        "INSERT INTO system_settings (key, value) VALUES (?, ?)",
        [('retention_days', '30'), ('scanner_enabled', '1'),
         ('manual_trigger', '1')],
    )
    conn.commit()

    class Adapter:
        async def fetch_val(self, sql, params=(), default=None):
            row = conn.execute(sql, params).fetchone()
            return row[0] if row else default

        async def execute(self, sql, params=()):
            conn.execute(sql, params)
            conn.commit()

    async def fake_scan():
        obsidios._shutdown.set()
        return ScanResult(target="10.0.0.0/24")

    async def noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(wired_scanner, "run_scan", fake_scan)
    monkeypatch.setattr(cve_mapper, "map_cves_for_scan", _empty_cve_map)
    monkeypatch.setattr(cve_mapper, "persist_cves", _noop)
    monkeypatch.setattr(exploit_validator, "validate_exploits", _exploit_stats)
    monkeypatch.setattr(osint_scanner, "run_osint_scan", _noop_args)
    monkeypatch.setattr(nuclei_scanner, "run_nuclei_scan", _noop_args)
    monkeypatch.setattr(wired_scanner, "run_wireless_scan", _noop)
    monkeypatch.setattr(graph_builder, "rebuild_graph", _graph)
    monkeypatch.setattr(tagnn, "run_tagnn_prediction", _noop)
    monkeypatch.setattr(path_finder, "run_simulation", _simulation)
    monkeypatch.setattr(claude_client, "generate_report", _report)
    monkeypatch.setattr("forge.rule_generator.run_forge", _forge_noop)
    monkeypatch.setattr(obsidios, "_notify", noop)
    monkeypatch.setattr(obsidios, "scan_counter", 0)
    monkeypatch.setattr("chronicle.db.execute", Adapter().execute)
    monkeypatch.setattr("chronicle.db.fetch_val", Adapter().fetch_val)
    monkeypatch.setattr(settings.scan, "scan_interval_seconds", 0)

    obsidios._shutdown.clear()
    asyncio.run(obsidios.scan_cycle(asyncio.Event()))

    remaining = [r["id"] for r in conn.execute("SELECT id FROM scans ORDER BY id")]
    assert remaining == [5]
    diffs = [r["scan_id"] for r in conn.execute(
        "SELECT scan_id FROM scan_diffs ORDER BY scan_id")]
    assert diffs == [5]
    conn.close()


def test_status_counts_unacknowledged_alerts(monkeypatch):
    """The HUD hard-coded zero, hiding every SENTINEL alert from operators."""
    seen = []

    async def fake_init():
        return None

    async def fake_close():
        return None

    async def fake_fetch_val(sql, *_args, **_kwargs):
        if "sentinel_alerts" in sql:
            seen.append(sql)
            return 7
        return 0

    async def fake_fetch_all(*_args, **_kwargs):
        return []

    from oracle import posture_score

    async def fake_posture():
        return {"overall_score": 80}

    responses = []

    def capture(*args, **_kwargs):
        responses.append(args)

    monkeypatch.setattr(obsidios.db, "init", fake_init)
    monkeypatch.setattr(obsidios.db, "close", fake_close)
    monkeypatch.setattr(obsidios.db, "fetch_val", fake_fetch_val)
    monkeypatch.setattr(obsidios.db, "fetch_all", fake_fetch_all)
    monkeypatch.setattr(posture_score, "calculate_posture_score", fake_posture)
    monkeypatch.setattr(obsidios, "console", _Console(capture))

    result = CliRunner().invoke(obsidios.cli, ["status"])

    assert result.exit_code == 0, result.output
    assert seen, "status must query sentinel_alerts"
    assert any("7" in str(a) for args in responses for a in args)


class _Console:
    """Minimal console that records instead of rendering."""

    def __init__(self, sink):
        self.sink = sink

    def print(self, *args, **kwargs):
        self.sink(*args)

    def input(self, *_args, **_kwargs):
        raise KeyboardInterrupt
