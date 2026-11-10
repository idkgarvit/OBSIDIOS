"""Live scan display regressions.

The display is pure UX, but it runs inside the scan pipeline: a crash there
aborts a real scan, and unbounded rendering makes a /16 sweep unusable.
"""
import io

import networkx as nx
from rich.console import Console

from iris import live_display


def _render(display, width=200) -> str:
    buf = io.StringIO()
    Console(file=buf, width=width, force_terminal=False).print(
        display._build_layout()
    )
    return buf.getvalue()


class TestLayout:
    def test_host_rows_are_rendered(self):
        display = live_display.ScanDisplay("10.0.0.0/24")
        display.finish_arp(["10.0.0.5", "10.0.0.6"])
        out = _render(display)
        assert "10.0.0.5" in out
        assert "10.0.0.6" in out

    def test_rich_markup_from_host_data_is_escaped(self):
        display = live_display.ScanDisplay("10.0.0.0/24")
        display.finish_arp(["10.0.0.5"])
        display.host_done("10.0.0.5", 3, "[bold red]evil[/]")
        out = _render(display)
        assert "[bold red]evil[/]" in out

    def test_host_table_is_capped(self):
        display = live_display.ScanDisplay("10.0.0.0/16")
        display.finish_arp([f"10.0.{i // 250}.{i % 250 + 1}" for i in range(100)])
        out = _render(display)
        assert "... and 60 more" in out
        # The oldest entries are dropped from the view, not from the stats.
        assert display.stats["hosts"] == 100
        assert len(display.host_status) == 100

    def test_stats_bar_reflects_counters(self):
        display = live_display.ScanDisplay("10.0.0.0/24")
        display.finish_arp(["10.0.0.5"])
        display.finish_cve(7)
        display.finish_phantom(2)
        display.finish_forge(9)
        out = _render(display)
        assert "7" in out and "2" in out and "9" in out


class TestPhaseMethods:
    def test_phase_methods_are_safe_without_a_live_display(self):
        display = live_display.ScanDisplay("10.0.0.0/24")
        display.start_arp("10.0.0.0/24")
        display.finish_arp([])
        display.start_nmap(0)
        display.host_scanning("10.0.0.5")   # unknown host must not KeyError
        display.host_done("10.0.0.5", 0, None)
        display.finish_cve(0)               # no task started yet
        display.update_host_cves("10.0.0.5", 1)
        display.finish_graph(1, 0)          # no task started yet
        display.finish_phantom(0)
        display.finish_forge(0)

    def test_finish_cve_uses_the_task_total(self):
        display = live_display.ScanDisplay("10.0.0.0/24")
        display.start_cve_lookup(5)
        display.finish_cve(0)
        assert display.progress.tasks[display._task_cve].completed == 5

    def test_start_arp_escapes_markup(self):
        display = live_display.ScanDisplay("[red]10.0.0.0/24[/]")
        display.start_arp("[red]10.0.0.0/24[/]")
        assert "\\[red]" in display.progress.tasks[display._task_arp].description


class TestContextManager:
    def test_enter_and_exit_do_not_raise_off_terminal(self, monkeypatch):
        buf = io.StringIO()
        monkeypatch.setattr(
            live_display, "console", Console(file=buf, width=120, force_terminal=False)
        )
        display = live_display.ScanDisplay("10.0.0.0/24")
        with display as active:
            assert active is display
            display.start_arp("10.0.0.0/24")
            display.finish_arp(["10.0.0.5"])
        assert display._live is not None

    def test_final_summary_reports_counters(self, monkeypatch):
        buf = io.StringIO()
        monkeypatch.setattr(
            live_display, "console", Console(file=buf, width=120, force_terminal=False)
        )
        display = live_display.ScanDisplay("10.0.0.0/24")
        display.stats.update(hosts=3, ports=11, cves=4, paths=2, rules=7)
        display.print_final_summary()
        out = buf.getvalue()
        assert "Hosts discovered" in out and "3" in out
        assert "IDS rules forged" in out and "7" in out


class TestPipelineWiring:
    def test_scan_pipeline_drives_every_phase(self, monkeypatch):
        """The pipeline used to stop updating the display after nmap start."""
        import obsidios
        from iris import cve_mapper, graph_builder, nuclei_scanner, osint_scanner, wired_scanner

        calls = []

        class FakeDisplay:
            def __getattr__(self, name):
                def record(*args, **kwargs):
                    calls.append(name)
                return record

        async def fake_discover(_target):
            return [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "h5"}]

        async def fake_scan(_hosts):
            return [{
                "ip": "10.0.0.5",
                "hostname": "h5",
                "os": [{"name": "Linux"}],
                "ports": [{"port": 443, "protocol": "tcp", "state": "open",
                           "service": "https"}],
            }]

        async def fake_upsert_hosts(_hosts, _data):
            return {"10.0.0.5": 1}

        async def fake_upsert_ports(_data, _map, _started=None):
            return None

        async def fake_map_cves(_scan):
            return {}, {}

        async def fake_persist(*_args):
            return None

        async def fake_noop(_ips):
            return None

        async def fake_graph():
            g = nx.DiGraph()
            g.add_node(1)
            g.add_node(2)
            g.add_edge(1, 2)
            return g

        monkeypatch.setattr(wired_scanner, "discover_hosts", fake_discover)
        monkeypatch.setattr(wired_scanner, "scan_hosts_concurrent", fake_scan)
        monkeypatch.setattr(wired_scanner, "_upsert_hosts", fake_upsert_hosts)
        monkeypatch.setattr(wired_scanner, "_upsert_ports", fake_upsert_ports)
        monkeypatch.setattr(cve_mapper, "map_cves_for_scan", fake_map_cves)
        monkeypatch.setattr(cve_mapper, "persist_cves", fake_persist)
        monkeypatch.setattr(osint_scanner, "run_osint_scan", fake_noop)
        monkeypatch.setattr(nuclei_scanner, "run_nuclei_scan", fake_noop)
        monkeypatch.setattr(graph_builder, "rebuild_graph", fake_graph)

        from dashboard.app import run_async

        run_async(obsidios._scan_pipeline("10.0.0.0/24", FakeDisplay()))

        for phase in (
            "start_arp", "finish_arp", "start_nmap", "host_scanning",
            "host_done", "start_cve_lookup", "finish_cve", "start_graph",
            "finish_graph",
        ):
            assert phase in calls, f"{phase} was never called"

    def test_no_hosts_short_circuits(self, monkeypatch):
        import obsidios
        from iris import wired_scanner

        names = []

        class FakeDisplay:
            def __getattr__(self, name):
                def record(*args, **kwargs):
                    names.append(name)
                return record

        async def no_hosts(_target):
            return []

        monkeypatch.setattr(wired_scanner, "discover_hosts", no_hosts)
        result = __import__("asyncio").run(
            obsidios._scan_pipeline("10.0.0.0/24", FakeDisplay())
        )
        assert result == (None, None, 0)
        assert names == ["start_arp", "finish_arp"]
