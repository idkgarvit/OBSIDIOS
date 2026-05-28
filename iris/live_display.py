"""
iris/live_display.py
─────────────────────
Live terminal display for IRIS scans.
Shows real-time progress so users know exactly what's happening.
Uses Rich's Live display — updates every 0.5 seconds.
"""
from __future__ import annotations

import asyncio
import time
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

console = Console()


class ScanDisplay:
    """
    Live terminal display for the full OBSIDIOS scan pipeline.
    Shows progress for: ARP sweep, nmap scans, CVE lookup, graph build.
    """

    def __init__(self, target: str):
        self.target    = target
        self.start_time = time.time()

        # Progress bars
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description:<35}[/]"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("[dim]{task.fields[status]}[/]"),
            TimeElapsedColumn(),
            console=console,
        )

        # Host status tracking
        self.host_status: dict[str, dict] = {}

        # Stats
        self.stats = {
            "hosts":    0,
            "ports":    0,
            "cves":     0,
            "paths":    0,
            "rules":    0,
        }

        # Task IDs
        self._task_arp:   TaskID | None = None
        self._task_nmap:  TaskID | None = None
        self._task_cve:   TaskID | None = None
        self._task_graph: TaskID | None = None
        self._task_phantom: TaskID | None = None
        self._task_forge: TaskID | None = None

        self._live: Live | None = None

    # ── Layout builder ─────────────────────────────────────────────────────

    def _build_layout(self) -> Table:
        """Build the full display layout as a Rich Table."""
        root = Table.grid(expand=True)
        root.add_column()

        # Header
        header = Text()
        elapsed = int(time.time() - self.start_time)
        mins, secs = divmod(elapsed, 60)
        header.append("⚡ OBSIDIOS ", style="bold red")
        header.append("— Autonomous Network Security Platform", style="dim")
        header.append(f"   [{mins:02d}:{secs:02d}]", style="bold yellow")
        root.add_row(Panel(header, border_style="red", padding=(0, 1)))

        # Progress bars
        root.add_row(Panel(
            self.progress,
            title="[bold]Pipeline Progress[/]",
            border_style="blue",
            padding=(0, 1),
        ))

        # Host status table
        if self.host_status:
            host_table = Table(
                show_header=True,
                header_style="bold dim",
                border_style="dim",
                expand=True,
                padding=(0, 1),
            )
            host_table.add_column("Host IP",     style="cyan",   width=18)
            host_table.add_column("Status",      style="white",  width=16)
            host_table.add_column("Ports",       style="yellow", width=8,  justify="right")
            host_table.add_column("CVEs",        style="red",    width=8,  justify="right")
            host_table.add_column("OS",          style="dim",    width=30)

            for ip, info in self.host_status.items():
                status = info.get("status", "pending")
                if status == "scanning":
                    status_str = "[yellow]⠸ scanning...[/]"
                elif status == "done":
                    status_str = "[green]✅ done[/]"
                elif status == "cve_lookup":
                    status_str = "[blue]🔍 CVE lookup[/]"
                elif status == "complete":
                    status_str = "[bold green]✅ complete[/]"
                else:
                    status_str = "[dim]pending[/]"

                host_table.add_row(
                    ip,
                    status_str,
                    str(info.get("ports", "-")),
                    str(info.get("cves", "-")),
                    (info.get("os") or "unknown")[:30],
                )

            root.add_row(Panel(
                host_table,
                title="[bold]Host Discovery[/]",
                border_style="cyan",
                padding=(0, 1),
            ))

        # Stats bar
        stats_table = Table.grid(expand=True, padding=(0, 3))
        stats_table.add_column(justify="center")
        stats_table.add_column(justify="center")
        stats_table.add_column(justify="center")
        stats_table.add_column(justify="center")
        stats_table.add_column(justify="center")

        def stat(val: int, label: str, color: str) -> Text:
            t = Text()
            t.append(f"{val}\n", style=f"bold {color}")
            t.append(label, style="dim")
            return t

        stats_table.add_row(
            stat(self.stats["hosts"], "HOSTS",      "cyan"),
            stat(self.stats["ports"], "OPEN PORTS", "yellow"),
            stat(self.stats["cves"],  "CVEs",       "red"),
            stat(self.stats["paths"], "KILL CHAINS","magenta"),
            stat(self.stats["rules"], "IDS RULES",  "green"),
        )

        root.add_row(Panel(
            stats_table,
            title="[bold]Live Statistics[/]",
            border_style="yellow",
            padding=(0, 1),
        ))

        return root

    # ── Context manager ────────────────────────────────────────────────────

    def __enter__(self) -> "ScanDisplay":
        self._live = Live(
            self._build_layout(),
            console=console,
            refresh_per_second=2,
            screen=True,
        )
        self._live.__enter__()
        return self

    def __exit__(self, *args) -> None:
        if self._live:
            self._live.__exit__(*args)

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._build_layout())

    # ── Phase: ARP sweep ───────────────────────────────────────────────────

    def start_arp(self, network: str) -> None:
        self._task_arp = self.progress.add_task(
            f"ARP Sweep  {network}",
            total=1,
            status="scanning layer-2...",
        )
        self._refresh()

    def finish_arp(self, hosts: list[str]) -> None:
        if self._task_arp is not None:
            self.progress.update(
                self._task_arp,
                completed=1,
                status=f"[green]{len(hosts)} hosts found[/]",
            )
        self.stats["hosts"] = len(hosts)
        for ip in hosts:
            self.host_status[ip] = {"status": "pending", "ports": 0, "cves": 0, "os": None}
        self._refresh()

    # ── Phase: nmap service scan ───────────────────────────────────────────

    def start_nmap(self, total_hosts: int) -> None:
        self._task_nmap = self.progress.add_task(
            "Service Scan",
            total=total_hosts,
            status="fingerprinting services...",
        )
        self._refresh()

    def host_scanning(self, ip: str) -> None:
        if ip in self.host_status:
            self.host_status[ip]["status"] = "scanning"
        self._refresh()

    def host_done(self, ip: str, ports: int, os_name: str | None) -> None:
        if ip in self.host_status:
            self.host_status[ip]["status"] = "done"
            self.host_status[ip]["ports"]  = ports
            self.host_status[ip]["os"]     = os_name
        self.stats["ports"] += ports
        if self._task_nmap is not None:
            self.progress.advance(self._task_nmap)
            completed = sum(
                1 for h in self.host_status.values()
                if h["status"] in ("done", "cve_lookup", "complete")
            )
            self.progress.update(
                self._task_nmap,
                status=f"{completed}/{len(self.host_status)} done",
            )
        self._refresh()

    # ── Phase: CVE lookup ─────────────────────────────────────────────────

    def start_cve_lookup(self, total: int) -> None:
        self._task_cve = self.progress.add_task(
            "CVE Lookup  (NVD API)",
            total=total,
            status="querying NVD...",
        )
        self._refresh()

    def cve_progress(self, done: int, total: int, ip: str | None = None) -> None:
        if self._task_cve is not None:
            self.progress.update(
                self._task_cve,
                completed=done,
                status=f"{done}/{total} services",
            )
        if ip and ip in self.host_status:
            self.host_status[ip]["status"] = "cve_lookup"
        self._refresh()

    def finish_cve(self, total_cves: int) -> None:
        if self._task_cve is not None:
            self.progress.update(
                self._task_cve,
                completed=self.progress.tasks[self._task_cve].total,
                status=f"[green]{total_cves} CVEs mapped[/]",
            )
        self.stats["cves"] = total_cves
        for ip in self.host_status:
            if self.host_status[ip]["status"] == "cve_lookup":
                self.host_status[ip]["status"] = "complete"
        self._refresh()

    def update_host_cves(self, ip: str, cve_count: int) -> None:
        if ip in self.host_status:
            self.host_status[ip]["cves"] = cve_count
        self._refresh()

    # ── Phase: Graph + PHANTOM ────────────────────────────────────────────

    def start_graph(self) -> None:
        self._task_graph = self.progress.add_task(
            "Building Attack Graph",
            total=1,
            status="computing edges...",
        )
        self._refresh()

    def finish_graph(self, nodes: int, edges: int) -> None:
        if self._task_graph is not None:
            self.progress.update(
                self._task_graph,
                completed=1,
                status=f"[green]{nodes} nodes, {edges} edges[/]",
            )
        self._refresh()

    def start_phantom(self) -> None:
        self._task_phantom = self.progress.add_task(
            "PHANTOM Kill Chain Sim",
            total=1,
            status="simulating...",
        )
        self._refresh()

    def finish_phantom(self, paths: int) -> None:
        if self._task_phantom is not None:
            self.progress.update(
                self._task_phantom,
                completed=1,
                status=f"[red]{paths} kill chains found[/]",
            )
        self.stats["paths"] = paths
        self._refresh()

    def start_forge(self) -> None:
        self._task_forge = self.progress.add_task(
            "FORGE Rule Generation",
            total=1,
            status="writing rules...",
        )
        self._refresh()

    def finish_forge(self, rules: int) -> None:
        if self._task_forge is not None:
            self.progress.update(
                self._task_forge,
                completed=1,
                status=f"[yellow]{rules} Suricata rules forged[/]",
            )
        self.stats["rules"] = rules
        self._refresh()

    # ── Final summary ──────────────────────────────────────────────────────

    def print_final_summary(self) -> None:
        elapsed = int(time.time() - self.start_time)
        mins, secs = divmod(elapsed, 60)

        console.print()
        console.print(Panel(
            f"[bold green]✅ OBSIDIOS SCAN COMPLETE[/]\n\n"
            f"  [cyan]Hosts discovered :[/] {self.stats['hosts']}\n"
            f"  [yellow]Open ports       :[/] {self.stats['ports']}\n"
            f"  [red]CVEs mapped      :[/] {self.stats['cves']}\n"
            f"  [magenta]Kill chains      :[/] {self.stats['paths']}\n"
            f"  [green]IDS rules forged :[/] {self.stats['rules']}\n\n"
            f"  [dim]Total time: {mins:02d}:{secs:02d}[/]",
            title="[bold red]OBSIDIOS[/]",
            border_style="green",
            padding=(1, 2),
        ))
