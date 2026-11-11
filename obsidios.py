"""obsidios.py — Main orchestrator + CLI"""
from __future__ import annotations

import asyncio
import json
import queue
import select
import signal
import sqlite3
import subprocess
import sys
import threading
import time

import click
import uvloop
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from loguru import logger
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.markup import MarkupError
from rich.markup import escape as _escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from chronicle import db
from config import settings

console = Console()


def _safe(value) -> str:
    """Escape untrusted text before interpolating it into Rich markup.

    Wi-Fi SSIDs, operator arguments and scan findings may contain '[' / ']';
    unescaped they raise MarkupError and abort the command (or the shell).
    """
    return _escape("" if value is None else str(value))


def _markup_safe(text: str) -> str:
    """Return text Rich can render, escaping it when its markup is malformed.

    The War Room feed mixes internally styled lines with untrusted command
    output. A stray closing tag from a subprocess used to raise MarkupError
    inside the render loop and kill the TUI; malformed lines are shown
    literally instead.
    """
    try:
        Text.from_markup(text)
    except MarkupError:
        return _escape(text)
    return text

BANNER = """
 █████╗  ██████╗  ██████╗  ██╗ ██████╗  ██╗  █████╗  ██████╗
██╔══██╗ ██╔══██╗ ██╔════╝ ██║ ██╔══██╗ ██║ ██╔══██╗ ██╔════╝
██║  ██║ ██████╔╝ ██████╗  ██║ ██║  ██║ ██║ ██║  ██║ ██████╗
██║  ██║ ██╔══██╗ ╚═══██╗ ██║ ██║  ██║ ██║ ██║  ██║ ╚═══██╗
╚██████╔╝ ██████╔╝ ██████╔╝ ██║ ██████╔╝ ██║ ╚██████╔╝ ██████╔╝
 ╚═════╝  ╚═════╝  ╚═════╝  ╚═╝ ╚═════╝  ╚═╝  ╚═════╝  ╚═════╝
"""

_shutdown = asyncio.Event()
def _handle_signal(sig): _shutdown.set()

scan_counter = 0


async def _notify(title: str, message: str = "", color: int | str = "info") -> None:
    """Best-effort operator notification.

    The scanner must keep working when Discord/webhooks are down: a notification
    failure used to abort the whole scan cycle before any scanning happened.
    """
    try:
        from alerts.notifier import send_alert
        await send_alert(title=title, message=message, color=color,
                         footer="OBSIDIOS v2.0")
    except Exception as exc:
        logger.warning(f"[OBSIDIOS] Notification failed ({title}): {exc}")


_MAX_TARGET_LEN = 64


def normalize_target_cidr(raw: str) -> tuple[str | None, str | None]:
    """Validate and canonicalise an operator-supplied scan target.

    The dashboard has always refused 0.0.0.0/0, overly broad and public ranges.
    The CLI used to write whatever it was given straight into
    `system_settings.target_network`, where IRIS then refused to scan it — the
    operator saw "Target Updated" while every scan silently did nothing.
    """
    import ipaddress

    text = (raw or "").strip()
    if not text or len(text) > _MAX_TARGET_LEN:
        return None, f"target must be a CIDR or IP (max {_MAX_TARGET_LEN} chars)"
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        return None, f"invalid CIDR: {exc}"
    from config.settings import validate_target_cidr
    ok, reason = validate_target_cidr(str(net))
    if not ok:
        return None, reason
    return str(net), None


def normalize_scan_profile(raw: str) -> str | None:
    """Return the canonical profile name, or None when it is not configured."""
    from config.settings import scan as scan_cfg
    text = (raw or "").strip().upper()
    return text if text in scan_cfg.SCAN_PROFILES else None


async def _audit_cli(
    action: str,
    *,
    target: str | None = None,
    detail: str | None = None,
    outcome: str = "success",
) -> None:
    """Best-effort append to the operator audit trail from the local CLI."""
    import os

    try:
        actor = os.environ.get("USER") or "cli"
        await db.execute(
            "INSERT INTO audit_log (actor, role, action, target, detail, ip, outcome) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                actor[:128],
                "operator",
                str(action)[:64],
                None if target is None else str(target)[:256],
                None if detail is None else str(detail)[:2000],
                "local",
                str(outcome)[:16],
            ),
        )
    except Exception as exc:
        logger.warning(f"[CLI] Audit write failed ({action}): {exc}")


_scan_busy = False


async def scan_cycle() -> None:
    global scan_counter, _scan_busy
    from forge.rule_generator import run_forge
    from iris.cve_mapper import map_cves_for_scan, persist_cves
    from iris.graph_builder import rebuild_graph
    from iris.nuclei_scanner import run_nuclei_scan
    from iris.osint_scanner import run_osint_scan
    from iris.wired_scanner import run_scan, run_wireless_scan
    from oracle.tagnn import run_tagnn_prediction
    from phantom.path_finder import run_simulation

    while not _shutdown.is_set():

        from chronicle.db import execute, fetch_val

        try:
            await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','Starting scan cycle...')")
            logger.info("[OBSIDIOS] Scan cycle starting")
            
            # A manual trigger from the dashboard runs even when paused.
            manual = await fetch_val("SELECT value FROM system_settings WHERE key='manual_trigger'", default="0")

            # Check for Manual Override
            enabled = await fetch_val("SELECT value FROM system_settings WHERE key='scanner_enabled'", default="0")
            if enabled == "0" and manual != "1":
                logger.warning("[SCANNER] Manual Override: PAUSED. Waiting for command...")
                already = await fetch_val("SELECT value FROM system_settings WHERE key='_paused_alert_sent'", default="0")
                if already != "1":
                    await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('_paused_alert_sent','1')")
                    await _notify(
                        "⏸ **Scanner Paused**",
                        "Manual override is active — all scanning suspended.\n"
                        "Waiting for start command from dashboard.",
                        color="medium",
                    )
                await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','Paused')")
                await asyncio.sleep(10)
                continue
            else:
                await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('_paused_alert_sent','0')")

            # Scheduled and manual cycles share the daemon. Running two nmap
            # sweeps at once duplicated load, DB writes and alerts; keep the
            # trigger pending until the in-flight cycle finishes.
            if _scan_busy:
                logger.warning("[SCANNER] Previous scan still running — waiting before starting another")
                await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','Waiting for previous scan...')")
                await asyncio.sleep(10)
                continue

            if manual == "1":
                logger.info("[OBSIDIOS] Manual trigger detected — running immediate scan")
                await execute("UPDATE system_settings SET value='0' WHERE key='manual_trigger'")
                await _notify(
                    "🔁 **Manual Scan Triggered**",
                    "Immediate scan cycle initiated from dashboard",
                    color="info",
                )

            last_scan_id = await fetch_val(
                "SELECT id FROM scans WHERE status='DONE' ORDER BY finished_at DESC LIMIT 1"
            )

            _scan_busy = True
            try:
                scan_result = await run_scan()
            finally:
                _scan_busy = False

            if any("cancelled" in str(error).lower() for error in scan_result.errors):
                logger.warning("[OBSIDIOS] Scan cancelled by operator — skipping post-processing")
                await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','')")
                await asyncio.sleep(2)
                continue

            await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','CVE mapping...')")

            mapped_cves = 0
            if scan_result.hosts:
                cve_map, aff_map = await map_cves_for_scan(scan_result)
                await persist_cves(cve_map, scan_result, aff_map)
                # Count the mappings this cycle actually produced. The old
                # update replaced this with the global `cves` cache size, so
                # scan history grew every time an unrelated CVE was fetched.
                mapped_cves = sum(len(v) for v in cve_map.values())

            # Cross-reference CVEs with known exploits (Exploit-DB / MSF)
            from iris.exploit_validator import validate_exploits
            exploit_stats = await validate_exploits()
            logger.success(f"[EXPLOIT] {exploit_stats['validated']} CVEs matched known exploits ({exploit_stats['msf_count']} MSF, {exploit_stats['edb_count']} EDB)")
            await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','OSINT + Nuclei + Wireless...')")
            ips = [h.ip for h in scan_result.hosts]
            await run_osint_scan(ips)
            await run_nuclei_scan(ips)
            await run_wireless_scan()

            await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','Building attack graph...')")
            await rebuild_graph()

            # Autonomous Red-Teaming
            await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','Attack path simulation (PHANTOM)...')")
            logger.info("[OBSIDIOS] Starting autonomous attack simulation...")
            simulation = await run_simulation(max_paths=10)
            
            # Topological Attack Graph Neural Network (TAGNN)
            logger.info("[OBSIDIOS] Running TAGNN Zero-Day Prediction...")
            await run_tagnn_prediction()
            # Always run FORGE: an empty simulation must still retire stale
            # rules and rewrite the sensor ruleset, otherwise detections for
            # paths that no longer exist stay loaded indefinitely.
            await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','Generating Suricata rules (FORGE)...')")
            await run_forge(simulation)
            if simulation.total_paths > 0:
                logger.success(f"[OBSIDIOS] Autonomous red-team complete: {simulation.total_paths} paths found")
                await _notify(
                    "🕸 **Attack Paths Discovered**",
                    f"PHANTOM simulated **{simulation.total_paths}** kill chains across your network",
                    color="info",
                )
            
            scan_counter += 1
            try:
                from alerts.notifier import send_alert
                from oracle.claude_client import generate_report
                report_path = await generate_report()
                await send_alert(
                    title="📊 Automated Pentest Report Ready",
                    message=f"Scan cycle #{scan_counter} complete. Fresh intelligence report generated.\nPath: {report_path}",
                    color=4244223
                )
            except Exception as e:
                logger.error(f"[OBSIDIOS] Auto-report failed: {e}")

            # VulnDrift — compare this scan against previous
            if scan_result.scan_id and last_scan_id:
                from iris.wired_scanner import compute_scan_diff
                diffs = await compute_scan_diff(scan_result.scan_id, last_scan_id)
                if diffs:
                    logger.warning(f"[VULNDRIFT] {len(diffs)} changes detected since last scan!")
                    new_h = sum(1 for d in diffs if d['type'] == 'NEW_HOST')
                    gone_h = sum(1 for d in diffs if d['type'] == 'GONE_HOST')
                    parts = []
                    if new_h: parts.append(f"🟢 **{new_h}** new host(s)")
                    if gone_h: parts.append(f"🔴 **{gone_h}** host(s) went offline")
                    await _notify(
                        "📊 **VulnDrift: Network Changed**",
                        " — ".join(parts),
                        color="medium",
                    )

            # Record what this cycle mapped. Host and port counts were already
            # written by run_scan() from the sweep itself; replacing them with
            # global table totals turned history into a running total of every
            # host ever seen.
            from chronicle.db import execute
            await execute(
                "UPDATE scans SET cves_found=? WHERE id=?",
                (mapped_cves, scan_result.scan_id)
            )
            if scan_result.errors:
                logger.warning(
                    "[OBSIDIOS] Scan cycle incomplete: "
                    + "; ".join(str(error) for error in scan_result.errors)
                )
            else:
                logger.success("[OBSIDIOS] Scan cycle complete")
            from alerts.notifier import flush_alerts
            await flush_alerts()
            # Auto-prune old data based on retention setting
            try:
                days_str = await fetch_val("SELECT value FROM system_settings WHERE key='retention_days'", default="30")
                days = int(days_str)
                # Match the dashboard's 1-3650 validation: a 730-day retention
                # used to be silently ignored here, so auto-prune never ran.
                if 1 <= days <= 3650:
                    cutoff = time.time() - (days * 86400)
                    # Cancelled/failed scans have no finished_at; age them by
                    # started_at instead of keeping them forever.
                    old_scan_eq = "COALESCE(finished_at, started_at) < ?"
                    await execute(
                        f"DELETE FROM scan_diffs WHERE scan_id IN "
                        f"(SELECT id FROM scans WHERE {old_scan_eq})", (cutoff,))  # nosec B608 - static fragment
                    await execute(
                        f"DELETE FROM scans WHERE {old_scan_eq}", (cutoff,))  # nosec B608 - static fragment
                    await execute("DELETE FROM behavioral_events WHERE ts < ?", (cutoff,))
                    await execute("DELETE FROM anomalies WHERE acknowledged = 1 AND detected_at < ?", (cutoff,))
            except Exception:
                pass
        except Exception as exc:
            logger.exception(f"[OBSIDIOS] Scan error: {exc}")
            # A dead notifier must not skip the scan_phase reset and idle poll.
            await _notify(
                "❌ **Scan Cycle Failed**",
                f"```{str(exc)[:500]}```",
                color="critical",
            )
        try:
            await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','')")
        except Exception:
            pass
        try:
            # Poll every 30s for manual_trigger instead of one long sleep
            interval = settings.scan.scan_interval_seconds
            poll_every = 30
            elapsed = 0
            while elapsed < interval:
                if _shutdown.is_set():
                    break
                manual = await fetch_val("SELECT value FROM system_settings WHERE key='manual_trigger'", default="0")
                if manual == "1":
                    logger.info("[OBSIDIOS] Manual trigger during idle — starting next cycle")
                    await execute("UPDATE system_settings SET value='0' WHERE key='manual_trigger'")
                    break
                await asyncio.sleep(min(poll_every, interval - elapsed))
                elapsed += poll_every
        except Exception:
            pass


async def _scheduled_scan_cycle() -> None:
    """Run one scheduled scan and log the outcome truthfully."""
    global _scan_busy

    from chronicle.db import fetch_val
    from iris.cve_mapper import map_cves_for_scan, persist_cves
    from iris.graph_builder import rebuild_graph
    from iris.wired_scanner import run_scan

    # The dashboard pause switch means "all scanning suspended": a cron job
    # must not keep sweeping the network behind the operator's back.
    enabled = await fetch_val(
        "SELECT value FROM system_settings WHERE key='scanner_enabled'",
        default="0")
    if enabled != "1":
        logger.info("[AUTOMATION] Scanner is paused — scheduled scan skipped")
        return
    if _scan_busy:
        logger.warning("[AUTOMATION] Another scan is running — scheduled scan skipped")
        return

    _scan_busy = True
    try:
        result = await run_scan()
        if result.hosts:
            cve_map, aff_map = await map_cves_for_scan(result)
            await persist_cves(cve_map, result, aff_map)
            await rebuild_graph()
        if result.errors:
            # An empty/refused sweep is not a completed scan cycle.
            logger.error(
                "[AUTOMATION] Scheduled scan incomplete: "
                + "; ".join(str(error) for error in result.errors)
            )
            return
        logger.success(
            f"[AUTOMATION] Scheduled scan complete: {len(result.hosts)} host(s)"
        )
    finally:
        _scan_busy = False


async def run_scheduler():
    """Background worker that manages scheduled scans from dashboard settings."""
    from chronicle.db import fetch_val

    scheduler = AsyncIOScheduler()
    scheduler.start()
    logger.info("[AUTOMATION] Scheduler engine online")
    
    current_job_id = None
    last_settings = None

    try:
        while not _shutdown.is_set():
            try:
                # Load settings from DB
                freq = await fetch_val("SELECT value FROM system_settings WHERE key='schedule_frequency'")
                time_val = await fetch_val("SELECT value FROM system_settings WHERE key='schedule_time'", default="02:00")
                enabled = await fetch_val("SELECT value FROM system_settings WHERE key='schedule_enabled'", default="0")
            
                settings_fingerprint = f"{freq}-{time_val}-{enabled}"
            
                if settings_fingerprint != last_settings:
                    last_settings = settings_fingerprint
                    if current_job_id:
                        try: scheduler.remove_job(current_job_id)
                        except: pass
                
                    if enabled == "1" and freq:
                        logger.info(f"[AUTOMATION] Configuring schedule: {freq} at {time_val}")
                        parts = time_val.split(":") if isinstance(time_val, str) else []
                        valid_time = (
                            len(parts) == 2 and all(p.isdigit() for p in parts)
                            and 0 <= int(parts[0]) <= 23 and 0 <= int(parts[1]) <= 59
                        )
                        if not valid_time:
                            # A malformed schedule_time must not kill the scheduler
                            # loop or crash on an unbound `job`.
                            logger.error(
                                f"[AUTOMATION] Invalid schedule_time {time_val!r} — "
                                "expected HH:MM, no job scheduled"
                            )
                        else:
                            h, m = int(parts[0]), int(parts[1])

                            async def scheduled_task():
                                logger.warning("[AUTOMATION] Firing scheduled scan cycle")
                                await _scheduled_scan_cycle()

                            job = None
                            if freq == "hourly":
                                job = scheduler.add_job(scheduled_task, 'interval', hours=1)
                            elif freq == "daily":
                                job = scheduler.add_job(scheduled_task, 'cron', hour=h, minute=m)
                            elif freq == "weekly":
                                job = scheduler.add_job(scheduled_task, 'cron', day_of_week='mon', hour=h, minute=m)
                            elif freq == "monthly":
                                # The dashboard accepts "monthly" as a valid frequency;
                                # without this branch the UI showed a saved schedule
                                # that never produced a single scan.
                                job = scheduler.add_job(scheduled_task, 'cron', day=1, hour=h, minute=m)
                            else:
                                logger.warning(
                                    f"[AUTOMATION] Unknown schedule frequency {freq!r} — "
                                    "no job scheduled"
                                )

                            if job is not None:
                                current_job_id = job.id
                                logger.success(f"[AUTOMATION] Job {current_job_id} scheduled next run: {job.next_run_time}")
                    else:
                        logger.info("[AUTOMATION] No active schedule configured")
                    
            except Exception as e:
                logger.error(f"[AUTOMATION] Scheduler error: {e}")
            
            await asyncio.sleep(60) # Poll for settings changes every minute
    finally:
        scheduler.shutdown(wait=False)


async def pulse_loop():
    """High-frequency asset pulse to keep the 3D map updated."""
    from chronicle.db import fetch_val
    from iris.graph_builder import rebuild_graph
    from iris.heartbeat import HEARTBEAT_INTERVAL_SECONDS, heartbeat_once

    while not _shutdown.is_set():
        try:
            # Pause must silence the 15 s ARP/nmap sweep too, not just the
            # full scan cycle. Rebuilding the graph from existing DB rows is
            # local-only, so it is safe to keep the map live while paused.
            enabled = await fetch_val(
                "SELECT value FROM system_settings WHERE key='scanner_enabled'",
                default="0")
            if enabled == "1":
                target = await fetch_val(
                    "SELECT value FROM system_settings WHERE key='target_network'",
                    default="")
                if target:
                    await heartbeat_once(target)
            await rebuild_graph()
        except Exception as e:
            logger.error(f"[PULSE] Error: {e}")
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)

async def _run_scan_cycle_wrapped():
    """Wrap scan_cycle with health monitoring — restarts on crash."""
    while not _shutdown.is_set():
        try:
            await scan_cycle()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.exception(f"[OBSIDIOS] scan_cycle crashed: {e}")
            logger.info("[OBSIDIOS] Restarting scan_cycle in 5s...")
            await asyncio.sleep(5)

async def _run_all(
    target: str,
    interval: int,
    *,
    persist_target: bool = False,
    persist_profile: bool = False,
) -> None:
    global _scan_busy

    settings.scan.target_network        = target
    settings.scan.scan_interval_seconds = interval
    _scan_busy = False
    # Company-infra startup guards: fail closed in production, warn in dev
    try:
        from config.settings import security as _sec
        from config.settings import validate_prod_config, validate_target_cidr
        prod_errors = validate_prod_config()
        if prod_errors:
            for e in prod_errors:
                console.print(f"  [bold red]BLOCKED:[/] {_safe(e)}")
            logger.error(f"[OBSIDIOS] Production guardrails failed: {prod_errors}")
            raise SystemExit(2)
        ok, reason = validate_target_cidr(target)
        if not ok:
            console.print(f"  [bold red]BLOCKED target {_safe(target)}:[/] {_safe(reason)}")
            logger.error(f"[OBSIDIOS] Refusing target {target}: {reason}")
            raise SystemExit(2)
        if _sec.is_production:
            console.print("  [bold green]Guards:[/] production checks passed (secret, creds, target)")
    except SystemExit:
        raise
    except Exception as e:
        logger.warning(f"[OBSIDIOS] Guard check skipped: {e}")
    await db.init()
    tasks = []
    try:
        # Start paused — scanner only activates when user explicitly enables it
        await db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scanner_enabled', '0')")
        await db.execute("UPDATE scans SET status='CANCELLED' WHERE status='RUNNING'")
        # An explicit `run --target/--profile` is an operator decision: make
        # the daemon and dashboard agree instead of letting a stale DB value
        # silently override the CLI on the first scan.
        if persist_target:
            await db.execute(
                "INSERT OR REPLACE INTO system_settings (key, value) "
                "VALUES ('target_network', ?)", (target,))
        if persist_profile:
            await db.execute(
                "INSERT OR REPLACE INTO system_settings (key, value) "
                "VALUES ('scan_profile', ?)", (settings.scan.scan_profile,))
        # SENTINEL refuses to start when a configured rule file is absent.
        # Create the empty generated ruleset before the sensor can read it.
        try:
            from forge.rule_generator import ensure_rules_file
            ensure_rules_file()
        except Exception as exc:
            logger.warning(f"[OBSIDIOS] Could not prepare FORGE rules file: {exc}")
        console.print(f"  [bold]Target  :[/] [cyan]{_safe(target)}[/]")
        console.print(f"  [bold]Interval:[/] [cyan]{_safe(interval)}s[/]")
        console.print(f"  [bold]Profile :[/] [cyan]{_safe(settings.scan.scan_profile)}[/]")
        console.print("  [bold]Scanner :[/] [yellow]PAUSED (start from dashboard)[/]")
        console.print()
        if threading.current_thread() is threading.main_thread():
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, _handle_signal, sig)
        tasks = [
            asyncio.create_task(pulse_loop()),
            asyncio.create_task(_run_scan_cycle_wrapped(), name="iris-scan"),
            asyncio.create_task(run_scheduler(), name="automation-scheduler")
        ]
        logger.success("[OBSIDIOS] All systems online")
        await _shutdown.wait()
    finally:
        # Cancel whatever actually started; a setup failure must not leak tasks.
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await db.close()

async def _scan_pipeline(target: str, display=None):
    from chronicle.models import Host, Port, ScanResult
    from iris.cve_mapper import map_cves_for_scan, persist_cves
    from iris.graph_builder import rebuild_graph
    from iris.nuclei_scanner import run_nuclei_scan
    from iris.osint_scanner import run_osint_scan
    from iris.wired_scanner import (
        _first_os_entry,
        _mark_missing_hosts_offline,
        _scan_cancelled,
        _upsert_hosts,
        _upsert_ports,
        discover_hosts,
        scan_hosts_concurrent,
    )

    scan_started = time.time()
    # A CLI scan used to leave no row in `scans`. The dashboard kept showing
    # the previous scan and ORACLE refused to analyse fresh data because no
    # completed scan existed.
    scan_id = None
    hosts_found = ports_found = cves_found = 0
    try:
        scan_row = await db.execute_returning(
            "INSERT INTO scans (scan_type,target,started_at,status) VALUES (?,?,?,'RUNNING') RETURNING id",
            ("FULL", target, scan_started),
        )
        scan_id = scan_row["id"] if scan_row else None
        if display: display.start_arp(target)
        arp_hosts = await discover_hosts(target)
        if display: display.finish_arp([
            h["ip"] for h in arp_hosts
            if isinstance(h, dict) and isinstance(h.get("ip"), str)
        ])
        if not arp_hosts: return None, None, 0
        if await _scan_cancelled(scan_id):
            logger.warning(f"[IRIS] CLI scan {scan_id} cancelled before host scanning")
            return ScanResult(
                target=target, scan_id=scan_id,
                errors=["scan cancelled by operator"],
            ), None, 0
        if display:
            display.start_nmap(len(arp_hosts))
            for h in arp_hosts:
                if isinstance(h, dict) and isinstance(h.get("ip"), str):
                    display.host_scanning(h["ip"])
        scan_data = await scan_hosts_concurrent(arp_hosts)
        # The dashboard marked the row CANCELLED: never persist a partial
        # sweep as the authoritative state of the network.
        if await _scan_cancelled(scan_id):
            logger.warning(f"[IRIS] CLI scan {scan_id} cancelled — discarding results")
            return ScanResult(
                target=target, scan_id=scan_id,
                errors=["scan cancelled by operator"],
            ), None, 0
        if display:
            for data in scan_data:
                if not isinstance(data, dict) or not isinstance(data.get("ip"), str):
                    continue
                ports = data.get("ports")
                if not isinstance(ports, list):
                    ports = []
                os_first = _first_os_entry(data.get("os"))
                os_name = os_first.get("name") if os_first else None
                display.host_done(data["ip"], len(ports), os_name)
        host_id_map = await _upsert_hosts(arp_hosts, scan_data)
        # Passing the start time lets the scanner close ports that genuinely
        # disappeared; without it a CLI scan never reconciled stale open ports.
        await _upsert_ports(scan_data, host_id_map, scan_started)
        # A CLI scan is the only scan a user may run for hours; without this,
        # hosts that disappeared stayed is_active=1 until a daemon scan ran.
        seen_ips = [
            h["ip"] for h in arp_hosts
            if isinstance(h, dict) and isinstance(h.get("ip"), str) and h["ip"]
        ]
        if seen_ips:
            await _mark_missing_hosts_offline(seen_ips)
        scan_result = ScanResult(target=target, scan_id=scan_id)
        for data in scan_data:
            if not isinstance(data, dict):
                continue
            ip = data.get("ip")
            if not isinstance(ip, str):
                continue
            hid = host_id_map.get(ip)
            if hid is None:
                # Host row could not be written — Port validation would reject the
                # whole result and turn a partial scan into a failed one.
                logger.warning(f"[IRIS] No host id for {ip} — skipping result")
                continue
            os_first = _first_os_entry(data.get("os")) or {}
            scan_result.hosts.append(Host(
                id=hid, ip=ip, hostname=data.get("hostname"),
                os_name=os_first.get("name"),
            ))
            ports = data.get("ports")
            if not isinstance(ports, list):
                ports = []
            port_objs = []
            for p in ports:
                if not isinstance(p, dict):
                    logger.warning(f"[IRIS] Skipping malformed port for {ip}")
                    continue
                try:
                    port_objs.append(Port(
                        host_id=hid, port=p["port"],
                        protocol=p.get("protocol", "tcp"),
                        state=p.get("state", "open"),
                        service=p.get("service"), product=p.get("product"),
                        version=p.get("version"), extra_info=p.get("extra_info"),
                        cpe=p.get("cpe"),
                    ))
                except Exception as exc:
                    # One bad port must not discard the rest of the host's
                    # valid services.
                    logger.warning(f"[IRIS] Skipping malformed port for {ip}: {exc}")
            if port_objs:
                scan_result.ports[ip] = port_objs
        hosts_found = len({
            h["ip"] for h in arp_hosts
            if isinstance(h, dict) and isinstance(h.get("ip"), str) and h["ip"].strip()
        })
        ports_found = sum(len(v) for v in scan_result.ports.values())
        if display:
            display.start_cve_lookup(ports_found)
        cve_map, aff_map = await map_cves_for_scan(scan_result)
        await persist_cves(cve_map, scan_result, aff_map)
        total_cves = sum(len(v) for v in cve_map.values())
        cves_found = total_cves
        if display:
            display.finish_cve(total_cves)
        ips = [h.ip for h in scan_result.hosts]
        await run_osint_scan(ips)
        await run_nuclei_scan(ips)
        if display:
            display.start_graph()
        graph = await rebuild_graph()
        if display:
            display.finish_graph(graph.number_of_nodes(), graph.number_of_edges())
        return scan_result, scan_data, 0
    except Exception as exc:
        if scan_id:
            try:
                await db.execute(
                    "UPDATE scans SET status='FAILED', error=? WHERE id=?",
                    (str(exc)[:1000], scan_id),
                )
            except Exception as db_exc:
                logger.error(f"[IRIS] Could not mark CLI scan {scan_id} failed: {db_exc}")
        raise
    finally:
        if scan_id:
            try:
                # Mark the row DONE only if nobody cancelled it while it ran.
                # Without `status='DONE'` every CLI scan stayed RUNNING forever,
                # which blocked `trigger` and made ORACLE see no fresh scan.
                await db.execute(
                    "UPDATE scans SET finished_at=?, hosts_found=?, ports_found=?, "
                    "cves_found=?, status='DONE' WHERE id=? AND status='RUNNING'",
                    (time.time(), hosts_found, ports_found, cves_found, scan_id),
                )
            except Exception as exc:
                logger.error(f"[IRIS] Could not finalise CLI scan {scan_id}: {exc}")

@click.group()
def cli(): pass

@cli.command()
@click.option("--target", "-t", default=settings.scan.target_network)
def scan(target):
    raw_target = target
    target, error = normalize_target_cidr(target)
    if error:
        console.print(
            f"[bold red]BLOCKED target {_safe(repr(raw_target))}:[/] "
            f"{_safe(error)}"
        )
        raise SystemExit(2)

    async def _once():
        await db.init()
        try:
            from iris.live_display import ScanDisplay
            display = ScanDisplay(target)
            with display: await _scan_pipeline(target, display)
            display.print_final_summary()
        finally:
            await db.close()
    uvloop.run(_once())

@cli.command()
@click.option("--target", "-t", default=settings.scan.target_network)
@click.option("--interval", "-i", default=settings.scan.scan_interval_seconds)
@click.option("--profile", "-p", default=settings.scan.scan_profile)
@click.pass_context
def run(ctx, target, interval, profile):
    from click.core import ParameterSource

    from config.settings import scan as scan_cfg

    selected = normalize_scan_profile(profile)
    if selected is None:
        choices = ", ".join(sorted(scan_cfg.SCAN_PROFILES))
        console.print(f"[bold red]BLOCKED profile {_safe(repr(profile))}:[/] choose one of {choices}")
        raise SystemExit(2)
    if not isinstance(interval, int) or interval <= 0:
        console.print(
            f"[bold red]BLOCKED interval {interval!r}:[/] "
            "must be a positive number of seconds"
        )
        raise SystemExit(2)
    settings.scan.scan_profile = selected
    uvloop.run(_run_all(
        target,
        interval,
        persist_target=ctx.get_parameter_source("target") == ParameterSource.COMMANDLINE,
        persist_profile=ctx.get_parameter_source("profile") == ParameterSource.COMMANDLINE,
    ))

@cli.command()
@click.option("--host", default=settings.dash.host, show_default=True,
              help="Bind address; use 0.0.0.0 only behind a trusted proxy/VPN")
@click.option("--port", default=settings.dash.port, type=int, show_default=True,
              help="Bind port (OBSIDIOS_DASH_PORT)")
def dash(host, port):
    import os
    if os.environ.get("OBSIDIOS_ENV", "dev").strip().lower() in ("prod", "production"):
        from config.settings import validate_prod_config
        errs = validate_prod_config()
        if errs:
            for e in errs:
                console.print(f"  [bold red]BLOCKED:[/] {_safe(e)}")
            raise SystemExit(2)
    logger.info(f"Starting Gunicorn on {host}:{port} with gthread workers...")
    proc = subprocess.run(
        [sys.executable, "-m", "gunicorn", "-k", "gthread", "--threads", "10",
         "-w", "1", "-b", f"{host}:{port}", "dashboard.app:app"]
    )
    # Surface a bind/startup failure to Docker/systemd instead of exiting 0.
    if proc.returncode:
        raise SystemExit(proc.returncode)




@cli.command()
@click.option("--iface", default="eth1")
@click.option("--duration", default=1, help="Minutes to capture")
def echo(iface, duration):
    async def _run():
        await db.init()
        try:
            from echo.drift_detector import run_echo
            await run_echo(iface=iface, duration_minutes=duration)
        finally:
            await db.close()
    uvloop.run(_run())


@cli.command()
@click.option("--iface", default="eth0", help="Network interface to monitor")
@click.option("--log-dir", default="/var/log/suricata", help="Suricata log directory")
def sentinel(iface, log_dir):
    """Start SENTINEL: real-time Suricata alert pipeline with SHIELD auto-response."""
    async def _run():
        await db.init()
        try:
            from sentinel.runner import start_sentinel
            await start_sentinel(iface=iface, log_dir=log_dir)
        finally:
            await db.close()
    uvloop.run(_run())


@cli.command()
def status():
    """High-level Strategic HUD in the terminal."""
    async def _show():
        await db.init()
        try:
            from oracle.posture_score import calculate_posture_score
            res = await calculate_posture_score()
            posture = res.get('overall_score', 0)

            # Stats. The terminal HUD must agree with the dashboard: a CVE on
            # a retired host or a prediction for a gone path is history.
            from chronicle import live_state
            hosts = await db.fetch_val('SELECT COUNT(*) FROM hosts WHERE is_active=1')
            cves = await live_state.count_live_cves()
            blocks = await db.fetch_val('SELECT COUNT(*) FROM shield_actions WHERE is_active=1')
            alerts = await live_state.count_actionable_alerts()

            console.print(Panel(Text("STRATEGIC HUB STATUS: ONLINE", justify="center", style="bold green"), border_style="green"))

            table = Table(title="Tactical Metrics", box=None)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="bold white")
            table.add_row("Global Posture", f"{posture}%")
            table.add_row("Active Assets", str(hosts))
            table.add_row("Vulnerabilities", str(cves))
            table.add_row("Shield Blocks", str(blocks))
            table.add_row("Unacked Alerts", str(alerts))
            console.print(table)

            # Recent Diffs
            diffs = await db.fetch_all('SELECT diff_type, detail FROM scan_diffs ORDER BY created_at DESC LIMIT 5')
            if diffs:
                d_table = Table(title="Behavioral Drift", style="orange3")
                d_table.add_column("Type")
                d_table.add_column("Detail")
                for d in diffs: d_table.add_row(_safe(d['diff_type']), _safe(d['detail']))
                console.print(d_table)
        finally:
            await db.close()
    uvloop.run(_show())

@cli.command()
@click.option("--dest", default="reports/backups", help="Backup directory")
@click.option("--keep", default=7, help="Keep newest N backups")
def backup(dest, keep):
    """Online SQLite backup (WAL-safe) + rotation. Safe to run while daemon is live."""
    from pathlib import Path

    from chronicle.backup import backup_db
    src = settings.db.db_path
    out = backup_db(src, Path(dest), keep=int(keep))
    console.print(f"[bold green]Backup OK:[/] {_safe(out)}")


@cli.command()
@click.argument("backup_file")
@click.option("--force", is_flag=True, help="Skip confirmation prompt")
def restore(backup_file, force):
    """Restore DB from backup. Current DB is copied to .pre-restore-<ts>.bak first."""
    from pathlib import Path

    from chronicle.backup import restore_db
    dest = Path(settings.db.db_path)
    if not force and not click.confirm(f"Restore {backup_file} over {dest}? Current DB will be saved as .bak."):
        console.print("[yellow]Aborted.[/]")
        return
    out = restore_db(Path(backup_file), dest)
    console.print(f"[bold green]Restore OK:[/] {_safe(out)} (restart daemon + dash)")


@cli.command()
@click.argument('framework', default='PCI-DSS')
def audit(framework):
    """Run a compliance audit directly in the CLI."""
    async def _audit():
        await db.init()
        try:
            from oracle.compliance_mapper import map_compliance
            res = await map_compliance(framework.upper())
            if res.get('error'):
                console.print(
                    f"[bold red]BLOCKED framework {_safe(repr(framework))}:[/] {_safe(res['error'])}")
                raise SystemExit(2)

            console.print(f"[bold cyan]Compliance Audit: {_safe(res['framework'])}[/]")
            console.print(f"Score: [bold]{res['compliance_score']}%[/] | Compliant: {res['compliant']} | Failures: {res['non_compliant']}")

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Requirement")
            table.add_column("Status")
            table.add_column("Issues")

            for f in res['findings']:
                color = "green" if f['status'] == 'COMPLIANT' else "red"
                table.add_row(_safe(f['requirement']), f"[{color}]{f['status']}[/]", _safe("\n".join(f['issues']) or "-"))

            console.print(table)
        finally:
            await db.close()
    uvloop.run(_audit())

@cli.command()
def remediation():
    """Show AI-prioritized patch roadmap."""
    async def _roadmap():
        await db.init()
        try:
            from oracle.patch_prioritizer import generate_patch_priority
            res = await generate_patch_priority()

            table = Table(title="Strategic Remediation Roadmap")
            table.add_column("Priority", style="dim")
            table.add_column("Target")
            table.add_column("CVE")
            table.add_column("Risk")
            table.add_column("Exploitable")

            for idx, p in enumerate(res['priority_list'][:15]):
                table.add_row(f"#{idx+1}", _safe(f"{p['ip']} ({p['service']})"), _safe(p['cve_id']), str(p['network_risk']), "YES" if p['exploitable'] else "NO")

            console.print(table)
        finally:
            await db.close()
    uvloop.run(_roadmap())


@cli.command()
@click.option('--release', help='IP to release from SHIELD block')
def shield(release):
    """View or manage SHIELD active blocks."""
    async def _manage():
        await db.init()
        try:
            if release:
                # A DB-only update used to print "RELEASED" while the kernel DROP
                # rule stayed in place. Revert through SHIELD so the firewall is
                # actually changed and the failure is reported honestly.
                from shield.reconfigurer import revert_action
                rows = await db.fetch_all(
                    "SELECT id FROM shield_actions WHERE target_ip=? AND is_active=1",
                    (release,),
                )
                if not rows:
                    console.print(f"[yellow]No active SHIELD block for {_safe(release)}.[/]")
                else:
                    reverted = failed = 0
                    for row in rows:
                        try:
                            if await revert_action(row["id"], reverted_by="CLI"):
                                reverted += 1
                            else:
                                failed += 1
                        except Exception as exc:
                            logger.error(f"[SHIELD] Could not revert action #{row['id']}: {exc}")
                            failed += 1
                    if failed:
                        console.print(
                            f"[bold yellow]Released {reverted}/{len(rows)} block(s) for "
                            f"{_safe(release)}; {failed} could not be removed — the firewall "
                            f"rule may still be live.[/]"
                        )
                        # Partial success is a failure: exiting 0 would let a
                        # script believe the IP is unblocked while a DROP rule
                        # is still enforced.
                        raise SystemExit(1)
                    else:
                        console.print(f"[bold green]RELEASED:[/] {_safe(release)} from tactical block.")
            else:
                blocks = await db.fetch_all('SELECT id, taken_at, target_ip, action_type, justification FROM shield_actions WHERE is_active=1')
                console.print("[bold blue]🛡 SHIELD Defensive Posture[/]")
                if blocks:
                    table = Table(show_header=True, header_style="bold blue")
                    table.add_column("Target IP")
                    table.add_column("Action")
                    table.add_column("Justification")
                    for b in blocks:
                        table.add_row(_safe(b['target_ip']), _safe(b['action_type']), _safe(b['justification']))
                    console.print(table)
                else:
                    console.print("[dim]No active blocks.[/]")
        finally:
            await db.close()
    uvloop.run(_manage())


@cli.command()
def iris():
    """View IRIS intelligence findings (OSINT & Wireless)."""
    async def _show():
        await db.init()
        try:
            # OSINT
            osint = await db.fetch_all('SELECT source, finding_type, severity FROM osint_findings ORDER BY discovered_at DESC LIMIT 5')
            console.print("[bold cyan]🔭 IRIS OSINT Intelligence[/]")
            if osint:
                o_table = Table(show_header=True)
                o_table.add_column("Source")
                o_table.add_column("Finding")
                o_table.add_column("Severity")
                for o in osint: o_table.add_row(_safe(o['source']), _safe(o['finding_type']), _safe(o['severity']))
                console.print(o_table)

            # Wireless
            wifi = await db.fetch_all('SELECT ssid, threat_type, signal_strength FROM wireless_threats WHERE is_active=1')
            console.print("\n[bold cyan]📡 Wireless Threat Intelligence[/]")
            if wifi:
                w_table = Table(show_header=True)
                w_table.add_column("SSID")
                w_table.add_column("Threat")
                w_table.add_column("Signal")
                for w in wifi: w_table.add_row(_safe(w['ssid'] or '-'), _safe(w['threat_type']), f"{_safe(w['signal_strength'])} dBm")
                console.print(w_table)
            else:
                console.print("[dim]No wireless threats detected.[/]")
        finally:
            await db.close()
    uvloop.run(_show())

@cli.command()
@click.pass_context
def shell(ctx):
    """Enter interactive tactical shell."""
    console.print(Panel("Entering OBSIDIOS Interactive Shell... Type 'exit' to leave.", style="bold cyan"))
    while True:
        try:
            cmd_line = console.input("[bold green]OBSIDIOS[/] > ").strip()
            if not cmd_line or cmd_line.lower() in ['exit', 'quit', 'q']: break
            
            parts = cmd_line.split()
            cmd_name = parts[0]

            if cmd_name in cli.commands:
                try:
                    cli.main(args=parts, standalone_mode=False)
                except SystemExit:
                    # A refused sub-command exits 2; the shell itself must survive.
                    continue
                except click.ClickException as e:
                    e.show()
                except Exception as e:
                    console.print(f"[red]Error executing {_safe(cmd_name)}: {_safe(e)}[/]")
            else:
                console.print(f"[yellow]Unknown command: {_safe(cmd_name)}. Type --help for list.[/]")
        except KeyboardInterrupt:
            break
    console.print("[bold cyan]Leaving shell.[/]")







@cli.command()
def phantom():
    """View predicted adversarial kill-chains."""
    async def _show():
        await db.init()
        try:
            res = await db.fetch_all('SELECT attacker_roi, path_json, narrative FROM attack_paths WHERE is_active=1 ORDER BY attacker_roi DESC LIMIT 10')

            console.print("[bold red]👻 PHANTOM Adversarial Intelligence[/]")
            if not res:
                console.print("[dim]No active attack paths identified.[/]")
                return

            for p in res:
                roi = p['attacker_roi']
                try:
                    steps = json.loads(p['path_json']) if isinstance(p['path_json'], str) else p['path_json']
                    if isinstance(steps, dict):
                        steps = [steps]
                    if not isinstance(steps, list):
                        steps = []
                    ips = [str(step.get('ip', '?')) for step in steps if isinstance(step, dict)]
                    path_str = " -> ".join(ips) if ips else "Unknown Path"
                except Exception:
                    path_str = "Unknown Path"

                # Narrative/path data is untrusted (scanner + model output). Rich
                # would otherwise parse `[/]` or `[bold]` as markup and crash the
                # CLI, and raw control sequences would reach the terminal.
                panel_text = Text()
                panel_text.append("ROI: ", style="bold yellow")
                panel_text.append(str(roi) if roi is not None else "N/A", style="bold yellow")
                panel_text.append("\n")
                panel_text.append(path_str, style="cyan")
                panel_text.append("\n\n")
                panel_text.append(
                    str(p['narrative'] or 'No narrative available.'), style="dim"
                )
                console.print(Panel(panel_text, title="PREDICTED KILL-CHAIN", border_style="red"))
        finally:
            await db.close()
    uvloop.run(_show())


@cli.group()
def config():
    """Manage OBSIDIOS system configurations."""
    pass

@config.command(name="show")
def config_show():
    """Show current active configuration."""
    async def _show():
        await db.init()
        try:
            target = await db.fetch_val("SELECT value FROM system_settings WHERE key='target_network'", default="Not Set")
            profile = await db.fetch_val("SELECT value FROM system_settings WHERE key='scan_profile'", default="FAST")
            enabled = await db.fetch_val("SELECT value FROM system_settings WHERE key='scanner_enabled'", default="0")

            table = Table(title="System Configuration")
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="bold white")
            table.add_row("Target Network", Text(str(target)))
            table.add_row("Scan Profile", Text(str(profile)))
            table.add_row("Engine Status", Text("ONLINE" if enabled == "1" else "PAUSED"))
            console.print(table)
        finally:
            await db.close()
    uvloop.run(_show())

@config.command(name="set-target")
@click.argument('cidr')
def config_set_target(cidr):
    """Set the active tactical target (CIDR)."""
    target, error = normalize_target_cidr(cidr)
    if error:
        console.print(f"[bold red]BLOCKED target {_safe(repr(cidr))}:[/] {_safe(error)}")
        raise SystemExit(2)

    async def _set():
        await db.init()
        try:
            await db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('target_network', ?)", (target,))
            await _audit_cli("TARGET_UPDATE", target=target, detail="source=cli")
            console.print(f"[bold green]Target Updated:[/ ] {target}")
        finally:
            await db.close()
    uvloop.run(_set())

@config.command(name="set-profile")
@click.argument('profile')
def config_set_profile(profile):
    """Set the tactical scan profile."""
    selected = normalize_scan_profile(profile)
    if not selected:
        from config.settings import scan as scan_cfg
        choices = ", ".join(sorted(scan_cfg.SCAN_PROFILES))
        console.print(f"[bold red]BLOCKED profile {_safe(repr(profile))}:[/] choose one of {choices}")
        raise SystemExit(2)

    async def _set():
        await db.init()
        try:
            await db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scan_profile', ?)", (selected,))
            await _audit_cli("PROFILE_UPDATE", target=selected, detail="source=cli")
            console.print(f"[bold green]Profile Updated:[/ ] {selected}")
        finally:
            await db.close()
    uvloop.run(_set())


@config.command(name="set-scanner")
@click.argument('state', type=click.Choice(["on", "off"], case_sensitive=False))
def config_set_scanner(state):
    """Enable or pause the scanning engine (on/off)."""
    enabled = "1" if state.lower() == "on" else "0"

    async def _set():
        await db.init()
        try:
            await db.execute(
                "INSERT OR REPLACE INTO system_settings (key, value) "
                "VALUES ('scanner_enabled', ?)", (enabled,))
            await _audit_cli(
                "SCANNER_UPDATE", target=enabled, detail="source=cli")
            label = "ONLINE" if enabled == "1" else "PAUSED"
            console.print(f"[bold green]Engine Status:[/] {label}")
        finally:
            await db.close()
    uvloop.run(_set())

@cli.command()
def trigger():
    """Manually trigger a full intelligence cycle."""
    async def _trigger():
        await db.init()
        try:
            is_running = await db.fetch_val("SELECT COUNT(*) FROM scans WHERE status='RUNNING'", default=0)
            if is_running > 0:
                console.print("[bold yellow]WARNING: A scan cycle is already in progress.")
                return

            console.print("[bold cyan]Initiating Tactical Intelligence Cycle...")
            from iris.cve_mapper import map_cves_for_scan, persist_cves
            from iris.graph_builder import rebuild_graph
            from iris.wired_scanner import run_scan

            result = await run_scan()
            if result.hosts:
                cve_map, aff_map = await map_cves_for_scan(result)
                await persist_cves(cve_map, result, aff_map)
                await rebuild_graph()
            # An empty or refused scan is not a completed intelligence cycle.
            # Reporting success hid scope/nmap refusals and empty sweeps.
            if result.errors:
                for error in result.errors:
                    console.print(f"[bold yellow]Scan issue:[/] {_safe(error)}")
                console.print(
                    f"[bold yellow]Intelligence cycle incomplete:[/] "
                    f"{len(result.hosts)} host(s) processed."
                )
                raise SystemExit(1)
            console.print(
                f"[bold green]Intelligence cycle complete:[/] "
                f"{len(result.hosts)} host(s) processed."
            )
        finally:
            await db.close()
    uvloop.run(_trigger())

def _read_hub_snapshot(db_path: str):
    """Read the War Room tiles without letting a bad DB kill the TUI.

    The old nested reader used a bare `except:`, which also swallowed Ctrl-C,
    and leaked the SQLite connection whenever a query failed mid-way.
    """
    conn = None
    try:
        conn = sqlite3.connect(db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA busy_timeout=5000')
        cur = conn.cursor()
        cur.execute(
            'SELECT overall_score, active_alerts FROM posture_scores '
            'ORDER BY recorded_at DESC LIMIT 1')
        p = cur.fetchone()
        cur.execute('SELECT COUNT(*) FROM hosts WHERE is_active=1')
        a = cur.fetchone()[0]
        cur.execute(
            'SELECT target_ip FROM shield_actions WHERE is_active=1 LIMIT 5')
        b = [dict(r) for r in cur.fetchall()]
        cur.execute(
            'SELECT finding_type FROM osint_findings '
            'ORDER BY discovered_at DESC LIMIT 5')
        o = [dict(r) for r in cur.fetchall()]
        return (
            p['overall_score'] if p else 0,
            a,
            p['active_alerts'] if p else 0,
            b,
            o,
        )
    except Exception:
        # A missing/locked/old-schema DB means the console shows zeros; it
        # must stay interactive instead of crashing the whole War Room.
        return (0, 0, 0, [], [])
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


class WarRoomTUI:
    def __init__(self):
        self.log_queue = queue.Queue()
        self.log_history = []
        self.layout = Layout()
        self.current_input = ""
        self.max_logs = 18

    def make_layout(self):
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3)
        )
        self.layout["body"].split_row(
            Layout(name="feed", ratio=2),
            Layout(name="intel", ratio=1)
        )
        return self.layout

    def update_header(self, posture, assets, threats):
        self.layout["header"].update(
            Panel(f"[bold cyan]⚡ OBSIDIOS COMMAND CENTER[/] | POSTURE: [bold]{posture}%[/] | ASSETS: {assets} | THREATS: [red]{threats}[/]", border_style="blue")
        )

    def update_feed(self):
        while not self.log_queue.empty():
            self.log_history.append(self.log_queue.get())
            if len(self.log_history) > self.max_logs: self.log_history.pop(0)
        feed_text = "\n".join(_markup_safe(line) for line in self.log_history)
        feed_text = feed_text or "[dim]Monitoring Tactical Streams...[/]"
        self.layout["feed"].update(Panel(feed_text, title="[bold red]LIVE TACTICAL FEED[/]", border_style="red"))

    def update_intel(self, blocks, osint):
        stats = "[bold blue]SHIELD BLOCKS[/]\n" + ("\n".join(
            [f" - {_safe(b['target_ip'])}" for b in blocks]) or "[dim]None[/]")
        stats += "\n\n[bold cyan]IRIS OSINT[/]\n" + ("\n".join(
            [f" - {_safe(o['finding_type'])}" for o in osint]) or "[dim]None[/]")
        self.layout["intel"].update(Panel(stats, title="[bold blue]STRATEGIC INTEL[/]", border_style="blue"))

    def update_footer(self, input_text=""):
        self.layout["footer"].update(
            Panel(f"[bold green]COMMAND[/] > {input_text}", title="OPERATIVE CONSOLE (type 'help' or 'exit')", border_style="green")
        )

@cli.command()
@click.option("--host", default=settings.dash.host, show_default=True,
              help="Dashboard bind address; use 0.0.0.0 only behind a trusted proxy/VPN")
@click.pass_context
def start(ctx, host):
    """GOD MODE: Start platform and enter the War Room."""
    console.print(BANNER, style="bold cyan")
    console.print(Panel("LAUNCHING OBSIDIOS UNIFIED OPERATIONAL MODE", style="bold green"))
    
    dash_proc: dict[str, subprocess.Popen] = {}

    def run_engine():

        from config import settings
        asyncio.run(_run_all(settings.scan.target_network, settings.scan.scan_interval_seconds))
    
    def run_dash():
        proc = subprocess.Popen(
            [sys.executable, "-m", "gunicorn", "-k", "gthread", "--threads", "10",
             "-w", "1", "-b", f"{host}:{settings.dash.port}", "dashboard.app:app"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        dash_proc["proc"] = proc
        proc.wait()
    
    threading.Thread(target=run_engine, daemon=True).start()
    threading.Thread(target=run_dash, daemon=True).start()
    time.sleep(2)
    try:
        ctx.invoke(hub)
    finally:
        # A daemon thread does not reap its child: exiting the War Room used
        # to leave gunicorn holding port 8080 until it was killed by hand.
        proc = dash_proc.get("proc")
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

@cli.command()
@click.pass_context
def hub(ctx):
    """Enter the Integrated Intelligence Console."""
    logger.remove()
    tui = WarRoomTUI()
    layout = tui.make_layout()
    
    def check_input():
        if select.select([sys.stdin], [], [], 0.0)[0]:
            return sys.stdin.readline().strip()
        return None

    def fetch_data():
        return _read_hub_snapshot(settings.db.db_path)

    with Live(layout, refresh_per_second=5, screen=True):
        while True:
            try:
                posture, assets, threats, blocks, osint = fetch_data()
                tui.update_header(posture, assets, threats)
                tui.update_feed()
                tui.update_intel(blocks, osint)
                tui.update_footer(tui.current_input)
                
                cmd = check_input()
                if cmd:
                    if cmd.lower() in ['exit', 'quit', 'q']: break
                    if cmd.lower() == 'help':
                        tui.log_queue.put("[bold cyan][HELP][/] trigger, status, phantom, audit, remediation, shield, config")
                        continue
                    
                    parts = cmd.split()
                    if parts[0] in cli.commands:
                        tui.log_queue.put(f"[bold blue][CMD][/] Executing: {_safe(cmd)}")
                        res = subprocess.run([sys.executable, __file__] + parts, capture_output=True, text=True)
                        for line in res.stdout.splitlines():
                            if line.strip(): tui.log_queue.put(f"[dim]> {_safe(line.strip())}[/]")
                    else:
                        tui.log_queue.put(f"[bold yellow][WARN][/] Unknown command: {_safe(parts[0])}")
                
                time.sleep(0.1)
            except KeyboardInterrupt: break

if __name__ == "__main__": cli()
