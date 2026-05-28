"""obsidios.py — Main orchestrator + CLI"""
from __future__ import annotations
import asyncio, signal, time, json, threading, queue, select, sys, subprocess
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import click, uvloop
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.live import Live
from rich.layout import Layout


from chronicle import db
from config import settings

console = Console()

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

async def scan_cycle(scan_event: asyncio.Event) -> None:
    global scan_counter
    from iris.wired_scanner import run_scan, run_wireless_scan
    from iris.cve_mapper import map_cves_for_scan, persist_cves
    from iris.graph_builder import rebuild_graph
    from iris.osint_scanner import run_osint_scan
    from iris.nuclei_scanner import run_nuclei_scan
    from phantom.path_finder import run_simulation
    from oracle.tagnn import run_tagnn_prediction
    from forge.rule_generator import run_forge

    while not _shutdown.is_set():

        from chronicle.db import fetch_val, execute

        try:
            await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','Starting scan cycle...')")
            logger.info("[OBSIDIOS] Scan cycle starting")
            
            # Check for manual trigger from dashboard — runs even when paused
            manual = await fetch_val("SELECT value FROM system_settings WHERE key='manual_trigger'", default="0")
            if manual == "1":
                logger.info("[OBSIDIOS] Manual trigger detected — running immediate scan")
                await execute("UPDATE system_settings SET value='0' WHERE key='manual_trigger'")
                from alerts.notifier import send_alert
                await send_alert(title="🔁 **Manual Scan Triggered**", message="Immediate scan cycle initiated from dashboard", color="info", footer="OBSIDIOS v2.0")
            
            # Check for Manual Override
            enabled = await fetch_val("SELECT value FROM system_settings WHERE key='scanner_enabled'", default="0")
            if enabled == "0" and manual != "1":
                logger.warning("[SCANNER] Manual Override: PAUSED. Waiting for command...")
                from alerts.notifier import send_alert
                already = await fetch_val("SELECT value FROM system_settings WHERE key='_paused_alert_sent'", default="0")
                if already != "1":
                    await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('_paused_alert_sent','1')")
                    await send_alert(title="⏸ **Scanner Paused**", message="Manual override is active — all scanning suspended.\nWaiting for start command from dashboard.", color="medium", footer="OBSIDIOS v2.0")
                await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','Paused')")
                await asyncio.sleep(10)
                continue
            else:
                await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('_paused_alert_sent','0')")

            last_scan_id = await fetch_val(
                "SELECT id FROM scans WHERE status='DONE' ORDER BY finished_at DESC LIMIT 1"
            )

            scan_result = await run_scan()
            await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','CVE mapping...')")

            if scan_result.hosts:
                cve_map, aff_map = await map_cves_for_scan(scan_result)
                await persist_cves(cve_map, scan_result, aff_map)

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
            if simulation.total_paths > 0:
                await execute("INSERT OR REPLACE INTO system_settings(key,value) VALUES('scan_phase','Generating Suricata rules (FORGE)...')")
                await run_forge(simulation)
                logger.success(f"[OBSIDIOS] Autonomous red-team complete: {simulation.total_paths} paths found")
                from alerts.notifier import send_alert
                await send_alert(title="🕸 **Attack Paths Discovered**", message=f"PHANTOM simulated **{simulation.total_paths}** kill chains across your network", color="info", footer="OBSIDIOS v2.0")
            
            scan_counter += 1
            try:
                from oracle.claude_client import generate_report
                from alerts.notifier import send_alert
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
                    from alerts.notifier import send_alert
                    new_h = sum(1 for d in diffs if d['type'] == 'NEW_HOST')
                    gone_h = sum(1 for d in diffs if d['type'] == 'GONE_HOST')
                    parts = []
                    if new_h: parts.append(f"🟢 **{new_h}** new host(s)")
                    if gone_h: parts.append(f"🔴 **{gone_h}** host(s) went offline")
                    await send_alert(title="📊 **VulnDrift: Network Changed**", message=" — ".join(parts), color="medium", footer="OBSIDIOS v2.0")

            # Update scan record with final counts after all phases
            from chronicle.db import execute
            await execute(
                "UPDATE scans SET hosts_found=(SELECT COUNT(*) FROM hosts), "
                "ports_found=(SELECT COUNT(*) FROM ports), "
                "cves_found=(SELECT COUNT(*) FROM cves) WHERE id=?",
                (scan_result.scan_id,)
            )
            logger.success("[OBSIDIOS] Scan cycle complete")
            from alerts.notifier import flush_alerts
            await flush_alerts()
            # Auto-prune old data based on retention setting
            try:
                days_str = await fetch_val("SELECT value FROM system_settings WHERE key='retention_days'", default="30")
                days = int(days_str)
                if 0 < days <= 365:
                    cutoff = time.time() - (days * 86400)
                    await execute("DELETE FROM scan_diffs WHERE scan_id IN (SELECT id FROM scans WHERE finished_at < ?)", (cutoff,))
                    await execute("DELETE FROM scans WHERE finished_at < ?", (cutoff,))
                    await execute("DELETE FROM behavioral_events WHERE ts < ?", (cutoff,))
                    await execute("DELETE FROM anomalies WHERE acknowledged = 1 AND detected_at < ?", (cutoff,))
            except Exception:
                pass
        except Exception as exc:
            logger.exception(f"[OBSIDIOS] Scan error: {exc}")
            from alerts.notifier import send_alert
            await send_alert(title="❌ **Scan Cycle Failed**", message=f"```{str(exc)[:500]}```", color="critical", footer="OBSIDIOS v2.0")
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


async def run_scheduler():
    """Background worker that manages scheduled scans from dashboard settings."""
    from chronicle.db import fetch_val
    from iris.wired_scanner import run_scan
    from iris.cve_mapper import map_cves_for_scan, persist_cves
    from iris.graph_builder import rebuild_graph
    
    scheduler = AsyncIOScheduler()
    scheduler.start()
    logger.info("[AUTOMATION] Scheduler engine online")
    
    current_job_id = None
    last_settings = None

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
                    h, m = map(int, time_val.split(":"))
                    
                    async def scheduled_task():
                        logger.warning("[AUTOMATION] Firing scheduled scan cycle")
                        # We use the existing scan logic by setting a flag or calling it
                        # For simplicity, we just trigger run_scan here
                        result = await run_scan()
                        if result.hosts:
                            cve_map, aff_map = await map_cves_for_scan(result)
                            await persist_cves(cve_map, result, aff_map)
                            await rebuild_graph()
                        logger.success("[AUTOMATION] Scheduled scan complete")

                    if freq == "hourly":
                        job = scheduler.add_job(scheduled_task, 'interval', hours=1)
                    elif freq == "daily":
                        job = scheduler.add_job(scheduled_task, 'cron', hour=h, minute=m)
                    elif freq == "weekly":
                        job = scheduler.add_job(scheduled_task, 'cron', day_of_week='mon', hour=h, minute=m)
                    
                    current_job_id = job.id
                    logger.success(f"[AUTOMATION] Job {current_job_id} scheduled next run: {job.next_run_time}")
                else:
                    logger.info("[AUTOMATION] No active schedule configured")
                    
        except Exception as e:
            logger.error(f"[AUTOMATION] Scheduler error: {e}")
            
        await asyncio.sleep(60) # Poll for settings changes every minute


async def pulse_loop():
    """High-frequency asset pulse to keep the 3D map updated."""
    from iris.wired_scanner import fast_host_discovery
    from iris.graph_builder import rebuild_graph
    while not _shutdown.is_set():
        try:
            await fast_host_discovery()
            await rebuild_graph()
        except Exception as e:
            logger.error(f"[PULSE] Error: {e}")
        await asyncio.sleep(15) # Pulse every 15 seconds

async def _run_scan_cycle_wrapped():
    """Wrap scan_cycle with health monitoring — restarts on crash."""
    while not _shutdown.is_set():
        try:
            await scan_cycle(asyncio.Event())
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.exception(f"[OBSIDIOS] scan_cycle crashed: {e}")
            logger.info("[OBSIDIOS] Restarting scan_cycle in 5s...")
            await asyncio.sleep(5)

async def _run_all(target: str, interval: int) -> None:
    settings.scan.target_network        = target
    settings.scan.scan_interval_seconds = interval
    await db.init()
    # Start paused — scanner only activates when user explicitly enables it
    await db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scanner_enabled', '0')")
    await db.execute("UPDATE scans SET status='CANCELLED' WHERE status='RUNNING'")
    console.print(f"  [bold]Target  :[/] [cyan]{target}[/]")
    console.print(f"  [bold]Interval:[/] [cyan]{interval}s[/]")
    console.print(f"  [bold]Profile :[/] [cyan]{settings.scan.scan_profile}[/]")
    console.print(f"  [bold]Scanner :[/] [yellow]PAUSED (start from dashboard)[/]")
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
    for t in tasks: t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await db.close()

async def _scan_pipeline(target: str, display=None):
    from iris.wired_scanner import discover_hosts, scan_hosts_concurrent, _upsert_hosts, _upsert_ports
    from iris.cve_mapper import map_cves_for_scan, persist_cves
    from iris.graph_builder import rebuild_graph
    from iris.osint_scanner import run_osint_scan
    from iris.nuclei_scanner import run_nuclei_scan
    from chronicle.models import ScanResult, Host, Port

    if display: display.start_arp(target)
    arp_hosts = await discover_hosts(target)
    if display: display.finish_arp([h["ip"] for h in arp_hosts])
    if not arp_hosts: return None, None, 0
    if display:
        display.start_nmap(len(arp_hosts))
        for h in arp_hosts: display.host_scanning(h["ip"])
    scan_data = await scan_hosts_concurrent(arp_hosts)
    host_id_map = await _upsert_hosts(arp_hosts, scan_data)
    await _upsert_ports(scan_data, host_id_map)
    scan_result = ScanResult(target=target)
    for data in scan_data:
        ip = data["ip"]; hid = host_id_map.get(ip)
        scan_result.hosts.append(Host(id=hid, ip=ip, hostname=data.get("hostname"), os_name=data["os"][0]["name"] if data.get("os") else None))
        port_objs = [Port(host_id=hid, port=p["port"], protocol=p.get("protocol","tcp"), state=p.get("state","open"),
                          service=p.get("service"), product=p.get("product"), version=p.get("version"),
                          extra_info=p.get("extra_info"), cpe=p.get("cpe")) for p in data.get("ports",[])]
        if port_objs:
            scan_result.ports[ip] = port_objs
    cve_map, aff_map = await map_cves_for_scan(scan_result)
    await persist_cves(cve_map, scan_result, aff_map)
    ips = [h.ip for h in scan_result.hosts]
    await run_osint_scan(ips)
    await run_nuclei_scan(ips)
    await rebuild_graph()
    return scan_result, scan_data, 0

@click.group()
def cli(): pass

@cli.command()
@click.option("--target", "-t", default=settings.scan.target_network)
def scan(target):
    async def _once():
        await db.init()
        from iris.live_display import ScanDisplay
        display = ScanDisplay(target)
        with display: await _scan_pipeline(target, display)
        await db.close()
    uvloop.run(_once())

@cli.command()
@click.option("--target", "-t", default=settings.scan.target_network)
@click.option("--interval", "-i", default=settings.scan.scan_interval_seconds)
@click.option("--profile", "-p", default=settings.scan.scan_profile)
def run(target, interval, profile):
    settings.scan.scan_profile = profile
    uvloop.run(_run_all(target, interval))

@cli.command()
@click.option("--host", default="0.0.0.0")
@click.option("--port", default=8080)
def dash(host, port):
    logger.info(f"Starting Gunicorn on {host}:{port} with gthread workers...")
    subprocess.run([sys.executable, "-m", "gunicorn", "-k", "gthread", "--threads", "10", "-w", "1", "-b", f"{host}:{port}", "dashboard.app:app"])




@cli.command()
@click.option("--iface", default="eth1")
@click.option("--duration", default=1, help="Minutes to capture")
def echo(iface, duration):
    async def _run():
        await db.init()
        from echo.drift_detector import run_echo
        await run_echo(iface=iface, duration_minutes=duration)
        await db.close()
    uvloop.run(_run())


@cli.command()
@click.option("--iface", default="eth0", help="Network interface to monitor")
@click.option("--log-dir", default="/var/log/suricata", help="Suricata log directory")
def sentinel(iface, log_dir):
    """Start SENTINEL: real-time Suricata alert pipeline with SHIELD auto-response."""
    async def _run():
        await db.init()
        from sentinel.runner import start_sentinel
        await start_sentinel(iface=iface, log_dir=log_dir)
        await db.close()
    uvloop.run(_run())


@cli.command()
def status():
    """High-level Strategic HUD in the terminal."""
    async def _show():
        await db.init()
        from oracle.posture_score import calculate_posture_score
        res = await calculate_posture_score()
        posture = res.get('overall_score', 0)
        
        # Stats
        hosts = await db.fetch_val('SELECT COUNT(*) FROM hosts WHERE is_active=1')
        cves = await db.fetch_val('SELECT COUNT(*) FROM cves')
        blocks = await db.fetch_val('SELECT COUNT(*) FROM shield_actions WHERE is_active=1')
        alerts = 0

        console.print(Panel(Text(f"STRATEGIC HUB STATUS: ONLINE", justify="center", style="bold green"), border_style="green"))
        
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
            for d in diffs: d_table.add_row(d['diff_type'], d['detail'])
            console.print(d_table)
            
        await db.close()
    uvloop.run(_show())

@cli.command()
@click.argument('framework', default='PCI-DSS')
def audit(framework):
    """Run a compliance audit directly in the CLI."""
    async def _audit():
        await db.init()
        from oracle.compliance_mapper import map_compliance
        res = await map_compliance(framework.upper())
        
        console.print(f"[bold cyan]Compliance Audit: {res['framework']}[/]")
        console.print(f"Score: [bold]{res['compliance_score']}%[/] | Compliant: {res['compliant']} | Failures: {res['non_compliant']}")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Requirement")
        table.add_column("Status")
        table.add_column("Issues")
        
        for f in res['findings']:
            color = "green" if f['status'] == 'COMPLIANT' else "red"
            table.add_row(f['requirement'], f"[{color}]{f['status']}[/]", "\n".join(f['issues']) or "-")
        
        console.print(table)
        await db.close()
    uvloop.run(_audit())

@cli.command()
def remediation():
    """Show AI-prioritized patch roadmap."""
    async def _roadmap():
        await db.init()
        from oracle.patch_prioritizer import generate_patch_priority
        res = await generate_patch_priority()
        
        table = Table(title="Strategic Remediation Roadmap")
        table.add_column("Priority", style="dim")
        table.add_column("Target")
        table.add_column("CVE")
        table.add_column("Risk")
        table.add_column("Exploitable")
        
        for idx, p in enumerate(res['priority_list'][:15]):
            table.add_row(f"#{idx+1}", f"{p['ip']} ({p['service']})", p['cve_id'], str(p['network_risk']), "YES" if p['exploitable'] else "NO")
            
        console.print(table)
        await db.close()
    uvloop.run(_roadmap())


@cli.command()
@click.option('--release', help='IP to release from SHIELD block')
def shield(release):
    """View or manage SHIELD active blocks."""
    async def _manage():
        await db.init()
        if release:
            await db.execute('UPDATE shield_actions SET is_active=0, reverted_at=unixepoch() WHERE target_ip=? AND is_active=1', (release,))
            console.print(f"[bold green]RELEASED:[/] {release} from tactical block.")
        else:
            blocks = await db.fetch_all('SELECT id, taken_at, target_ip, action_type, justification FROM shield_actions WHERE is_active=1')
            console.print("[bold blue]🛡 SHIELD Defensive Posture[/]")
            if blocks:
                table = Table(show_header=True, header_style="bold blue")
                table.add_column("Target IP")
                table.add_column("Action")
                table.add_column("Justification")
                for b in blocks:
                    table.add_row(b['target_ip'], b['action_type'], b['justification'])
                console.print(table)
            else:
                console.print("[dim]No active blocks.[/]")
        await db.close()
    uvloop.run(_manage())


@cli.command()
def iris():
    """View IRIS intelligence findings (OSINT & Wireless)."""
    async def _show():
        await db.init()
        # OSINT
        osint = await db.fetch_all('SELECT source, finding_type, severity FROM osint_findings ORDER BY discovered_at DESC LIMIT 5')
        console.print("[bold cyan]🔭 IRIS OSINT Intelligence[/]")
        if osint:
            o_table = Table(show_header=True)
            o_table.add_column("Source")
            o_table.add_column("Finding")
            o_table.add_column("Severity")
            for o in osint: o_table.add_row(o['source'], o['finding_type'], o['severity'])
            console.print(o_table)

        # Wireless
        wifi = await db.fetch_all('SELECT ssid, threat_type, signal_strength FROM wireless_threats WHERE is_active=1')
        console.print("\n[bold cyan]📡 Wireless Threat Intelligence[/]")
        if wifi:
            w_table = Table(show_header=True)
            w_table.add_column("SSID")
            w_table.add_column("Threat")
            w_table.add_column("Signal")
            for w in wifi: w_table.add_row(w['ssid'] or '-', w['threat_type'], f"{w['signal_strength']} dBm")
            console.print(w_table)
        else:
            console.print("[dim]No wireless threats detected.[/]")
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
            cmd_args = parts[1:]
            
            if cmd_name in cli.commands:
                try:
                    cli.main(args=parts, standalone_mode=False)
                except Exception as e:
                    console.print(f"[red]Error executing {cmd_name}: {e}[/]")
            else:
                console.print(f"[yellow]Unknown command: {cmd_name}. Type --help for list.[/]")
        except KeyboardInterrupt:
            break
    console.print("[bold cyan]Leaving shell.[/]")







@cli.command()
def phantom():
    """View predicted adversarial kill-chains."""
    async def _show():
        await db.init()
        res = await db.fetch_all('SELECT attacker_roi, path_json, narrative FROM attack_paths WHERE is_active=1 ORDER BY attacker_roi DESC LIMIT 10')
        
        console.print("[bold red]👻 PHANTOM Adversarial Intelligence[/]")
        if not res:
            console.print("[dim]No active attack paths identified.[/]")
            await db.close()
            return

        for p in res:
            roi = p['attacker_roi']
            try:
                ips = [step['ip'] for step in json.loads(p['path_json'])]
                path_str = " -> ".join(ips)
            except Exception:
                path_str = "Unknown Path"
                
            panel_text = f"[bold yellow]ROI: {roi}[/]\n[cyan]{path_str}[/]\n\n[dim]{p['narrative'] or 'No narrative available.'}[/]"
            console.print(Panel(panel_text, title="PREDICTED KILL-CHAIN", border_style="red"))
            
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
        target = await db.fetch_val("SELECT value FROM system_settings WHERE key='target_network'", default="Not Set")
        profile = await db.fetch_val("SELECT value FROM system_settings WHERE key='scan_profile'", default="FAST")
        enabled = await db.fetch_val("SELECT value FROM system_settings WHERE key='scanner_enabled'", default="1")
        
        table = Table(title="System Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="bold white")
        table.add_row("Target Network", target)
        table.add_row("Scan Profile", profile)
        table.add_row("Engine Status", "ONLINE" if enabled == "1" else "PAUSED")
        console.print(table)
        await db.close()
    uvloop.run(_show())

@config.command(name="set-target")
@click.argument('cidr')
def config_set_target(cidr):
    """Set the active tactical target (CIDR)."""
    async def _set():
        await db.init()
        await db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('target_network', ?)", (cidr,))
        console.print(f"[bold green]Target Updated:[/ ] {cidr}")
        await db.close()
    uvloop.run(_set())

@config.command(name="set-profile")
@click.argument('profile', type=click.Choice(['FAST', 'STEALTH', 'GHOST', 'STEALTH_IDLE']))
def config_set_profile(profile):
    """Set the tactical scan profile."""
    async def _set():
        await db.init()
        await db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scan_profile', ?)", (profile,))
        console.print(f"[bold green]Profile Updated:[/ ] {profile}")
        await db.close()
    uvloop.run(_set())

@cli.command()
def trigger():
    """Manually trigger a full intelligence cycle."""
    async def _trigger():
        await db.init()
        is_running = await db.fetch_val("SELECT COUNT(*) FROM scans WHERE status='RUNNING'", default=0)
        if is_running > 0:
            console.print("[bold yellow]WARNING: A scan cycle is already in progress.")
            await db.close()
            return

        console.print("[bold cyan]Initiating Tactical Intelligence Cycle...")
        from iris.wired_scanner import run_scan
        from iris.cve_mapper import map_cves_for_scan, persist_cves
        from iris.graph_builder import rebuild_graph

        result = await run_scan()
        if result.hosts:
            cve_map, aff_map = await map_cves_for_scan(result)
            await persist_cves(cve_map, result, aff_map)
            await rebuild_graph()
        console.print("[bold green]Intelligence cycle complete.")
        await db.close()
    uvloop.run(_trigger())

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
        feed_text = "\n".join(self.log_history) or "[dim]Monitoring Tactical Streams...[/]"
        self.layout["feed"].update(Panel(feed_text, title="[bold red]LIVE TACTICAL FEED[/]", border_style="red"))

    def update_intel(self, blocks, osint):
        stats = "[bold blue]SHIELD BLOCKS[/]\n" + ("\n".join([f" - {b['target_ip']}" for b in blocks]) or "[dim]None[/]")
        stats += "\n\n[bold cyan]IRIS OSINT[/]\n" + ("\n".join([f" - {o['finding_type']}" for o in osint]) or "[dim]None[/]")
        self.layout["intel"].update(Panel(stats, title="[bold blue]STRATEGIC INTEL[/]", border_style="blue"))

    def update_footer(self, input_text=""):
        self.layout["footer"].update(
            Panel(f"[bold green]COMMAND[/] > {input_text}", title="OPERATIVE CONSOLE (type 'help' or 'exit')", border_style="green")
        )

@cli.command()
@click.pass_context
def start(ctx):
    """GOD MODE: Start platform and enter the War Room."""
    console.print(BANNER, style="bold cyan")
    console.print(Panel("LAUNCHING OBSIDIOS UNIFIED OPERATIONAL MODE", style="bold green"))
    
    def run_engine():
        from config import settings
        import uvloop
        asyncio.run(_run_all(settings.scan.target_network, settings.scan.scan_interval_seconds))
    
    def run_dash():
        subprocess.run([sys.executable, "-m", "gunicorn", "-k", "gthread", "--threads", "10", "-w", "1", "-b", "0.0.0.0:8080", "dashboard.app:app"], 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    threading.Thread(target=run_engine, daemon=True).start()
    threading.Thread(target=run_dash, daemon=True).start()
    time.sleep(2)
    ctx.invoke(hub)

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
        import sqlite3
        try:
            conn = sqlite3.connect(settings.db.db_path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA busy_timeout=5000')
            cur = conn.cursor()
            cur.execute('SELECT overall_score, active_alerts FROM posture_scores ORDER BY recorded_at DESC LIMIT 1')
            p = cur.fetchone()
            cur.execute('SELECT COUNT(*) FROM hosts WHERE is_active=1')
            a = cur.fetchone()[0]
            cur.execute('SELECT target_ip FROM shield_actions WHERE is_active=1 LIMIT 5')
            b = [dict(r) for r in cur.fetchall()]
            cur.execute('SELECT finding_type FROM osint_findings ORDER BY discovered_at DESC LIMIT 5')
            o = [dict(r) for r in cur.fetchall()]
            conn.close()
            return (p['overall_score'] if p else 0, a, p['active_alerts'] if p else 0, b, o)
        except: return (0, 0, 0, [], [])

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
                        tui.log_queue.put(f"[bold blue][CMD][/] Executing: {cmd}")
                        res = subprocess.run([sys.executable, __file__] + parts, capture_output=True, text=True)
                        for line in res.stdout.splitlines():
                            if line.strip(): tui.log_queue.put(f"[dim]> {line.strip()}")
                    else:
                        tui.log_queue.put(f"[bold yellow][WARN][/] Unknown command: {parts[0]}")
                
                time.sleep(0.1)
            except KeyboardInterrupt: break

if __name__ == "__main__": cli()
