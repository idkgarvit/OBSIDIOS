"""
sentinel/runner.py — Suricata subprocess wrapper + alert pipeline.

Spawns Suricata, tails eve.json, matches alerts against FORGE rules,
cross-references with PHANTOM attack paths, writes to sentinel_alerts,
and triggers SHIELD auto-response.
"""
from __future__ import annotations
import asyncio
import json
import os
import pathlib
import signal
import subprocess
import time
from loguru import logger

from chronicle import db


# ── Constants ──────────────────────────────────────────────────────────────
POLL_INTERVAL = 0.5  # seconds between eve.json polls
SHUTDOWN_WAIT = 5.0  # seconds to wait for Suricata to exit
SURICATA_BIN  = "suricata"
SURICATA_CONF = pathlib.Path(__file__).parent / "suricata.yaml"


# ── Alert Pipeline ─────────────────────────────────────────────────────────

async def _match_forge_rule(sid: int) -> dict | None:
    """Look up a Suricata SID in forge_rules. Returns rule row or None."""
    row = await db.fetch_one(
        "SELECT id, rule_text, rule_category, mitre_technique, attack_path_id "
        "FROM forge_rules WHERE rule_sid=? AND is_active=1",
        (sid,),
    )
    if not row:
        return None
    return dict(row)


async def _match_attack_path(src_ip: str, dst_ip: str) -> dict | None:
    """Check if src→dst was predicted by PHANTOM. Returns best-matching path."""
    paths = await db.fetch_all(
        """SELECT id, attacker_roi, path_json FROM attack_paths
           WHERE is_active=1 ORDER BY attacker_roi DESC LIMIT 10"""
    )
    for p in paths:
        try:
            steps = json.loads(p["path_json"])
            if not steps:
                continue
            # Check if src_ip appears as a step and dst_ip is further along
            src_idx = None
            dst_idx = None
            for i, s in enumerate(steps):
                ip = s.get("ip", "")
                if ip == src_ip:
                    src_idx = i
                if ip == dst_ip:
                    dst_idx = i
            if src_idx is not None and dst_idx is not None and src_idx < dst_idx:
                return {"id": p["id"], "roi": p["attacker_roi"]}
        except (json.JSONDecodeError, TypeError):
            continue
    return None


async def _write_alert(alert: dict) -> int | None:
    """Insert a sentinel_alert row. Returns row id or None."""
    row = await db.execute_returning(
        """INSERT INTO sentinel_alerts
           (alerted_at, rule_sid, forge_rule_id, attack_path_id,
            src_ip, dst_ip, src_port, dst_port, protocol,
            severity, message, predicted)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id""",
        (
            alert.get("alerted_at", time.time()),
            alert.get("rule_sid"),
            alert.get("forge_rule_id"),
            alert.get("attack_path_id"),
            alert.get("src_ip"),
            alert.get("dst_ip"),
            alert.get("src_port"),
            alert.get("dst_port"),
            alert.get("protocol", "tcp"),
            alert.get("severity", 1),
            alert.get("message", "")[:500],
            1 if alert.get("predicted") else 0,
        ),
    )
    return row["id"] if row else None


def _parse_eve_alert(line: str) -> dict | None:
    """Parse a single eve.json line. Returns normalized alert dict or None."""
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None

    if entry.get("event_type") != "alert":
        return None

    alert = entry.get("alert", {})
    src_ip = entry.get("src_ip", "")
    dst_ip = entry.get("dest_ip", "")
    src_port = entry.get("src_port", 0)
    dst_port = entry.get("dest_port", 0)
    proto = entry.get("proto", "TCP").lower()
    sid = alert.get("signature_id", 0)
    severity = alert.get("severity", 1)  # 1=high, 2=med, 3=low, 4=info
    message = alert.get("signature", "")

    if not src_ip or not dst_ip or not sid:
        return None

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "rule_sid": sid,
        "severity": severity,
        "message": message,
        "alerted_at": entry.get("timestamp", time.time()),
        "raw": entry,
    }


# ── Event Loop ─────────────────────────────────────────────────────────────

async def _tail_eve(eve_path: str, shutdown_event: asyncio.Event) -> None:
    """Poll eve.json for new lines and process alerts."""
    path = pathlib.Path(eve_path)
    if not path.exists():
        logger.warning(f"[SENTINEL] eve.json not found at {eve_path}, waiting...")
        while not path.exists() and not shutdown_event.is_set():
            await asyncio.sleep(1)
        if shutdown_event.is_set():
            return

    # Seek to end to avoid re-processing old alerts
    with open(eve_path, "r") as f:
        f.seek(0, os.SEEK_END)
        while not shutdown_event.is_set():
            line = f.readline()
            if not line:
                await asyncio.sleep(POLL_INTERVAL)
                continue
            line = line.strip()
            if not line:
                continue

            try:
                await _process_alert(line)
            except Exception as exc:
                logger.error(f"[SENTINEL] Alert processing error: {exc}")


async def _process_alert(line: str) -> None:
    """Process a single Suricata alert through the full pipeline."""
    alert = _parse_eve_alert(line)
    if not alert:
        return

    sid = alert["rule_sid"]

    # Step 1: Match against FORGE rules
    rule = await _match_forge_rule(sid)
    if not rule:
        return  # Only process alerts matching our generated rules

    forge_rule_id = rule["id"]
    attack_path_id = rule.get("attack_path_id")
    alert["forge_rule_id"] = forge_rule_id
    alert["mitre_technique"] = rule.get("mitre_technique", "")

    # Step 2: Cross-reference with PHANTOM attack paths
    if attack_path_id:
        alert["attack_path_id"] = attack_path_id
        alert["predicted"] = True
    else:
        path_match = await _match_attack_path(alert["src_ip"], alert["dst_ip"])
        if path_match:
            alert["attack_path_id"] = path_match["id"]
            alert["predicted"] = True
        else:
            alert["predicted"] = False

    # Step 3: Write to sentinel_alerts
    alert_id = await _write_alert(alert)
    if not alert_id:
        return

    predicted_str = "PREDICTED" if alert["predicted"] else "UNEXPECTED"
    logger.info(
        f"[SENTINEL] Alert #{alert_id} [{predicted_str}] "
        f"SID:{sid} {alert['src_ip']}→{alert['dst_ip']}:{alert['dst_port']} "
        f"\"{alert['message'][:60]}\""
    )

    from alerts.notifier import send_alert, check_cooldown
    mitre = alert.get("mitre_technique", "")
    cooldown_key = f"sentinel:{alert['src_ip']}→{alert['dst_ip']}"
    if not check_cooldown(cooldown_key, 60):
        logger.debug(f"[SENTINEL] Alert #{alert_id} suppressed (cooldown): {cooldown_key}")
        return
    if alert["predicted"]:
        await send_alert(
            title=f"🔴 **Intrusion Predicted: Alert #{alert_id}**",
            message=f"`{alert['src_ip']}` → `{alert['dst_ip']}:{alert['dst_port']}`\n```{alert['message'][:200]}```",
            color="high",
            fields=[{"name": "Source", "value": f"`{alert['src_ip']}`", "inline": True},
                    {"name": "Target", "value": f"`{alert['dst_ip']}:{alert['dst_port']}`", "inline": True},
                    {"name": "MITRE", "value": mitre or "N/A", "inline": True},
                    {"name": "Status", "value": "✅ Path Predicted", "inline": True}],
            footer="OBSIDIOS v2.0"
        )
    else:
        await send_alert(
            title=f"⛔ **UNEXPECTED Intrusion: Alert #{alert_id}**",
            message=f"`{alert['src_ip']}` → `{alert['dst_ip']}:{alert['dst_port']}`\n```{alert['message'][:200]}```",
            color="critical",
            fields=[{"name": "Source", "value": f"`{alert['src_ip']}`", "inline": True},
                    {"name": "Target", "value": f"`{alert['dst_ip']}:{alert['dst_port']}`", "inline": True},
                    {"name": "MITRE", "value": mitre or "N/A", "inline": True},
                    {"name": "Status", "value": "❌ NOT Predicted", "inline": True}],
            footer="OBSIDIOS v2.0"
        )

    # Step 4: Trigger SHIELD auto-response
    try:
        from shield.reconfigurer import respond_to_sentinel_alert

        shield_alert = {
            "src_ip": alert["src_ip"],
            "dst_ip": alert["dst_ip"],
            "dst_port": alert["dst_port"],
            "attack_path_id": alert.get("attack_path_id"),
            "predicted": alert["predicted"],
            "severity": alert["severity"],
        }
        await respond_to_sentinel_alert(shield_alert)
    except Exception as exc:
        logger.error(f"[SENTINEL] SHIELD response failed: {exc}")
        from alerts.notifier import send_alert
        await send_alert(title="🛡 **SHIELD Response Failed**", message=f"Auto-response to alert **#{alert_id}** failed: `{str(exc)[:200]}`", color="medium", footer="OBSIDIOS v2.0")


# ── Suricata Process Management ───────────────────────────────────────────

def _build_suricata_cmd(iface: str, log_dir: str, conf_path: str) -> list[str]:
    """Build the Suricata command line."""
    return [
        SURICATA_BIN,
        "-i", iface,
        "--set", f"default-log-dir={log_dir}",
        "-c", conf_path,
        "--af-packet",
        "-v",
    ]


async def _spawn_suricata(
    cmd: list[str],
    shutdown_event: asyncio.Event,
) -> asyncio.subprocess.Process | None:
    """Spawn Suricata as a subprocess."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info(f"[SENTINEL] Suricata started (PID: {proc.pid})")
        return proc
    except FileNotFoundError:
        logger.error(f"[SENTINEL] Suricata binary not found at '{SURICATA_BIN}'")
        return None
    except Exception as exc:
        logger.error(f"[SENTINEL] Failed to spawn Suricata: {exc}")
        return None


async def _monitor_suricata(
    proc: asyncio.subprocess.Process,
    shutdown_event: asyncio.Event,
) -> None:
    """Monitor Suricata stderr for errors; restart if it crashes."""
    while not shutdown_event.is_set():
        try:
            line = await asyncio.wait_for(
                proc.stderr.readline(), timeout=1.0
            )
            if line:
                msg = line.decode(errors="replace").strip()
                if msg:
                    logger.debug(f"[SURICATA] {msg}")
        except asyncio.TimeoutError:
            # Check if process is still alive
            if proc.returncode is not None:
                logger.warning(
                    f"[SENTINEL] Suricata exited (code: {proc.returncode}), restarting..."
                )
                from alerts.notifier import send_alert
                await send_alert(title="💀 **Suricata Crashed**", message=f"Exit code: `{proc.returncode}` — auto-restarting in 3s", color="critical", footer="OBSIDIOS v2.0")
                return False  # Signal caller to restart
    return True


# ── Public API ─────────────────────────────────────────────────────────────

async def start_sentinel(
    iface: str = "eth0",
    log_dir: str = "/var/log/suricata",
    conf_path: str | None = None,
) -> None:
    """
    Start SENTINEL: spawn Suricata and begin processing alerts.

    Runs forever until cancelled. Designed to run as an asyncio task
    in the daemon container or as a standalone CLI command.
    """
    await db.init()

    if conf_path is None:
        conf_path = str(SURICATA_CONF)

    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)
    eve_path = os.path.join(log_dir, "eve.json")

    shutdown_event = asyncio.Event()

    def _handle_signal():
        logger.info("[SENTINEL] Shutdown signal received")
        shutdown_event.set()

    # Register signal handlers for graceful shutdown
    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, _handle_signal)
        loop.add_signal_handler(signal.SIGINT, _handle_signal)
    except (NotImplementedError, RuntimeError):
        pass  # Not on Unix or not in main thread

    cmd = _build_suricata_cmd(iface, log_dir, conf_path)
    logger.info(f"[SENTINEL] Starting on interface {iface}, log dir: {log_dir}")

    while not shutdown_event.is_set():
        proc = await _spawn_suricata(cmd, shutdown_event)
        if proc is None:
            logger.error("[SENTINEL] Cannot start — Suricata not found or failed")
            return

        # Give Suricata a moment to create eve.json
        await asyncio.sleep(2)

        # Start the eve.json tailer as a concurrent task
        tailer_task = asyncio.create_task(_tail_eve(eve_path, shutdown_event))

        # Monitor Suricata
        result = await _monitor_suricata(proc, shutdown_event)
        tailer_task.cancel()
        try:
            await tailer_task
        except asyncio.CancelledError:
            pass

        if shutdown_event.is_set():
            break

        # If Suricata crashed, wait and restart
        logger.info("[SENTINEL] Restarting Suricata in 3 seconds...")
        await asyncio.sleep(3)

    # Graceful shutdown
    logger.info("[SENTINEL] Shutting down...")
    if proc and proc.returncode is None:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=SHUTDOWN_WAIT)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

    await db.close()
    logger.success("[SENTINEL] Stopped")