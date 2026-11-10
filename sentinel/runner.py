"""
sentinel/runner.py — Suricata subprocess wrapper + alert pipeline.

Spawns Suricata, tails eve.json, matches alerts against FORGE rules,
cross-references with PHANTOM attack paths, writes to sentinel_alerts,
and triggers SHIELD auto-response.
"""
from __future__ import annotations

import asyncio
import datetime
import ipaddress
import json
import os
import pathlib
import signal
import subprocess
import time

from loguru import logger

from chronicle import db
from config import settings

# ── Constants ──────────────────────────────────────────────────────────────
POLL_INTERVAL = 0.5  # seconds between eve.json polls
SHUTDOWN_WAIT = 5.0  # seconds to wait for Suricata to exit
SURICATA_START_WAIT = 2.0  # seconds for Suricata to create eve.json
SURICATA_RESTART_DELAY = 3.0  # seconds before restarting a crashed Suricata
SURICATA_BIN  = "suricata"
SURICATA_CONF = pathlib.Path(__file__).parent / "suricata.yaml"


# ── Alert Pipeline ─────────────────────────────────────────────────────────

async def _match_forge_rule(sid: int) -> dict | None:
    """Look up a Suricata SID in forge_rules. Returns rule row or None.

    Deliberately ignores ``is_active``: it records author intent for the *next*
    ruleset write. A rule excluded a minute ago can still be live in Suricata
    until the operator redeploys, so alerts it produces must still be recorded
    instead of silently dropped.
    """
    row = await db.fetch_one(
        "SELECT id, rule_text, rule_category, mitre_technique, attack_path_id "
        "FROM forge_rules WHERE rule_sid=?",
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
            if not isinstance(steps, list) or not steps:
                continue
            # Check if src_ip appears as a step and dst_ip is further along
            src_idx = None
            dst_idx = None
            for i, s in enumerate(steps):
                if not isinstance(s, dict):
                    continue
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


def _text(value, default: str = "") -> str:
    """Coerce an eve.json field to text without ever raising."""
    if value is None:
        return default
    return value if isinstance(value, str) else str(value)


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
            _text(alert.get("message"), "")[:500],
            1 if alert.get("predicted") else 0,
        ),
    )
    return row["id"] if row else None


def _parse_timestamp(value) -> float:
    """Suricata emits ISO-8601 strings; SQLite columns are REAL epoch seconds."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str) and value:
        raw = value.strip().replace("Z", "+00:00")
        # Python <3.11 needs a colon in the UTC offset (+0000 -> +00:00).
        if len(raw) >= 5 and raw[-5] in "+-" and raw[-4:].isdigit():
            raw = raw[:-5] + raw[-5:-2] + ":" + raw[-2:]
        try:
            return datetime.datetime.fromisoformat(raw).timestamp()
        except (ValueError, OverflowError):
            pass
    return time.time()


def _port_number(value) -> int | None:
    """Coerce an eve.json port to a valid TCP/UDP port, or None.

    SQLite rejects a dict/list bound to an INTEGER column, and one malformed
    field would make `_write_alert()` raise and silently lose the alert.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 65535 else None


def _parse_eve_alert(line: str) -> dict | None:
    """Parse a single eve.json line. Returns normalized alert dict or None."""
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(entry, dict):
        return None
    if entry.get("event_type") != "alert":
        return None

    raw_alert = entry.get("alert")
    alert = raw_alert if isinstance(raw_alert, dict) else {}
    src_ip = entry.get("src_ip", "")
    dst_ip = entry.get("dest_ip", "")
    if not isinstance(src_ip, str) or not isinstance(dst_ip, str):
        return None
    src_port = _port_number(entry.get("src_port"))
    dst_port = _port_number(entry.get("dest_port"))
    proto = _text(entry.get("proto"), "TCP").lower()
    try:
        sid = int(alert.get("signature_id") or 0)
    except (TypeError, ValueError):
        sid = 0
    try:
        severity = int(alert.get("severity") or 1)
    except (TypeError, ValueError):
        severity = 1
    severity = max(1, min(4, severity))  # Suricata: 1=high .. 4=info
    message = _text(alert.get("signature"), "")

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
        "alerted_at": _parse_timestamp(entry.get("timestamp")),
        "raw": entry,
    }


# ── Event Loop ─────────────────────────────────────────────────────────────

async def _tail_eve(
    eve_path: str,
    shutdown_event: asyncio.Event,
    start_offset: int | None = None,
) -> None:
    """Poll eve.json for new lines and process alerts, surviving log rotation.

    ``start_offset`` is the byte offset of the file *before* Suricata was
    spawned. Starting there (instead of at EOF) means alerts generated during
    the first couple of seconds of startup are not silently lost.
    """
    path = pathlib.Path(eve_path)
    if not path.exists():
        logger.warning(f"[SENTINEL] eve.json not found at {eve_path}, waiting...")
        while not path.exists() and not shutdown_event.is_set():
            await asyncio.sleep(1)
        if shutdown_event.is_set():
            return

    f = None
    inode = None
    first_open = True
    try:
        while not shutdown_event.is_set():
            try:
                st = path.stat()
            except FileNotFoundError:
                await asyncio.sleep(POLL_INTERVAL)
                continue

            # Suricata rotates eve.json; reopen on inode change/truncation.
            if f is None or st.st_ino != inode:
                if f is not None:
                    f.close()
                    f = None
                try:
                    f = open(eve_path, errors="replace")
                except FileNotFoundError:
                    # Rotation can unlink the file between stat() and open();
                    # retrying is correct, crashing the tailer is not.
                    await asyncio.sleep(POLL_INTERVAL)
                    continue
                inode = st.st_ino
                if first_open:
                    size = f.seek(0, os.SEEK_END)
                    if start_offset is not None and start_offset <= size:
                        # Same file, appended to: skip the pre-existing tail.
                        f.seek(start_offset)
                    else:
                        # New or truncated file: read everything in it.
                        f.seek(0)
                    first_open = False
                else:
                    f.seek(0)

            pos = f.tell()
            line = f.readline()
            if not line:
                # Handle copy-truncate rotation where the inode is unchanged.
                try:
                    if path.stat().st_size < f.tell():
                        f.seek(0)
                except FileNotFoundError:
                    pass
                await asyncio.sleep(POLL_INTERVAL)
                continue
            if not line.endswith("\n"):
                # Suricata is mid-write. Re-read the line once it is complete;
                # processing a truncated JSON line silently drops the alert.
                f.seek(pos)
                await asyncio.sleep(POLL_INTERVAL)
                continue
            line = line.strip()
            if not line:
                continue

            try:
                await _process_alert(line)
            except Exception as exc:
                logger.error(f"[SENTINEL] Alert processing error: {exc}")
    finally:
        if f is not None:
            f.close()


async def _notify(**kwargs) -> None:
    """Send a notification without letting delivery failure abort the pipeline."""
    try:
        from alerts.notifier import send_alert

        await send_alert(**kwargs)
    except Exception as exc:
        logger.error(f"[SENTINEL] Notification failed: {exc}")


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

    # Notifications are best-effort. A dead webhook must never stop SHIELD
    # from responding to the intrusion.
    mitre = alert.get("mitre_technique", "")
    cooldown_key = f"sentinel:{alert['src_ip']}→{alert['dst_ip']}"
    suppress_notification = False
    try:
        from alerts.notifier import check_cooldown

        suppress_notification = not check_cooldown(cooldown_key, 60)
    except Exception as exc:
        logger.warning(f"[SENTINEL] Cooldown check failed ({exc}); sending alert")

    if suppress_notification:
        # The cooldown only silences the webhook. SHIELD must still run: the
        # first alert of the pair may not have triggered a block (different
        # severity/confidence), leaving this later one as the only chance.
        logger.debug(f"[SENTINEL] Alert #{alert_id} notification suppressed (cooldown): {cooldown_key}")
    elif alert["predicted"]:
        await _notify(
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
        await _notify(
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
            "protocol": alert.get("protocol"),
            "attack_path_id": alert.get("attack_path_id"),
            "predicted": alert["predicted"],
            "severity": alert["severity"],
        }
        await respond_to_sentinel_alert(shield_alert)
    except Exception as exc:
        logger.error(f"[SENTINEL] SHIELD response failed: {exc}")
        await _notify(title="🛡 **SHIELD Response Failed**", message=f"Auto-response to alert **#{alert_id}** failed: `{str(exc)[:200]}`", color="medium", footer="OBSIDIOS v2.0")


# ── Suricata Process Management ───────────────────────────────────────────

async def _resolve_home_net() -> str:
    """The dashboard target wins over the environment captured at start-up."""
    target = ""
    try:
        target = await db.fetch_val(
            "SELECT value FROM system_settings WHERE key='target_network'",
            default="") or ""
    except Exception as exc:
        logger.warning(f"[SENTINEL] Could not read target network: {exc}")
    target = target.strip() or settings.scan.target_network
    try:
        return str(ipaddress.ip_network(target, strict=False))
    except ValueError:
        return "192.168.0.0/16"


def _build_suricata_cmd(
    iface: str,
    log_dir: str,
    conf_path: str,
    home_net: str | None = None,
) -> list[str]:
    """Build the Suricata command line."""
    if home_net is None:
        home_net = settings.scan.target_network
    try:
        home_net = str(ipaddress.ip_network(home_net, strict=False))
    except ValueError:
        home_net = "192.168.0.0/16"
    return [
        SURICATA_BIN,
        "-i", iface,
        "--set", f"default-log-dir={log_dir}",
        "--set", f"vars.address-groups.HOME_NET={home_net}",
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
) -> bool:
    """Watch Suricata while it runs. Returns True on shutdown, False on exit."""
    while not shutdown_event.is_set():
        line = b""
        try:
            line = await asyncio.wait_for(proc.stderr.readline(), timeout=1.0)
        except TimeoutError:
            pass

        if line:
            msg = line.decode(errors="replace").strip()
            if msg:
                logger.debug(f"[SURICATA] {msg}")
            continue

        # EOF returns b"" immediately. Without checking the exit code and
        # sleeping here this loop spins a CPU core forever after a crash.
        if proc.returncode is not None:
            logger.warning(
                f"[SENTINEL] Suricata exited (code: {proc.returncode}), restarting..."
            )
            await _notify(
                title="💀 **Suricata Crashed**",
                message=f"Exit code: `{proc.returncode}` — auto-restarting in 3s",
                color="critical",
                footer="OBSIDIOS v2.0",
            )
            return False
        await asyncio.sleep(0.2)
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

    home_net = await _resolve_home_net()
    cmd = _build_suricata_cmd(iface, log_dir, conf_path, home_net=home_net)
    logger.info(
        f"[SENTINEL] Starting on interface {iface}, log dir: {log_dir}, "
        f"HOME_NET: {home_net}")

    proc = None
    tailer_task = None
    try:
        while not shutdown_event.is_set():
            # Remember how much of eve.json predates this Suricata process, so
            # the tailer can skip old alerts without dropping fresh startup
            # alerts.
            try:
                start_offset = os.path.getsize(eve_path)
            except OSError:
                start_offset = 0

            proc = await _spawn_suricata(cmd, shutdown_event)
            if proc is None:
                logger.error("[SENTINEL] Cannot start — Suricata not found or failed")
                return

            # Give Suricata a moment to create eve.json
            await asyncio.sleep(SURICATA_START_WAIT)

            # Start the eve.json tailer as a concurrent task
            tailer_task = asyncio.create_task(
                _tail_eve(eve_path, shutdown_event, start_offset=start_offset)
            )

            # Monitor Suricata
            await _monitor_suricata(proc, shutdown_event)
            tailer_task.cancel()
            try:
                await tailer_task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                # An unexpected tailer crash (permissions, disk I/O) used to
                # escape and kill the supervisor. Restarting Suricata gets a
                # fresh tailer task and keeps the alert pipeline alive.
                logger.error(f"[SENTINEL] eve.json tailer stopped: {exc}")
            tailer_task = None

            if shutdown_event.is_set():
                break

            # If Suricata crashed, wait and restart
            logger.info("[SENTINEL] Restarting Suricata in 3 seconds...")
            await asyncio.sleep(SURICATA_RESTART_DELAY)
    finally:
        # Graceful shutdown. `db.close()` must also run when Suricata could
        # not be spawned or the task is cancelled by the daemon.
        logger.info("[SENTINEL] Shutting down...")
        if tailer_task is not None:
            tailer_task.cancel()
            try:
                await tailer_task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                logger.debug(f"[SENTINEL] Tailer already stopped: {exc}")
        if proc and proc.returncode is None:
            try:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=SHUTDOWN_WAIT)
                except TimeoutError:
                    proc.kill()
                    await proc.wait()
            except ProcessLookupError:
                pass  # exited between the check and the signal
            except Exception as exc:
                logger.warning(f"[SENTINEL] Could not stop Suricata cleanly: {exc}")

        await db.close()
        logger.success("[SENTINEL] Stopped")