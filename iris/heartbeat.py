"""iris/heartbeat.py — ultra-fast host-presence pulse.

The daemon runs one cycle every 15 s. A cycle uses the same ARP + nmap
discovery path as a full scan (so a host first seen by heartbeat gets its MAC
recorded, not just a bare IP row) and reconciles presence without ever taking
the network offline when discovery itself failed.
"""
from __future__ import annotations

import asyncio
import json
import time

from loguru import logger

from chronicle import db
from iris import wired_scanner

HEARTBEAT_INTERVAL_SECONDS = 15


def _valid_hosts(hosts: object) -> list[dict[str, str]]:
    """Normalise discovery records; drop malformed or blank entries.

    Records come from ARP/nmap wrappers and are untrusted: one malformed
    entry must not abort the cycle or feed garbage into the hosts table.
    """
    clean: list[dict[str, str]] = []
    for host in hosts if isinstance(hosts, list) else []:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip")
        if not isinstance(ip, str) or not ip.strip():
            continue
        clean.append({"ip": ip.strip(), "mac": host.get("mac")})
    return clean


def _row_get(row, key: str, default=None):
    """Read a column from a sqlite3.Row or a plain dict.

    ``sqlite3.Row`` (what CHRONICLE returns) has no ``.get``; calling it
    raised AttributeError on every non-empty heartbeat sweep.
    """
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


async def heartbeat_once(target: str, socketio=None) -> dict:
    """Run one presence sweep and reconcile it with the hosts table.

    Returns a summary. ``status`` is ``refused`` for an invalid target,
    ``empty`` when discovery returned no hosts (the DB is left untouched so a
    failed sweep cannot mass-offline the network), or ``ok``.
    """
    ok, reason = wired_scanner.validate_target_cidr(target)
    if not ok:
        logger.error(
            f"[IRIS/HEARTBEAT] Refusing invalid target {target!r}: {reason}"
        )
        return {"status": "refused", "reason": reason}

    now = time.time()
    hosts = _valid_hosts(await wired_scanner.discover_hosts(target))
    live_ips = {host["ip"] for host in hosts}

    if not live_ips:
        logger.warning(
            f"[IRIS/HEARTBEAT] Discovery of {target} returned no hosts — "
            "skipping presence update"
        )
        return {"status": "empty", "live": 0, "up": 0, "down": 0}

    db_rows = await db.fetch_all(
        "SELECT ip, last_seen FROM hosts WHERE is_active=1")
    db_active_ips = {
        ip for row in db_rows
        if isinstance(ip := _row_get(row, "ip"), str) and ip
    }

    new_ips = live_ips - db_active_ips
    # A single missed discovery reply is not an outage. Only hosts unseen
    # beyond the grace window are taken down, matching the scan path.
    grace = wired_scanner._fast_offline_grace_seconds()
    unseen = db_active_ips - live_ips
    gone_ips = {
        ip for row in db_rows
        if (ip := _row_get(row, "ip")) in unseen
        and (_row_get(row, "last_seen", 0) or 0) < now - grace
    }

    mac_by_ip = {host["ip"]: host.get("mac") for host in hosts}
    for ip in new_ips:
        logger.success(f"[IRIS/HEARTBEAT] Host UP: {ip}")
        await db.execute(
            "INSERT INTO hosts (ip, mac, is_active, last_seen) VALUES (?, ?, 1, ?) "
            "ON CONFLICT(ip) DO UPDATE SET is_active=1, "
            "last_seen=excluded.last_seen, offline_since=NULL",
            (ip, mac_by_ip.get(ip), now),
        )
        if socketio:
            socketio.emit("host_event", {"type": "UP", "ip": ip}, namespace="/")

    # Refresh last_seen for every live host in one statement.
    await db.execute(
        "UPDATE hosts SET is_active=1, last_seen=?, offline_since=NULL "
        "WHERE ip IN (SELECT value FROM json_each(?))",
        (now, json.dumps(sorted(live_ips))),
    )

    for ip in gone_ips:
        logger.warning(f"[IRIS/HEARTBEAT] Host DOWN: {ip}")
        # Record when the outage started. Without it the scan-diff query can
        # never recognise the GONE_HOST transition, so a heartbeat-detected
        # outage was invisible in the timeline.
        await db.execute(
            "UPDATE hosts SET is_active=0, offline_since=unixepoch() "
            "WHERE ip=?", (ip,))
        if socketio:
            socketio.emit("host_event", {"type": "DOWN", "ip": ip}, namespace="/")

    if new_ips or gone_ips:
        if socketio:
            socketio.emit(
                "scan_progress",
                {"status": "refresh", "message": "Network topology changed"},
                namespace="/",
            )

    return {
        "status": "ok",
        "live": len(live_ips),
        "up": len(new_ips),
        "down": len(gone_ips),
    }


async def run_heartbeat_loop(target: str, socketio=None) -> None:
    """Continuous 15 s pulse to detect host presence changes."""
    ok, reason = wired_scanner.validate_target_cidr(target)
    if not ok:
        logger.error(
            f"[IRIS/HEARTBEAT] Refusing invalid target {target!r}: {reason}"
        )
        return

    logger.info(f"[IRIS/HEARTBEAT] Starting real-time pulse on {target}")
    while True:
        try:
            await heartbeat_once(target, socketio=socketio)
        except Exception as exc:
            logger.error(f"[IRIS/HEARTBEAT] Loop error: {exc}")
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
