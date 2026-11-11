"""chronicle/live_state.py — one definition of "current" for live views.

Historical rows stay in SQLite for audit, but a dashboard number must only
describe the network as it is now. That means:

* a host counts only while ``hosts.is_active=1``;
* a service counts only while its port is still ``open``;
* an attack path counts only while every host on it is still active;
* a predicted alert counts only while its path is live and at least one
  endpoint is still an active host. Real IDS alerts are events, not
  predictions, so they remain actionable until an operator acknowledges them.

Keeping those rules here means the scanner, the dashboard, ORACLE and the PDF
report cannot drift apart and quietly count a decommissioned host again.
"""
from __future__ import annotations

import json
from typing import Any

from loguru import logger

from chronicle import db

ACTIVE_HOST_IP_SQL = (
    "SELECT ip FROM hosts "
    "WHERE is_active=1 AND ip IS NOT NULL AND ip != ''"
)


def _field(row: Any, key: str, default: Any = None) -> Any:
    """Read one column from a dict or an ``aiosqlite.Row`` without raising."""
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return default


def path_is_live(path_json: Any, active_ips: set[str]) -> bool:
    """True when every hop in a serialized attack path is an active host.

    A path anchored on even one vanished host is no longer a route an attacker
    can take, so it must not appear in the action queue, posture score or PDF.
    """
    try:
        steps = json.loads(path_json) if isinstance(path_json, str) else path_json
    except (TypeError, ValueError):
        return False
    if not isinstance(steps, list) or not steps:
        return False
    for step in steps:
        if not isinstance(step, dict):
            return False
        ip = step.get("ip")
        if not isinstance(ip, str) or not ip or ip not in active_ips:
            return False
    return True


def alert_is_actionable(
    alert: Any,
    active_ips: set[str],
    live_path_ids: set[int],
) -> bool:
    """True when an unacknowledged alert still describes reachable exposure.

    Real (non-predicted) alerts are historical events and stay actionable until
    acknowledged. A prediction is only useful while its path is live and at
    least one endpoint still exists on the network.
    """
    if not _field(alert, "predicted", 0):
        return True
    path_id = _field(alert, "attack_path_id")
    if path_id is not None and path_id not in live_path_ids:
        return False
    src, dst = _field(alert, "src_ip"), _field(alert, "dst_ip")
    return bool(src in active_ips or dst in active_ips)


async def active_host_ips() -> set[str]:
    rows = await db.fetch_all(ACTIVE_HOST_IP_SQL) or []
    return {row["ip"] for row in rows if _field(row, "ip")}


async def live_attack_paths() -> list[Any]:
    """Active attack paths whose every hop is still an active host."""
    active = await active_host_ips()
    rows = await db.fetch_all(
        "SELECT * FROM attack_paths WHERE is_active=1 "
        "ORDER BY attacker_roi DESC"
    ) or []
    return [row for row in rows if path_is_live(_field(row, "path_json"), active)]


async def live_attack_path_ids() -> set[int]:
    return {
        path_id for path_id in (_field(row, "id") for row in await live_attack_paths())
        if path_id is not None
    }


async def count_live_attack_paths() -> int:
    return len(await live_attack_paths())


async def count_live_cves(severity: str | None = None) -> int:
    """Distinct CVEs on active hosts, open ports and undismissed findings."""
    sql = (
        "SELECT COUNT(DISTINCT pc.cve_id) FROM port_cves pc "
        "JOIN cves c ON c.id = pc.cve_id "
        "JOIN ports p ON p.id = pc.port_id "
        "JOIN hosts h ON h.id = p.host_id "
        "WHERE h.is_active = 1 AND p.state = 'open' "
        "AND COALESCE(pc.dismissed, 0) = 0 "
        "AND COALESCE(pc.verified_status, '') != 'NOT_AFFECTED'"
    )
    params: tuple = ()
    if severity:
        sql += " AND c.severity = ?"
        params = (severity,)
    return int(await db.fetch_val(sql, params, default=0) or 0)


async def actionable_alerts(include_acknowledged: bool = False) -> list[Any]:
    """Alerts whose decision is still current (stale predictions dropped)."""
    active = await active_host_ips()
    live_ids = await live_attack_path_ids()
    sql = "SELECT * FROM sentinel_alerts"
    if not include_acknowledged:
        sql += " WHERE acknowledged=0"
    rows = await db.fetch_all(sql) or []
    return [row for row in rows if alert_is_actionable(row, active, live_ids)]


async def count_actionable_alerts(include_acknowledged: bool = False) -> int:
    return len(await actionable_alerts(include_acknowledged))


async def retire_stale_attack_paths(active_ips: set[str] | None = None) -> int:
    """Deactivate paths that mention a host no longer active.

    Called after every sweep that marks hosts offline. Read paths use the same
    predicate, so an older database is still displayed honestly before the
    first scan writes the correction.
    """
    if active_ips is None:
        active_ips = await active_host_ips()
    rows = await db.fetch_all(
        "SELECT id, path_json FROM attack_paths WHERE is_active=1"
    ) or []
    stale = [
        row["id"] for row in rows
        if _field(row, "id") is not None
        and not path_is_live(_field(row, "path_json"), active_ips)
    ]
    if not stale:
        return 0
    try:
        placeholders = ",".join("?" for _ in stale)
        await db.execute(
            f"UPDATE attack_paths SET is_active=0 WHERE id IN ({placeholders})",
            tuple(stale),
        )
    except Exception as exc:
        logger.warning(f"[CHRONICLE] Could not retire stale attack paths: {exc}")
        return 0
    # Rules generated for a retired path no longer describe the network.
    # FORGE also does this on its next run; doing it here prevents the Forge
    # page and SENTINEL feed from enforcing a gone path in the meantime.
    try:
        placeholders = ",".join("?" for _ in stale)
        await db.execute(
            f"UPDATE forge_rules SET is_active=0 WHERE is_active=1 "
            f"AND attack_path_id IN ({placeholders})",
            tuple(stale),
        )
    except Exception as exc:
        logger.warning(f"[CHRONICLE] Could not retire rules for stale paths: {exc}")
    logger.info(
        f"[CHRONICLE] Retired {len(stale)} attack path(s) containing offline hosts"
    )
    return len(stale)
