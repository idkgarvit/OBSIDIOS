"""
oracle/threat_intel.py
────────────────────────────
Threat intelligence lookups for OBSIDIOS.

Local, deterministic and auditable by default:
  • Optional operator-supplied blocklist/feed file (OBSIDIOS_THREAT_FEED_FILE)
  • Service exposure findings derived from the CVEs actually mapped to hosts
  • No fabricated "malicious IP" data — demo fixtures are opt-in only

The previous implementation shipped a hardcoded MOCK_THREAT_DATA dict and a
stub geolocation function, which could label real hosts as malicious (or safe)
for no reason. Enterprise deployments need evidence, not decoration.
"""
from __future__ import annotations

import ipaddress
import os
import time
from pathlib import Path
from typing import Any

from loguru import logger

from chronicle import db

# Opt-in only: keeps demo/tests working without polluting production verdicts.
_DEMO_FEED = {
    "10.0.0.1": {"reputation": "suspicious", "score": 45, "threats": ["botnet_c2", "spam"]},
    "192.168.1.100": {"reputation": "malicious", "score": 85, "threats": ["ransomware", "data_exfil"]},
}

_FEED_CACHE: dict[str, Any] = {"mtime": None, "path": None, "entries": {}}


def _demo_enabled() -> bool:
    return os.environ.get("OBSIDIOS_THREAT_INTEL_DEMO", "").strip().lower() in ("1", "true", "yes")


def _feed_path() -> Path | None:
    raw = os.environ.get("OBSIDIOS_THREAT_FEED_FILE", "").strip()
    return Path(raw).expanduser() if raw else None


def _load_feed() -> dict[str, dict[str, Any]]:
    """Load `ip[,score[,reputation]]` lines from the operator feed (cached)."""
    path = _feed_path()
    if path is None:
        return dict(_DEMO_FEED) if _demo_enabled() else {}
    try:
        mtime = path.stat().st_mtime
    except OSError:
        if _FEED_CACHE["path"] != str(path):
            logger.warning(f"[THREAT-INTEL] Feed file not readable: {path}")
        _FEED_CACHE.update({"mtime": None, "path": str(path), "entries": {}})
        return {}
    if _FEED_CACHE["path"] == str(path) and _FEED_CACHE["mtime"] == mtime:
        return _FEED_CACHE["entries"]

    entries: dict[str, dict[str, Any]] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(",")]
            try:
                ip = str(ipaddress.ip_address(parts[0]))
            except ValueError:
                continue
            score = 90
            reputation = "malicious"
            if len(parts) > 1 and parts[1]:
                try:
                    score = max(0, min(100, int(float(parts[1]))))
                except ValueError:
                    pass
            if len(parts) > 2 and parts[2]:
                reputation = parts[2][:32]
            entries[ip] = {"score": score, "reputation": reputation,
                           "threats": ["blocklist_match"]}
    except OSError as exc:
        logger.warning(f"[THREAT-INTEL] Could not read feed {path}: {exc}")
        return {}
    _FEED_CACHE.update({"mtime": mtime, "path": str(path), "entries": entries})
    logger.info(f"[THREAT-INTEL] Loaded {len(entries)} entries from {path}")
    return entries


async def check_threat_intel(ips: list[str]) -> dict[str, Any]:
    """Check IPs against the configured threat intelligence feed.

    Invalid and duplicate inputs are not counted as "clear" — that would make
    the coverage report claim checks that never happened.
    """
    results = []
    found_threats = 0
    invalid = 0
    normalized: list[str] = []
    seen: set[str] = set()

    for raw in ips or []:
        try:
            ip = str(ipaddress.ip_address(str(raw).strip()))
        except (ValueError, TypeError):
            invalid += 1
            continue
        if ip in seen:
            continue
        seen.add(ip)
        normalized.append(ip)

    for ip in normalized:
        threat_info = await _check_ip_threat(ip)
        if threat_info:
            results.append(threat_info)
            found_threats += 1

    feed_path = _feed_path()
    return {
        "total_checked": len(normalized),
        "threats_found": found_threats,
        "clear": len(normalized) - found_threats,
        "invalid": invalid,
        "results": results,
        "feed": str(feed_path) if feed_path else "none",
        "checked_at": time.time(),
    }


async def _check_ip_threat(ip: str) -> dict | None:
    """Check an individual IP against the local feed."""
    feed = _load_feed()
    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return None

    entry = feed.get(ip)
    if entry:
        return {
            "ip": ip,
            "reputation": entry.get("reputation", "malicious"),
            "score": entry.get("score", 90),
            "threat_types": entry.get("threats", []),
            "source": "feed",
            "action_required": True,
        }

    # Private addresses are never "threat intel" events on their own; local
    # feeds can still list them explicitly (handled above).
    return None


async def check_service_threats() -> dict[str, Any]:
    """Find exposed services that have CRITICAL/HIGH CVEs mapped in CHRONICLE."""
    rows = await db.fetch_all(
        """SELECT h.ip, p.service, p.version, p.port, p.protocol,
                  c.cve_id, c.cvss_v3, c.severity
           FROM port_cves pc
           JOIN ports p ON p.id = pc.port_id
           JOIN hosts h ON h.id = p.host_id
           JOIN cves c  ON c.id = pc.cve_id
           WHERE p.state='open' AND h.is_active=1
             AND COALESCE(pc.dismissed, 0) = 0
             AND COALESCE(pc.verified_status, '') != 'NOT_AFFECTED'
             AND c.severity IN ('CRITICAL', 'HIGH')
           ORDER BY COALESCE(c.cvss_v3, 0) DESC
           LIMIT 500"""
    )

    grouped: dict[tuple, dict[str, Any]] = {}
    for r in rows:
        key = (r["ip"], r["port"], r["protocol"], r["service"] or "")
        finding = grouped.setdefault(key, {
            "ip": r["ip"],
            "port": r["port"],
            "protocol": r["protocol"],
            "service": r["service"],
            "version": r["version"],
            "known_exploits": [],
            "risk": "MEDIUM",
        })
        if len(finding["known_exploits"]) < 5:
            finding["known_exploits"].append(r["cve_id"])
        if r["severity"] == "CRITICAL":
            finding["risk"] = "HIGH"

    findings = list(grouped.values())
    return {
        "service_count": len({(r["ip"], r["port"], r["protocol"]) for r in rows}),
        "vulnerable_services": len(findings),
        "findings": findings,
    }


async def get_threat_summary() -> dict:
    """Get overall threat intelligence summary."""

    total_hosts = await db.fetch_val('SELECT COUNT(*) FROM hosts WHERE is_active=1')
    open_ports = await db.fetch_val('SELECT COUNT(*) FROM ports WHERE state="open"')
    feed_size = len(_load_feed())

    recent_alerts = await db.fetch_val(
        "SELECT COUNT(*) FROM sentinel_alerts WHERE alerted_at > ?",
        (time.time() - 86400,)
    )

    return {
        'network_size': total_hosts,
        'exposed_services': open_ports,
        'recent_threats': recent_alerts,
        'feed_entries': feed_size,
        'feed_configured': _feed_path() is not None,
        'threat_level': 'HIGH' if recent_alerts > 10 else 'MEDIUM' if recent_alerts > 0 else 'LOW',
        'recommendation': 'Review alerts' if recent_alerts > 0 else 'Continue monitoring'
    }
