import asyncio
import ipaddress
import os
import re
import subprocess

import shodan
from loguru import logger

from chronicle import db
from config.settings import osint as osint_cfg

# Hard ceiling on a single Shodan API call. The client is synchronous and runs
# in a worker thread; without this, one stuck connection freezes the scan.
SHODAN_TIMEOUT = 20.0

# Known MAC OUI prefixes for device identification
_MAC_VENDORS: dict[str, str] = {
    "00:11:22": "Apple",
    "00:25:00": "Apple",
    "3C:07:54": "Apple",
    "3C:22:FB": "Apple",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "00:03:FF": "Microsoft Hyper-V",
    "F0:1F:AF": "Dell",
    "00:1A:A0": "Dell",
    "14:58:D0": "HP",
    "3C:D9:2B": "HP",
    "00:0E:C6": "Cisco",
    "18:FE:34": "Espressif",
    "00:0C:42": "Netgear",
    "D8:1C:79": "Netgear",
    "A0:04:60": "Asus",
    "B0:6A:52": "Asus",
    "10:BF:48": "Asus",
    "04:F0:21": "Intel",
    "EC:B1:D7": "Intel",
    "00:60:2F": "Linux Device",
    "B8:27:EF": "Android Device",
    "EC:FA:BC": "Samsung",
    "24:18:1D": "Samsung",
    "00:E0:4C": "Realtek",
    "68:7A:B3": "ESP_XXXX (Espressif)",
    "24:0A:C4": "Espressif",
    "84:0D:8E": "Espressif",
    "74:83:C2": "Ubiquiti",
    "00:26:B9": "TP-Link",
    "50:C7:BF": "TP-Link",
    "14:CF:92": "T-Mobile",
    "E8:65:49": "Verizon",
    "10:17:A8": "IP Camera Device",
    "54:32:04": "Sonos",
    "58:BD:A3": "Roku",
    "00:FC:8B": "Amazon",
    "98:CD:AC": "Arris",
    "A8:1E:84": "Motorola",
}

# Optional operator-supplied MAC/OUI overrides, loaded from the documented
# OBSIDIOS_MAC_VENDORS file at import time.
def _normalise_mac(value: object) -> str:
    """Upper-case hex of a MAC/OUI, accepting colons, dashes and Cisco dots."""
    return re.sub(r"[^0-9A-F]", "", str(value or "").upper())


def _load_mac_vendors(path: str, table: dict[str, str] | None = None) -> int:
    """Merge operator MAC/OUI overrides; returns how many entries were accepted.

    Entries may be whitespace- or tab-separated and may be a full MAC rather
    than a three-byte OUI. The old loader accepted full-MAC prefixes but the
    lookup truncated every key to 8 characters, so those entries never matched.
    Operator entries are loaded after the built-ins, and `_lookup_mac_vendor`
    prefers the most specific (longest) prefix, so they override them.
    """
    target = _MAC_VENDORS if table is None else table
    added = 0
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                prefix = _normalise_mac(parts[0])
                vendor = parts[1].strip()
                if len(prefix) >= 6 and vendor:
                    target[parts[0].upper()] = vendor
                    added += 1
    except (OSError, UnicodeDecodeError):
        return 0
    return added


_ENV_MAC_FILE = os.environ.get("OBSIDIOS_MAC_VENDORS", "")
if _ENV_MAC_FILE:
    _load_mac_vendors(_ENV_MAC_FILE)


def _lookup_mac_vendor(mac: str, table: dict[str, str] | None = None) -> str | None:
    """Look up device vendor by MAC OUI (colons, dashes or Cisco dots).

    The longest matching prefix wins, and on a tie the later entry wins. That
    lets a full-MAC operator override beat the built-in six-hex OUI it starts
    with, and lets an operator re-declare an OUI to replace a built-in vendor.
    Returning the first match in insertion order silently ignored both.
    """
    key = _normalise_mac(mac)
    if len(key) < 6:
        return None
    vendor: str | None = None
    best_len = 0
    for prefix, candidate in (_MAC_VENDORS if table is None else table).items():
        normalised = _normalise_mac(prefix)
        if normalised and len(normalised) >= best_len and key.startswith(normalised):
            vendor = candidate
            best_len = len(normalised)
    return vendor


async def _store_finding(
    source: str, finding_type: str, target: str, detail: str, severity: str
) -> bool:
    """Record an OSINT finding once while it is still unremediated.

    Scanning an unchanged network used to insert the same row on every pass,
    so the posture score drifted purely with scan frequency and the table grew
    without bound.

    The existence check is part of the INSERT: a separate SELECT-then-INSERT
    let two overlapping scans (scheduled run plus a manual `trigger`) both see
    no row and insert duplicates, which double-counts the finding in the
    posture score.
    """
    row = await db.execute_returning(
        """INSERT INTO osint_findings (source, finding_type, target, detail, severity)
           SELECT ?, ?, ?, ?, ?
           WHERE NOT EXISTS (
               SELECT 1 FROM osint_findings
               WHERE source=? AND finding_type=? AND target=? AND detail=?
                 AND is_remediated=0
           )
           RETURNING id""",
        (source, finding_type, target, detail, severity,
         source, finding_type, target, detail),
    )
    return row is not None


def _reverse_dns(ip: str) -> str | None:
    """Resolve an address with nslookup (blocking — run it in an executor)."""
    try:
        result = subprocess.run(
            ["nslookup", ip],
            capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        # ISC/BIND nslookup prints "Name: host" while busybox prints
        # "name = host". The old pattern only understood the latter, so
        # reverse DNS never resolved on a standard Linux box.
        m = re.search(r'^\s*name\s*[:=]\s*(\S+)', line, re.IGNORECASE)
        if not m:
            continue
        # Some resolvers put the failure reason on a "Name:" line.
        name = m.group(1).rstrip(".")
        if name.upper() in {"NXDOMAIN", "NONEXISTENT", "UNKNOWN", "NONE"}:
            continue
        return name
    return None


async def _enrich_local_ip(ip: str) -> list[dict]:
    """Gather local intelligence for an internal IP: reverse DNS, DHCP, MAC vendor."""
    findings = []

    # Reverse DNS used to run synchronously inside the event loop: 200 internal
    # hosts × 5s timeout froze the dashboard for ~16 minutes. Offload it.
    try:
        hostname = await asyncio.get_running_loop().run_in_executor(
            None, _reverse_dns, ip
        )
    except Exception as exc:
        logger.debug(f"[IRIS/OSINT] Reverse DNS failed for {ip}: {exc}")
        hostname = None
    if hostname:
        findings.append({
            "source": "LOCAL_DNS",
            "finding_type": "REVERSE_DNS",
            "detail": f"Hostname: {hostname}",
            "severity": "INFO",
        })

    # Look up MAC and vendor from hosts table
    try:
        host_row = await db.fetch_one("SELECT mac FROM hosts WHERE ip=? AND mac IS NOT NULL", (ip,))
        if host_row and host_row["mac"]:
            mac = host_row["mac"].upper()
            vendor = _lookup_mac_vendor(mac)
            detail = f"MAC: {mac}"
            if vendor:
                detail += f", Vendor: {vendor}"
            findings.append({
                "source": "LOCAL_DB",
                "finding_type": "MAC_VENDOR",
                "detail": detail,
                "severity": "INFO",
            })
    except Exception:
        pass

    return findings


async def run_osint_scan(ip_list: list[str]):
    """
    Classify internal IPs and query Shodan for external exposure.
    Results are saved to osint_findings table.
    """
    logger.info(f"[IRIS/OSINT] Evaluating {len(ip_list)} hosts for OSINT...")
    
    api = shodan.Shodan(osint_cfg.shodan_api_key) if osint_cfg.shodan_api_key else None
    if not api:
        logger.debug("[IRIS/OSINT] Shodan API key not found. External scans will be skipped.")

    for ip in ip_list:
        try:
            # Reject anything that is not an IP before it can reach Shodan or
            # be counted as an internal asset.
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                logger.debug(f"[IRIS/OSINT] Skipping invalid address {ip!r}")
                continue

            # 1. Non-routable addresses (RFC1918, CGNAT, loopback, link-local,
            # documentation ranges) get local enrichment only. `is_private` is
            # the wrong test: it is False for 100.64.0.0/10 (CGNAT), which
            # must never be sent to Shodan.
            if not ip_obj.is_global:
                logger.debug(f"[IRIS/OSINT] {ip} is not globally routable. Enriching with local intel.")
                # Enrich with local network intelligence
                local_findings = await _enrich_local_ip(ip)
                if not local_findings:
                    # Fallback: just log as internal network
                    await _store_finding(
                        "LOCAL", "INTERNAL_NETWORK", ip,
                        "Private IP - No external info available", "INFO",
                    )
                for f in local_findings or []:
                    if not isinstance(f, dict):
                        continue
                    source = f.get("source")
                    finding_type = f.get("finding_type")
                    detail = f.get("detail")
                    if not (source and finding_type and detail):
                        continue
                    await _store_finding(
                        source, finding_type, ip, detail,
                        f.get("severity") or "INFO",
                    )
                continue

            # 2. External Scan (Only runs if API key is present and IP is not private)
            if not api:
                continue

            # Wrap blocking shodan call in run_in_executor. A hard timeout is
            # required: a hung HTTPS connection otherwise stalls the whole
            # scan pipeline (and the dashboard event loop it shares).
            loop = asyncio.get_running_loop()
            try:
                info = await asyncio.wait_for(
                    loop.run_in_executor(None, api.host, ip),
                    timeout=SHODAN_TIMEOUT,
                )
            except TimeoutError:
                logger.warning(
                    f"[IRIS/OSINT] Shodan lookup for {ip} timed out "
                    f"after {SHODAN_TIMEOUT:.0f}s")
                continue
            
            if info:
                # Shodan payloads are external data. A null/non-list `data`
                # or a non-dict banner used to abort the whole host, so one
                # malformed entry silently dropped every valid exposure.
                data = info.get("data", []) if isinstance(info, dict) else None
                if not isinstance(data, list):
                    logger.warning(
                        f"[IRIS/OSINT] Malformed Shodan response for {ip}; skipping")
                    continue
                stored = 0
                for item in data:
                    if not isinstance(item, dict):
                        logger.debug(
                            f"[IRIS/OSINT] Skipping malformed Shodan banner for {ip}")
                        continue
                    try:
                        port = int(item.get("port"))
                    except (TypeError, ValueError):
                        continue
                    if not 1 <= port <= 65535:
                        continue
                    transport = item.get("transport")
                    if not isinstance(transport, str) or not transport.strip():
                        transport = "unknown"
                    else:
                        transport = transport.strip().lower()
                    if await _store_finding(
                        "SHODAN", "EXTERNAL_EXPOSURE", ip,
                        f"Exposed Service: {transport}/{port}", "HIGH",
                    ):
                        stored += 1
                if stored:
                    logger.success(
                        f"[IRIS/OSINT] {stored} finding(s) recorded for {ip}")
                else:
                    logger.debug(f"[IRIS/OSINT] No new findings for {ip}")
        except shodan.APIError as e:
            if "No information available" not in str(e) and "Invalid IP" not in str(e):
                logger.warning(f"[IRIS/OSINT] Shodan error for {ip}: {e}")
        except Exception as e:
            logger.error(f"[IRIS/OSINT] OSINT error for {ip}: {e}")
