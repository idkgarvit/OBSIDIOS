import shodan
import asyncio
import ipaddress
import subprocess
import re
import os
from loguru import logger
from config.settings import osint as osint_cfg
from chronicle import db

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
    "18:FE:34": "Cisco",
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
    "18:FE:34": "Ubiquiti",
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

# Load custom MAC vendors from env file if present
_ENV_MAC_FILE = os.environ.get("OBSIDIOS_MAC_VENDORS", "")
if _ENV_MAC_FILE and os.path.exists(_ENV_MAC_FILE):
    try:
        with open(_ENV_MAC_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(" ", 1)
                if len(parts) == 2 and re.match(r'[0-9A-Fa-f:]{8,}', parts[0]):
                    _MAC_VENDORS[parts[0].upper()] = parts[1]
    except Exception:
        pass


def _lookup_mac_vendor(mac: str) -> str | None:
    """Look up device vendor by MAC OUI."""
    oui = mac.upper().strip().replace("-", ":")[:8]
    for prefix, vendor in _MAC_VENDORS.items():
        if oui.startswith(prefix):
            return vendor
    return None


async def _enrich_local_ip(ip: str) -> list[dict]:
    """Gather local intelligence for an internal IP: reverse DNS, DHCP, MAC vendor."""
    findings = []

    # Try reverse DNS
    try:
        result = subprocess.run(
            ["nslookup", ip],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                m = re.search(r'name\s*=\s*(\S+)\.?\s*$', line, re.IGNORECASE)
                if m:
                    hostname = m.group(1).rstrip(".")
                    findings.append({
                        "source": "LOCAL_DNS",
                        "finding_type": "REVERSE_DNS",
                        "detail": f"Hostname: {hostname}",
                        "severity": "INFO",
                    })
                    break
    except FileNotFoundError:
        pass
    except Exception:
        pass

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
            # 1. Private IP Check (Always runs)
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    logger.debug(f"[IRIS/OSINT] {ip} is a private IP. Enriching with local intel.")
                    # Enrich with local network intelligence
                    local_findings = await _enrich_local_ip(ip)
                    if not local_findings:
                        # Fallback: just log as internal network
                        await db.execute(
                            """INSERT INTO osint_findings (source, finding_type, target, detail, severity)
                               VALUES (?, ?, ?, ?, ?)""",
                            ("LOCAL", "INTERNAL_NETWORK", ip, "Private IP - No external info available", "INFO")
                        )
                    for f in local_findings:
                        await db.execute(
                            """INSERT INTO osint_findings (source, finding_type, target, detail, severity)
                               VALUES (?, ?, ?, ?, ?)""",
                            (f["source"], f["finding_type"], ip, f["detail"], f["severity"])
                        )
                    continue
            except ValueError:
                pass
            
            # 2. External Scan (Only runs if API key is present and IP is not private)
            if not api:
                continue

            # Wrap blocking shodan call in run_in_executor
            loop = asyncio.get_event_loop()
            info = await loop.run_in_executor(None, api.host, ip)
            
            if info:
                # Save findings
                for item in info.get("data", []):
                    port = item.get("port")
                    service = item.get("transport", "") + "/" + str(port)
                    
                    await db.execute(
                        """INSERT INTO osint_findings (source, finding_type, target, detail, severity)
                           VALUES (?, ?, ?, ?, ?)""",
                        ("SHODAN", "EXTERNAL_EXPOSURE", ip, f"Exposed Service: {service}", "HIGH")
                    )
                logger.success(f"[IRIS/OSINT] Findings recorded for {ip}")
        except shodan.APIError as e:
            if "No information available" not in str(e) and "Invalid IP" not in str(e):
                logger.warning(f"[IRIS/OSINT] Shodan error for {ip}: {e}")
        except Exception as e:
            logger.error(f"[IRIS/OSINT] OSINT error for {ip}: {e}")
