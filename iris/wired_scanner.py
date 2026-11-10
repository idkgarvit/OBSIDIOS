"""
iris/wired_scanner.py
IRIS wired network discovery: Dual-mode (Scapy + Nmap) aggressive discovery.
"""
from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import json
import logging
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import netifaces

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, Ether, srp
from scapy.all import conf as scapy_conf

scapy_conf.verb = 0
import nmap
from loguru import logger

from chronicle import db
from chronicle.models import Host, Port, ScanResult
from config.settings import scan as scan_cfg
from config.settings import validate_nmap_arguments, validate_target_cidr


async def get_target_from_db() -> str:
    try:
        if not db._initialized: await db.init()
        target = await db.fetch_val("SELECT value FROM system_settings WHERE key='target_network'", default="")
        return target if target else scan_cfg.target_network
    except: return scan_cfg.target_network


# The dashboard stores the selected profile in the DB, but the scanner used
# to read only the import-time environment value. Resolve the profile once per
# sweep and share it with every host task through a context variable.
_scan_args_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "obsidios_nmap_args", default=None)


async def _effective_nmap_args() -> str:
    """Return the nmap arguments for the next scan without a daemon restart.

    ``OBSIDIOS_NMAP_ARGS`` remains the final override. Otherwise the profile
    saved by the dashboard/CLI wins over the process start-up default, so
    ``config set-profile`` and the Network Config page take effect on the very
    next cycle.
    """
    if scan_cfg.nmap_arguments:
        return scan_cfg.active_nmap_args
    profile = ""
    try:
        if getattr(db, "_initialized", False):
            profile = await db.fetch_val(
                "SELECT value FROM system_settings WHERE key='scan_profile'",
                default="") or ""
    except Exception as exc:
        logger.warning(f"[IRIS] Could not read scan profile: {exc}")
    name = str(profile or scan_cfg.scan_profile).strip().upper()
    args = scan_cfg.SCAN_PROFILES.get(name)
    if not args:
        args = scan_cfg.SCAN_PROFILES.get(
            str(scan_cfg.scan_profile).strip().upper(),
            scan_cfg.SCAN_PROFILES["FAST"],
        )
    if scan_cfg.zombie_host:
        args = args.replace("ZOMBIE", scan_cfg.zombie_host)
    return args


async def _scan_cancelled(scan_id: int | None) -> bool:
    """True when the dashboard marked this scan CANCELLED while it ran."""
    if not scan_id:
        return False
    try:
        status = await db.fetch_val(
            "SELECT status FROM scans WHERE id=?", (scan_id,), default="")
        return status == "CANCELLED"
    except Exception:
        return False


_nmap_executor = ThreadPoolExecutor(max_workers=scan_cfg.scan_concurrency, thread_name_prefix="iris-nmap")

def _get_iface_for_network(network: str) -> str | None:
    try:
        target_net = ipaddress.ip_network(network, strict=False)
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                if ipaddress.ip_address(addr['addr']) in target_net: return iface
    except: pass
    return None

def _arp_sweep(network: str, timeout: float) -> list[dict[str, str]]:
    iface = _get_iface_for_network(network)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    target_iface = iface or scapy_conf.iface
    answered, _ = srp(pkt, iface=target_iface, timeout=timeout, retry=2, verbose=False)
    return [{"ip": r.psrc, "mac": r.hwsrc.upper()} for _, r in answered]

async def discover_hosts(network: str) -> list[dict[str, str]]:
    # Defence in depth: callers such as the fast pulse loop read the target
    # from the DB, so validate here as well as in run_scan().
    ok, reason = validate_target_cidr(network)
    if not ok:
        logger.error(f"[IRIS] Refusing discovery of {network!r}: {reason}")
        return []

    loop = asyncio.get_running_loop()
    logger.info(f"[IRIS] Host discovery starting → {network}")
    t0 = time.perf_counter()
    
    # Run ARP sweep + nmap ping sweep in parallel
    def _nmap_sweep(net: str):
        nm = nmap.PortScanner()
        args = "-sn -PE -PS22,80,443,445,3306,3389 -PA80,443 --min-parallelism 100"
        nm.scan(hosts=net, arguments=args)
        return nm
    
    arp_fut = loop.run_in_executor(_nmap_executor, _arp_sweep, network, 3.0)
    nmap_fut = loop.run_in_executor(_nmap_executor, _nmap_sweep, network)
    
    # One discovery source failing (no root for ARP, nmap not installed) must
    # not abort the scan when the other source still works.
    arp_results, nmap_result = await asyncio.gather(
        arp_fut, nmap_fut, return_exceptions=True
    )

    if isinstance(arp_results, BaseException):
        logger.warning(f"[IRIS] ARP sweep failed: {arp_results}")
        arp_results = []
    if isinstance(nmap_result, BaseException):
        logger.warning(f"[IRIS] nmap sweep failed: {nmap_result}")
        nmap_result = None

    hosts_dict = {h['ip']: h['mac'] for h in arp_results}
    if nmap_result is not None:
        for ip in nmap_result.all_hosts():
            # One malformed python-nmap record (missing addresses block, node
            # in a weird state) must not discard the hosts found before it.
            try:
                entry = nmap_result[ip]
                if entry.state() != 'up' or ip in hosts_dict:
                    continue
                addresses = entry['addresses'] or {}
                hosts_dict[ip] = (addresses.get('mac') or 'UNKNOWN').upper()
            except Exception as exc:
                logger.debug(f"[IRIS] Skipping nmap entry {ip!r}: {exc}")
                continue
                
    results = [{"ip": ip, "mac": mac} for ip, mac in hosts_dict.items()]
    logger.success(f"[IRIS] Discovery complete: {len(results)} hosts found in {time.perf_counter()-t0:.2f}s")
    return results

# ── Adaptive Port Scanning: Host Type Detection ──────────────────────────
HOST_TYPE_RULES = {
    "web_server":  {80, 443, 8080, 8443, 3000, 5000},
    "database":    {3306, 5432, 27017, 6379, 1433, 1521, 5984},
    "file_share":  {445, 139, 21, 20, 2049},
    "email":       {25, 110, 143, 993, 995, 587},
    "iot_embedded":{161, 8443, 8883, 5353, 502},
}

DEEP_SCAN_PORTS = {
    "web_server":  [8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8181, 8280, 8443, 8888, 9000, 9090, 9200, 9443, 3000, 3001, 4000, 5000, 5601],
    "database":    [1433, 1434, 1521, 3306, 3307, 5432, 5433, 6379, 7001, 7002, 9042, 9160, 9200, 9300, 9306, 27017, 27018, 27019, 28015, 5984],
    "file_share":  [135, 139, 445, 2049, 111, 513, 514, 636, 1389, 3268, 3269, 88, 464, 749, 751, 752, 753, 754],
    "email":       [25, 110, 143, 465, 587, 993, 995, 2525, 3535, 8025],
    "iot_embedded":[502, 503, 5353, 8443, 8883, 161, 162, 5683, 5684, 9001, 9002, 1883, 2883, 8083],
    "default":     [22, 23, 80, 443, 445, 3389, 8080, 8443, 2222, 5555, 6379, 27017],
}

def _detect_host_type(open_ports: list[int]) -> list[str]:
    port_set = set(open_ports)
    detected = []
    for htype, sig_ports in HOST_TYPE_RULES.items():
        if port_set & sig_ports:
            detected.append(htype)
    return detected or ["default"]


def _as_text(value, limit: int = 255) -> str:
    """Coerce XML-derived nmap fields to a bounded string."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value.strip()[:limit]


def _parse_open_ports(host) -> list[dict]:
    """Extract open ports from a python-nmap host result.

    The structure is decoded from nmap XML, so a single malformed protocol or
    port record must be skipped rather than raising away every port on the
    host (and turning a partially successful scan into no scan at all).
    """
    try:
        protocols = host.all_protocols()
    except Exception:
        return []

    ports: list[dict] = []
    for proto in protocols:
        if proto not in ("tcp", "udp", "sctp"):
            continue
        try:
            entries = host[proto]
        except Exception:
            continue
        if not isinstance(entries, dict):
            continue
        try:
            port_numbers = sorted(entries)
        except TypeError:
            continue

        for port in port_numbers:
            if not isinstance(port, int) or isinstance(port, bool):
                continue
            entry = entries[port]
            if not isinstance(entry, dict) or entry.get("state") != "open":
                continue
            ports.append({
                "port": port,
                "protocol": proto,
                "state": "open",
                "service": _as_text(entry.get("name")),
                "product": _as_text(entry.get("product")),
                "version": _as_text(entry.get("version")),
                "extra_info": _as_text(entry.get("extrainfo")),
                "cpe": _as_text(entry.get("cpe")),
            })
    return ports


def _nmap_scan_host(ip: str, args: str) -> dict:
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments=args)
    if ip not in nm.all_hosts(): return {}
    h = nm[ip]
    try:
        hostname = h.hostname()
    except Exception:
        hostname = ""
    try:
        state = h.state()
    except Exception:
        state = "unknown"
    res = {"ip":ip,"hostname":hostname,"state":state,"os":[],"ports":[],"host_types":[]}
    if "osmatch" in h:
        for m in h["osmatch"]:
            if not isinstance(m, dict) or not m.get("name"):
                continue
            # python-nmap reports accuracy as a string ("100") but the field
            # is absent on some matches; the old int() raised KeyError/ValueError
            # and discarded every port on the host.
            try:
                accuracy = int(str(m.get("accuracy", 0)).strip())
            except (TypeError, ValueError):
                accuracy = 0
            res["os"].append({"name": _as_text(m["name"], 128), "accuracy": accuracy})
    res["ports"] = _parse_open_ports(h)
    return res

def _nmap_deep_scan(ip: str, extra_ports: list[int]) -> list[dict]:
    """Second-pass targeted scan for host-type-specific ports."""
    if not extra_ports: return []
    port_str = ",".join(str(p) for p in sorted(set(extra_ports)))
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments=f"-sV -T4 --min-parallelism 10 --max-retries 1 -p {port_str}")
    if ip not in nm.all_hosts(): return []
    return _parse_open_ports(nm[ip])

async def scan_host(ip: str, sem: asyncio.Semaphore) -> dict:
    async with sem:
        args = _scan_args_ctx.get()
        if args is None:
            args = await _effective_nmap_args()
        if not validate_nmap_arguments(args)[0]:
            logger.error("[IRIS] Refusing to run scan with unsafe nmap arguments")
            return {}
        result = await asyncio.get_running_loop().run_in_executor(_nmap_executor, _nmap_scan_host, ip, args)
        if not result: return result
        # Adaptive second pass: detect host type and deep-scan. Entries are
        # normally produced by _parse_open_ports, but a scanner wrapper or a
        # future backend can hand back anything; junk must not fail the host.
        open_port_nums = [
            p["port"] for p in (result.get("ports") or [])
            if isinstance(p, dict)
            and isinstance(p.get("port"), int)
            and not isinstance(p.get("port"), bool)
        ]
        host_types = _detect_host_type(open_port_nums)
        result["host_types"] = host_types
        extra_ports = []
        already_scanned = set(open_port_nums)
        for ht in host_types:
            for p in DEEP_SCAN_PORTS.get(ht, []):
                if p not in already_scanned:
                    extra_ports.append(p)
                    already_scanned.add(p)
        if extra_ports:
            logger.info(f"[IRIS] Adaptive deep-scan {ip}: {host_types} → scanning {len(extra_ports)} extra ports")
            deep_ports = await asyncio.get_running_loop().run_in_executor(_nmap_executor, _nmap_deep_scan, ip, extra_ports)
            existing = {
                p["port"] for p in (result.get("ports") or [])
                if isinstance(p, dict)
                and isinstance(p.get("port"), int)
                and not isinstance(p.get("port"), bool)
            }
            for dp in deep_ports:
                if isinstance(dp, dict) and dp.get("port") not in existing:
                    result["ports"].append(dp)
        return result

async def scan_hosts_concurrent(hosts: list[dict]) -> list[dict]:
    # Discovery normally returns well-formed records, but this is also the
    # seam a test/alternate backend plugs into; a junk entry must not abort
    # every other host's scan.
    targets = [
        h for h in hosts
        if isinstance(h, dict) and isinstance(h.get("ip"), str) and h["ip"].strip()
    ]
    if not targets: return []
    sem = asyncio.Semaphore(scan_cfg.scan_concurrency)
    token = _scan_args_ctx.set(await _effective_nmap_args())
    try:
        results = await asyncio.gather(*[scan_host(h["ip"], sem) for h in targets], return_exceptions=True)
    finally:
        _scan_args_ctx.reset(token)
    ok = []
    for host, result in zip(targets, results, strict=True):
        if isinstance(result, BaseException):
            logger.warning(f"[IRIS] Port scan failed for {host.get('ip')}: {result}")
        elif isinstance(result, dict) and result:
            ok.append(result)
    return ok

# Known MAC OUIs strongly associated with mobile devices
# Nmap OS detection is unreliable for these — override with MAC-based guess
_MOBILE_MAC_PREFIXES: dict[str, str] = {
    "3C:07:54": "Apple iOS",
    "3C:22:FB": "Apple iOS",
    "00:25:00": "Apple iOS",
    "EC:FA:BC": "Android",
    "24:18:1D": "Android",
    "B8:27:EF": "Android",
    "14:CF:92": "Android",
    "10:17:A8": "IP Camera",
    "54:32:04": "Sonos Device",
    "58:BD:A3": "Roku Device",
    "00:FC:8B": "Amazon Device",
}

def _first_os_entry(value) -> dict | None:
    """Return the first OS match from scanner output, tolerating junk shapes."""
    if isinstance(value, list):
        first = value[0] if value else None
        return first if isinstance(first, dict) else None
    return value if isinstance(value, dict) else None


def _infer_os_from_mac(mac: str, nmap_os: str | None, nmap_acc: int | None) -> tuple[str | None, int | None]:
    """Override Nmap OS guess when MAC vendor indicates mobile/embedded and Nmap is uncertain."""
    if not mac:
        return nmap_os, nmap_acc
    oui = mac.upper().strip().replace("-", ":")[:8]
    mac_os = None
    for prefix, device_os in _MOBILE_MAC_PREFIXES.items():
        if oui.startswith(prefix):
            mac_os = device_os
            break
    if not mac_os:
        return nmap_os, nmap_acc
    try:
        accuracy = max(int(nmap_acc), 0)
    except (TypeError, ValueError):
        accuracy = 0
    if accuracy >= 80:
        return nmap_os, accuracy
    return mac_os, min(accuracy, 30)

async def _upsert_hosts(arp_hosts: list[dict], scan_data: list[dict]) -> dict[str, int]:
    now, host_id_map = time.time(), {}

    def _valid(records):
        for record in records or []:
            if not isinstance(record, dict):
                continue
            ip = record.get("ip")
            if isinstance(ip, str) and ip.strip():
                yield record

    nmap_by_ip = {r["ip"]: r for r in _valid(scan_data)}
    mac_by_ip = {h["ip"]: h.get("mac") for h in _valid(arp_hosts)}
    # A routed host can appear in the nmap sweep without an ARP reply; it must
    # still be persisted. Union both discovery sources instead of ARP only.
    all_ips = sorted(set(mac_by_ip) | set(nmap_by_ip))
    for ip in all_ips:
        raw_mac = mac_by_ip.get(ip)
        mac = raw_mac.strip() if isinstance(raw_mac, str) and raw_mac.strip() else None
        nd = nmap_by_ip.get(ip, {}); os_name = os_acc = None
        first = _first_os_entry(nd.get("os"))
        if first:
            os_name, os_acc = first.get("name"), first.get("accuracy")
        if mac:
            os_name, os_acc = _infer_os_from_mac(mac, os_name, os_acc)
        row = await db.execute_returning("INSERT INTO hosts (ip,mac,hostname,os_name,os_accuracy,is_active,last_seen,offline_since) VALUES (?,?,?,?,?,1,?,NULL) ON CONFLICT(ip) DO UPDATE SET mac=COALESCE(excluded.mac, mac), hostname=COALESCE(NULLIF(excluded.hostname,''), hostname), os_name=COALESCE(excluded.os_name, os_name), last_seen=excluded.last_seen, is_active=1, offline_since=NULL RETURNING id", (ip, mac if mac and mac.upper() != 'UNKNOWN' else None, nd.get("hostname"), os_name, os_acc, now))
        if row: host_id_map[ip] = row["id"]
    return host_id_map


def _fast_offline_grace_seconds() -> int:
    raw = os.environ.get("OBSIDIOS_FAST_OFFLINE_GRACE_SECONDS", "120").strip()
    try:
        return max(0, int(raw))
    except ValueError:
        logger.warning(f"[IRIS/FAST] Invalid grace {raw!r}; using 120s")
        return 120


def _offline_grace_seconds() -> float:
    """How long a host may be unseen before it is marked offline.

    Defaults to 1.5x the configured scan interval, so one missed ARP sweep
    does not flap a live asset (and does not generate a false GONE_HOST diff).
    """
    raw = os.environ.get("OBSIDIOS_OFFLINE_GRACE_SECONDS", "").strip()
    if raw:
        try:
            return max(0.0, float(raw))
        except ValueError:
            logger.warning(f"[IRIS] Invalid OBSIDIOS_OFFLINE_GRACE_SECONDS={raw!r}; using default")
    return max(300.0, float(scan_cfg.scan_interval_seconds) * 1.5)


async def _mark_missing_hosts_offline(seen_ips: list[str], grace: float | None = None) -> int:
    """Mark hosts unseen beyond the grace window offline (records when)."""
    if not seen_ips:
        return 0
    grace = _offline_grace_seconds() if grace is None else grace
    cutoff = time.time() - grace
    # json_each avoids SQLite's bound-variable limit on large ranges (/16).
    seen_json = json.dumps(seen_ips)
    try:
        count = await db.fetch_val(
            "SELECT COUNT(*) FROM hosts WHERE is_active=1 "
            "AND last_seen < ? AND ip NOT IN (SELECT value FROM json_each(?))",
            (cutoff, seen_json), default=0,
        )
        if not count:
            return 0
        await db.execute(
            "UPDATE hosts SET is_active=0, offline_since=? "
            "WHERE is_active=1 AND last_seen < ? "
            "AND ip NOT IN (SELECT value FROM json_each(?))",
            (time.time(), cutoff, seen_json),
        )
        return int(count)
    except Exception as exc:
        logger.warning(f"[IRIS] Could not update host offline state: {exc}")
        return 0

async def _upsert_ports(scan_data: list[dict], host_id_map: dict[str, int], scan_started: float | None = None) -> int:
    now, rows = time.time(), []
    for nd in scan_data:
        if not isinstance(nd, dict):
            continue
        ip = nd.get("ip")
        if not isinstance(ip, str):
            continue
        hid = host_id_map.get(ip)
        if not hid:
            continue
        for p in nd.get("ports") or []:
            if not isinstance(p, dict):
                continue
            port = p.get("port")
            if not isinstance(port, int) or isinstance(port, bool):
                continue
            rows.append((
                hid, port, p.get("protocol") or "tcp", p.get("state") or "open",
                p.get("service"), p.get("product"), p.get("version"),
                p.get("extra_info"), p.get("cpe"), now, now,
            ))
    if rows:
        await db.executemany(
            "INSERT INTO ports (host_id,port,protocol,state,service,product,version,extra_info,cpe,first_seen,last_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(host_id,port,protocol) DO UPDATE SET "
            "state=excluded.state, "
            "service=COALESCE(NULLIF(excluded.service,''),service), "
            "product=COALESCE(NULLIF(excluded.product,''),product), "
            "version=COALESCE(NULLIF(excluded.version,''),version), "
            # A CPE/extra-info discovered by a later scan used to be dropped
            # forever because only the INSERT carried it.
            "extra_info=COALESCE(NULLIF(excluded.extra_info,''),extra_info), "
            "cpe=COALESCE(NULLIF(excluded.cpe,''),cpe), "
            "last_seen=excluded.last_seen",
            rows,
        )

    # Ports that were open before this scan but were not seen now are closed.
    # Without this, CVEs on dead services keep inflating posture forever.
    #
    # Only hosts whose nmap scan actually produced a result are reconciled. A
    # host that answered ARP but whose port scan errored is still in
    # `host_id_map`; closing its ports would make its CVEs vanish on a
    # transient scanner failure. No observation is not the same as "closed".
    if host_id_map and scan_started:
        scanned_host_ids: set[int] = set()
        for nd in scan_data:
            if not isinstance(nd, dict):
                continue
            ip = nd.get("ip")
            if isinstance(ip, str) and ip in host_id_map:
                scanned_host_ids.add(host_id_map[ip])
        if scanned_host_ids:
            await db.execute(
                "UPDATE ports SET state='closed' WHERE state='open' "
                "AND host_id IN (SELECT value FROM json_each(?)) AND last_seen < ?",
                (json.dumps(sorted(scanned_host_ids)), scan_started),
            )
    return len(rows)


def _classify_wireless_threat(bssid: str | None, ssid: str, encryption: str, signal: int | None, known_networks: dict[str, str]) -> str:
    """Classify wireless threat type based on signal, encryption, and known networks."""
    if encryption == "OPEN":
        return "OPEN_NETWORK"
    if bssid and bssid in known_networks:
        previous_ssid = known_networks.get(bssid) or ""
        # Same BSSID advertising a different SSID — possible evil twin.
        # Previously every known BSSID was flagged on its second sighting.
        if previous_ssid and ssid and previous_ssid != ssid:
            return "EVIL_TWIN"
    if signal is not None and signal > -50:
        # Very strong signal from outside network — possible rogue AP
        return "ROGUE_AP"
    if ssid == "Hidden":
        return "HIDDEN_NETWORK"
    return "ENCRYPTED_NETWORK"


_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
# A busy network can have thousands of ARP entries; the display and the DB do
# not benefit from storing all of them on every scan.
_MAX_WIRELESS_CLIENTS = 500


def _is_unicast_mac(mac: str) -> bool:
    """False for broadcast/multicast MACs (first octet's low bit set)."""
    try:
        return not (int(mac.split(":", 1)[0], 16) & 1)
    except (ValueError, IndexError):
        return False


def _scan_wireless_clients(iface: str) -> list[dict]:
    """Detect wireless client stations via iw station dump + ARP table."""
    clients: list[dict] = []
    seen: set[str] = set()

    def add(mac: str, signal, ip, source: str) -> None:
        mac = mac.upper()
        if len(clients) >= _MAX_WIRELESS_CLIENTS:
            return
        if mac in seen or not _is_unicast_mac(mac):
            return
        if mac.startswith("00:00:00"):
            return
        seen.add(mac)
        clients.append({"mac": mac, "signal": signal, "ip": ip, "source": source})

    try:
        # Method 1: iw station dump (works if interface in AP mode)
        result = subprocess.run(
            ["iw", "dev", iface, "station", "dump"],
            capture_output=True, text=True, timeout=10
        )
        for block in result.stdout.split("Station "):
            if not block.strip():
                continue
            mac_m = _MAC_RE.search(block)
            sig_m = re.search(r'signal:.*?(-?\d+)', block)
            if mac_m:
                add(mac_m.group(0), int(sig_m.group(1)) if sig_m else None,
                    None, "iw_station_dump")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    except Exception:
        pass

    # Method 2: ARP cache (works in any mode — finds active talkers on the subnet)
    try:
        result = subprocess.run(
            ["arp", "-n"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            mac_m = next((_MAC_RE.fullmatch(p) for p in parts if _MAC_RE.fullmatch(p)), None)
            if not mac_m:
                continue
            ip_m = next((p for p in parts if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", p)), None)
            add(mac_m.group(0), None, ip_m, "arp_cache")
    except FileNotFoundError:
        pass
    except Exception:
        pass

    return clients


async def run_wireless_scan():
    # Module-level `db`/`scan_cfg` are used deliberately: re-importing them
    # here shadowed the module globals, which made the scan untestable and
    # hid configuration overrides.
    if not scan_cfg.enable_wireless:
        return
    iface = scan_cfg.wireless_interface
    # Auto-detect wireless interface if configured one doesn't exist
    try:
        # Offload blocking `ip`/`iw` calls: this coroutine runs on the shared
        # dashboard event loop, and a blocking scan would stall every request.
        r = await asyncio.to_thread(
            subprocess.run, ["iw", "dev"], capture_output=True, text=True, timeout=5
        )
        detected = re.findall(r'Interface\s+(\S+)', r.stdout)
        if iface not in detected and detected:
            iface = detected[0]
            logger.info(f"[WIRELESS] Auto-detected interface {iface} (configured {scan_cfg.wireless_interface} not found)")
    except Exception:
        pass
    # Get known BSSID→SSID mapping from previous scans to detect evil twin.
    # A read failure must not abort the scan (and the scheduler loop with it).
    try:
        prev_rows = await db.fetch_all(
            """SELECT bssid, ssid FROM wireless_threats
               WHERE bssid IS NOT NULL AND threat_type != 'CLIENT_DEVICE'
               ORDER BY detected_at DESC LIMIT 1000"""
        )
    except Exception as exc:
        logger.warning(f"[WIRELESS] Could not load previous BSSIDs: {exc}")
        prev_rows = []
    known_networks: dict[str, str] = {}
    for r in (prev_rows or []):
        known_networks.setdefault(r["bssid"], r["ssid"] or "")

    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["iw", "dev", iface, "scan"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0 or not result.stdout:
            logger.warning(f"[WIRELESS] No scan results on {iface}: {result.stderr.strip()}")
        else:
            now = time.time()
            # Mark the previous AP snapshot inactive; this scan is authoritative.
            await db.execute(
                "UPDATE wireless_threats SET is_active=0 WHERE threat_type != 'CLIENT_DEVICE'"
            )
            for block in result.stdout.split("BSS "):
                if not block.strip():
                    continue
                bssid_m = re.search(r'([0-9a-fA-F:]{17})', block)
                ssid_m = re.search(r'SSID: (.+)', block)
                sig_m = re.search(r'signal: (-?\d+)', block)
                chan_m = re.search(r'channel (\d+)', block)
                bssid = bssid_m.group(1) if bssid_m else None
                ssid = ssid_m.group(1).strip() if ssid_m else "Hidden"
                signal = int(sig_m.group(1)) if sig_m else None
                channel = int(chan_m.group(1)) if chan_m else None
                if "RSN:" in block:
                    encryption = "WPA2/WPA3"
                elif "WPA:" in block:
                    encryption = "WPA"
                else:
                    encryption = "OPEN"
                threat_type = _classify_wireless_threat(bssid, ssid, encryption, signal, known_networks)
                await db.execute(
                    "INSERT INTO wireless_threats (detected_at, threat_type, bssid, ssid, channel, signal_strength, encryption, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (now, threat_type, bssid, ssid, channel, signal, encryption,
                     f"Signal: {signal}dBm, Encryption: {encryption}" if signal else f"Encryption: {encryption}")
                )
                if threat_type in ("EVIL_TWIN", "ROGUE_AP", "OPEN_NETWORK"):
                    # A dead notifier must not abort the rest of the AP scan.
                    try:
                        from alerts.notifier import buffer_alert
                        await buffer_alert(
                            category="wireless",
                            title=f"📡 {threat_type}",
                            message=f"**SSID:** `{ssid}`\n**BSSID:** `{bssid}`\n**Signal:** {signal}dBm · **Ch:** {channel}",
                            color="high",
                        )
                    except Exception as exc:
                        logger.warning(f"[WIRELESS] Alert buffering failed: {exc}")
            logger.info(f"[WIRELESS] Scan complete: found APs on {iface}")

        # Scan for wireless clients (phones, TVs, IoT)
        clients = await asyncio.to_thread(_scan_wireless_clients, iface)
        if clients:
            now = time.time()
            await db.execute(
                "UPDATE wireless_threats SET is_active=0 WHERE threat_type='CLIENT_DEVICE'"
            )
            for client in clients:
                detail = f"MAC: {client['mac']}"
                if client.get("ip"):
                    detail += f", IP: {client['ip']}"
                if client.get("signal"):
                    detail += f", Signal: {client['signal']}dBm"
                detail += f", Source: {client.get('source', 'unknown')}"
                await db.execute(
                    "INSERT INTO wireless_threats (detected_at, threat_type, bssid, signal_strength, detail) VALUES (?, ?, ?, ?, ?)",
                    (now, "CLIENT_DEVICE", client["mac"], client.get("signal"), detail)
                )
            logger.info(f"[WIRELESS] Found {len(clients)} client device(s) on {iface}")

        # Every scan writes a fresh snapshot and retires the previous one, so
        # an instance scanning every few minutes accumulates rows forever.
        # Keep a month of history, bounded independently of the operator's
        # retention setting so the table cannot grow without limit.
        try:
            await db.execute(
                "DELETE FROM wireless_threats WHERE is_active=0 AND detected_at < ?",
                (time.time() - 30 * 86400,),
            )
        except Exception as exc:
            logger.warning(f"[WIRELESS] Could not prune old wireless rows: {exc}")

    except FileNotFoundError:
        logger.warning("[WIRELESS] `iw` not found — no wireless scanning available")
    except subprocess.TimeoutExpired:
        logger.warning(f"[WIRELESS] Scan timed out on {iface}")
    except Exception as e:
        logger.warning(f"[WIRELESS] Scan failed: {e}")

async def _notify_safe(**kwargs) -> None:
    """Best-effort notification; a webhook failure must not change scan state."""
    try:
        from alerts.notifier import send_alert

        await send_alert(**kwargs)
    except Exception as exc:
        logger.warning(f"[IRIS] Notification failed: {exc}")


async def run_scan(network: str | None = None) -> ScanResult:
    target = network or await get_target_from_db()
    started = time.time()
    res = ScanResult(target=target, started_at=started)

    # Never let a CLI/API caller scan outside the approved target scope.
    ok, reason = validate_target_cidr(target)
    if not ok:
        logger.error(f"[IRIS] Refusing scan of {target!r}: {reason}")
        res.errors.append(f"unsafe target: {reason}")
        return res
    args_ok, args_reason = validate_nmap_arguments(await _effective_nmap_args())
    if not args_ok:
        logger.error(f"[IRIS] Refusing scan: {args_reason}")
        res.errors.append(f"unsafe nmap arguments: {args_reason}")
        return res

    scan_row = await db.execute_returning("INSERT INTO scans (scan_type,target,started_at,status) VALUES (?,?,?,'RUNNING') RETURNING id", ("FULL", target, started))
    scan_id = scan_row["id"] if scan_row else None
    res.scan_id = scan_id
    try:
        hosts = await discover_hosts(target)
        if not hosts:
            res.errors.append("no hosts discovered")
            if scan_id:
                # Do not leave the scan row RUNNING forever just because the
                # sweep was empty.
                await db.execute(
                    "UPDATE scans SET finished_at=?, hosts_found=0, ports_found=0, status='DONE' WHERE id=?",
                    (time.time(), scan_id),
                )
            return res

        if await _scan_cancelled(scan_id):
            res.errors.append("scan cancelled by operator")
            logger.warning(f"[IRIS] Scan {scan_id} cancelled before host scanning")
            await _notify_safe(
                title="⛔ **Scan Cancelled**",
                message=f"Scan **#{scan_id}** was cancelled before host scanning",
                color="medium", footer="OBSIDIOS v2.0")
            return res

        scan_data = await scan_hosts_concurrent(hosts)

        # The operator asked to stop; do not persist a partial sweep as if it
        # were the authoritative current state.
        if await _scan_cancelled(scan_id):
            res.errors.append("scan cancelled by operator")
            logger.warning(f"[IRIS] Scan {scan_id} cancelled — discarding results")
            await _notify_safe(
                title="⛔ **Scan Cancelled**",
                message=f"Scan **#{scan_id}** was cancelled mid-execution; partial results discarded",
                color="medium", footer="OBSIDIOS v2.0")
            return res

        host_id_map = await _upsert_hosts(hosts, scan_data)
        ports_found = await _upsert_ports(scan_data, host_id_map, started)
        # Mark offline only after the grace window — one missed sweep is not proof.
        ips = [
            h["ip"] for h in hosts
            if isinstance(h, dict) and isinstance(h.get("ip"), str) and h["ip"]
        ]
        if ips:
            await _mark_missing_hosts_offline(ips)
        for nd in scan_data:
            if not isinstance(nd, dict):
                continue
            ip = nd.get("ip")
            if not isinstance(ip, str):
                continue
            hid = host_id_map.get(ip)
            if hid is None:
                # The host row could not be written (locked DB, constraint);
                # reporting it with no id crashes Port's validation and turns
                # a partial success into a "scan failed".
                logger.warning(f"[IRIS] No host id for {ip} — skipping result")
                continue
            os_first = _first_os_entry(nd.get("os")) or {}
            res.hosts.append(Host(
                id=hid, ip=ip, hostname=nd.get("hostname"),
                os_name=os_first.get("name"),
            ))
            ports_raw = nd.get("ports")
            if not isinstance(ports_raw, list):
                ports_raw = []
            port_objs = []
            for p in ports_raw:
                if not isinstance(p, dict):
                    logger.warning(f"[IRIS] Skipping malformed port for {ip}")
                    continue
                try:
                    port_objs.append(Port(host_id=hid, **p))
                except Exception as exc:
                    logger.warning(f"[IRIS] Skipping malformed port for {ip}: {exc}")
            if port_objs:
                res.ports[ip] = port_objs
        if scan_id:
            cancelled = await db.fetch_val("SELECT status FROM scans WHERE id=?", (scan_id,), default='')
            if cancelled == 'CANCELLED':
                logger.warning(f"[IRIS] Scan {scan_id} was cancelled — skipping DONE update")
                await _notify_safe(title="⛔ **Scan Cancelled**", message=f"Scan **#{scan_id}** was cancelled mid-execution", color="medium", footer="OBSIDIOS v2.0")
            else:
                await db.execute("UPDATE scans SET finished_at=?, hosts_found=?, ports_found=?, status='DONE' WHERE id=?", (time.time(), len(res.hosts), ports_found, scan_id))
    except Exception as e:
        logger.exception(f"[IRIS] Scan failed: {e}")
        # Callers (CLI trigger, scheduled task, scan_cycle) can only tell a
        # scan failed if the exception is reflected in the result.
        res.errors.append(str(e)[:500])
        if scan_id:
            # A failing bookkeeping write must not replace the original error
            # with a confusing second traceback (and skip the notification).
            try:
                await db.execute(
                    "UPDATE scans SET status='FAILED', error=? WHERE id=?",
                    (str(e), scan_id),
                )
            except Exception as db_exc:
                logger.error(f"[IRIS] Could not mark scan {scan_id} failed: {db_exc}")
        await _notify_safe(title="❌ **Scan Failed**", message=f"Scan **#{scan_id}** encountered an error:\n```{str(e)[:500]}```", color="critical", footer="OBSIDIOS v2.0")
    return res

async def compute_scan_diff(cur_id: int, prev_id: int | None = None) -> list[dict]:
    if not prev_id: return []
    cur = await db.fetch_one("SELECT started_at FROM scans WHERE id=?", (cur_id,))
    prev = await db.fetch_one("SELECT started_at FROM scans WHERE id=?", (prev_id,))
    if not cur or not prev: return []
    
    c_start = cur["started_at"]
    p_start = prev["started_at"]
    # Both columns default to a value, but a manually edited/legacy row can be
    # NULL; subtracting None raised TypeError and broke the diff entirely.
    if c_start is None or p_start is None:
        return []
    
    new_hosts = await db.fetch_all("SELECT id, ip FROM hosts WHERE first_seen >= ?", (c_start - 60,))
    # A host that stays offline stays inside the window on every following
    # scan, so the same outage was reported again and again (manual scans and
    # overlapping scheduled scans made the timeline repeat GONE_HOST rows).
    # Only report the transition that has not been recorded since it happened.
    gone_hosts = await db.fetch_all(
        """SELECT h.id, h.ip FROM hosts h
           WHERE h.is_active=0 AND h.offline_since IS NOT NULL
             AND h.offline_since >= ?
             AND NOT EXISTS (
                 SELECT 1 FROM scan_diffs d
                 WHERE d.host_id = h.id
                   AND d.diff_type = 'GONE_HOST'
                   AND d.created_at >= h.offline_since
             )""",
        (p_start - 60,),
    )
    
    diffs, rows = [], []
    for h in new_hosts:
        diffs.append({"type": "NEW_HOST", "ip": h["ip"]})
        rows.append((cur_id, "NEW_HOST", h["id"], None, None, f"New host: {h['ip']}", "T1018", "Discovery", "MEDIUM"))
        
    for h in gone_hosts:
        diffs.append({"type": "GONE_HOST", "ip": h["ip"]})
        rows.append((cur_id, "GONE_HOST", h["id"], None, None, f"Host offline: {h['ip']}", "T1489", "Impact", "HIGH"))
        
    if rows: 
        await db.executemany("INSERT INTO scan_diffs (scan_id, diff_type, host_id, port_id, cve_id, detail, mitre_technique, mitre_tactic, severity) VALUES (?,?,?,?,?,?,?,?,?)", rows)
    return diffs
