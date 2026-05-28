"""
iris/wired_scanner.py
IRIS wired network discovery: Dual-mode (Scapy + Nmap) aggressive discovery.
"""
from __future__ import annotations
import asyncio, time, ipaddress, netifaces
from concurrent.futures import ThreadPoolExecutor
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, Ether, srp, conf as scapy_conf
scapy_conf.verb = 0
import nmap
from loguru import logger
from chronicle import db
from chronicle.models import Host, Port, ScanResult
from config.settings import scan as scan_cfg

async def get_target_from_db() -> str:
    try:
        if not db._initialized: await db.init()
        target = await db.fetch_val("SELECT value FROM system_settings WHERE key='target_network'", default="")
        return target if target else scan_cfg.target_network
    except: return scan_cfg.target_network

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
    
    arp_results, nm = await asyncio.gather(arp_fut, nmap_fut)
    
    hosts_dict = {h['ip']: h['mac'] for h in arp_results}
    for ip in nm.all_hosts():
        if nm[ip].state() == 'up' and ip not in hosts_dict:
            mac = nm[ip]['addresses'].get('mac', 'UNKNOWN').upper()
            hosts_dict[ip] = mac
                
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

def _nmap_scan_host(ip: str, args: str) -> dict:
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments=args)
    if ip not in nm.all_hosts(): return {}
    h = nm[ip]
    res = {"ip":ip,"hostname":h.hostname(),"state":h.state(),"os":[],"ports":[],"host_types":[]}
    if "osmatch" in h: res["os"] = [{"name":m["name"],"accuracy":int(m["accuracy"])} for m in h["osmatch"]]
    for proto in h.all_protocols():
        for port in sorted(h[proto].keys()):
            p = h[proto][port]
            if p["state"] == "open":
                res["ports"].append({"port":port,"protocol":proto,"state":p["state"],"service":p.get("name",""),"product":p.get("product",""),"version":p.get("version",""),"extra_info":p.get("extrainfo",""),"cpe":p.get("cpe","")})
    return res

def _nmap_deep_scan(ip: str, extra_ports: list[int]) -> list[dict]:
    """Second-pass targeted scan for host-type-specific ports."""
    if not extra_ports: return []
    port_str = ",".join(str(p) for p in sorted(set(extra_ports)))
    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments=f"-sV -T4 --min-parallelism 10 --max-retries 1 -p {port_str}")
    if ip not in nm.all_hosts(): return []
    h = nm[ip]
    found = []
    for proto in h.all_protocols():
        for port in sorted(h[proto].keys()):
            p = h[proto][port]
            if p["state"] == "open":
                found.append({"port":port,"protocol":proto,"state":p["state"],"service":p.get("name",""),"product":p.get("product",""),"version":p.get("version",""),"extra_info":p.get("extrainfo",""),"cpe":p.get("cpe","")})
    return found

async def scan_host(ip: str, sem: asyncio.Semaphore) -> dict:
    async with sem:
        result = await asyncio.get_running_loop().run_in_executor(_nmap_executor, _nmap_scan_host, ip, scan_cfg.active_nmap_args)
        if not result: return result
        # Adaptive second pass: detect host type and deep-scan
        open_port_nums = [p["port"] for p in result.get("ports", [])]
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
            existing = {p["port"] for p in result["ports"]}
            for dp in deep_ports:
                if dp["port"] not in existing:
                    result["ports"].append(dp)
        return result

async def scan_hosts_concurrent(hosts: list[dict]) -> list[dict]:
    if not hosts: return []
    sem = asyncio.Semaphore(scan_cfg.scan_concurrency)
    results = await asyncio.gather(*[scan_host(h["ip"], sem) for h in hosts], return_exceptions=True)
    return [r for r in results if isinstance(r, dict) and r]

# Known MAC OUIs strongly associated with mobile devices
# Nmap OS detection is unreliable for these — override with MAC-based guess
_MOBILE_MAC_PREFIXES: dict[str, str] = {
    "3C:07:54": "Apple iOS",
    "3C:22:FB": "Apple iOS",
    "00:11:22": "Apple iOS",
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
    if nmap_acc is not None and nmap_acc >= 80:
        return nmap_os, nmap_acc
    return mac_os, min(nmap_acc or 0, 30)

async def _upsert_hosts(arp_hosts: list[dict], scan_data: list[dict]) -> dict[str, int]:
    now, host_id_map = time.time(), {}
    nmap_by_ip = {r["ip"]: r for r in scan_data}
    mac_by_ip = {h["ip"]: h["mac"] for h in arp_hosts}
    for ip, mac in mac_by_ip.items():
        nd = nmap_by_ip.get(ip, {}); os_name = os_acc = None
        if nd.get("os"): os_name, os_acc = nd["os"][0]["name"], nd["os"][0]["accuracy"]
        os_name, os_acc = _infer_os_from_mac(mac, os_name, os_acc)
        row = await db.execute_returning("INSERT INTO hosts (ip,mac,hostname,os_name,os_accuracy,is_active,last_seen) VALUES (?,?,?,?,?,1,?) ON CONFLICT(ip) DO UPDATE SET mac=COALESCE(excluded.mac, mac), hostname=COALESCE(excluded.hostname, hostname), os_name=COALESCE(excluded.os_name, os_name), last_seen=excluded.last_seen, is_active=1 RETURNING id", (ip, mac if mac != 'UNKNOWN' else None, nd.get("hostname"), os_name, os_acc, now))
        if row: host_id_map[ip] = row["id"]
    return host_id_map

async def _upsert_ports(scan_data: list[dict], host_id_map: dict[str, int]) -> int:
    now, rows = time.time(), []
    for nd in scan_data:
        hid = host_id_map.get(nd["ip"])
        if hid:
            for p in nd.get("ports", []): rows.append((hid,p["port"],p["protocol"],p["state"],p.get("service"),p.get("product"),p.get("version"),p.get("extra_info"),p.get("cpe"),now,now))
    if rows: await db.executemany("INSERT INTO ports (host_id,port,protocol,state,service,product,version,extra_info,cpe,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(host_id,port,protocol) DO UPDATE SET state=excluded.state, service=COALESCE(NULLIF(excluded.service,''),service), product=COALESCE(NULLIF(excluded.product,''),product), version=COALESCE(NULLIF(excluded.version,''),version), last_seen=excluded.last_seen", rows)
    return len(rows)


def _classify_wireless_threat(bssid: str | None, ssid: str, encryption: str, signal: int | None, known_bssids: set[str]) -> str:
    """Classify wireless threat type based on signal, encryption, and known networks."""
    if encryption == "OPEN":
        return "OPEN_NETWORK"
    if bssid and bssid in known_bssids and ssid != "Hidden":
        # Same BSSID seen with different SSID — possible evil twin
        return "EVIL_TWIN"
    if signal is not None and signal > -50:
        # Very strong signal from outside network — possible rogue AP
        return "ROGUE_AP"
    if ssid == "Hidden":
        return "HIDDEN_NETWORK"
    return "ENCRYPTED_NETWORK"


def _scan_wireless_clients(iface: str) -> list[dict]:
    """Detect wireless client stations via iw station dump + ARP table."""
    import subprocess
    clients = []
    try:
        # Method 1: iw station dump (works if interface in AP mode)
        result = subprocess.run(
            ["iw", "dev", iface, "station", "dump"],
            capture_output=True, text=True, timeout=10
        )
        for block in result.stdout.split("Station "):
            if not block.strip():
                continue
            mac_m = re.search(r'([0-9a-fA-F:]{17})', block)
            sig_m = re.search(r'signal:.*?(-?\d+)', block)
            if mac_m:
                clients.append({
                    "mac": mac_m.group(1).upper(),
                    "signal": int(sig_m.group(1)) if sig_m else None,
                    "source": "iw_station_dump",
                })
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
            if len(parts) >= 3 and re.match(r'[0-9a-fA-F:]{17}', parts[2]):
                mac = parts[2].upper()
                # Skip broadcast, multicast, and gateway MACs
                if mac.startswith(("FF:", "01:", "33:", "00:00:00")):
                    continue
                # Check if not already from AP scan
                if not any(c["mac"] == mac for c in clients):
                    clients.append({
                        "mac": mac,
                        "ip": parts[0] if re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]) else None,
                        "signal": None,
                        "source": "arp_cache",
                    })
    except FileNotFoundError:
        pass
    except Exception:
        pass

    return clients


async def run_wireless_scan():
    import subprocess, re, time
    from chronicle import db
    from config.settings import scan as scan_cfg
    if not scan_cfg.enable_wireless:
        return
    iface = scan_cfg.wireless_interface
    # Auto-detect wireless interface if configured one doesn't exist
    try:
        r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        detected = re.findall(r'Interface\s+(\S+)', r.stdout)
        if iface not in detected and detected:
            iface = detected[0]
            logger.info(f"[WIRELESS] Auto-detected interface {iface} (configured {scan_cfg.wireless_interface} not found)")
    except Exception:
        pass
    # Get known BSSIDs from previous scans to detect evil twin
    prev_rows = await db.fetch_all("SELECT DISTINCT bssid FROM wireless_threats WHERE bssid IS NOT NULL")
    known_bssids = {r["bssid"] for r in prev_rows} if prev_rows else set()

    try:
        result = subprocess.run(
            ["iw", "dev", iface, "scan"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0 or not result.stdout:
            logger.warning(f"[WIRELESS] No scan results on {iface}: {result.stderr.strip()}")
        else:
            now = time.time()
            for block in result.stdout.split("BSS "):
                if not block.strip():
                    continue
                bssid_m = re.search(r'([0-9a-fA-F:]{17})', block)
                ssid_m = re.search(r'SSID: (.+)', block)
                sig_m = re.search(r'signal: (-?\d+)', block)
                chan_m = re.search(r'channel (\d+)', block)
                enc_m = re.search(r'RSN:[\s\*]*\*? ?(?:Version: \d+)?\s*\*?([A-Za-z0-9\-]+)', block)
                bssid = bssid_m.group(1) if bssid_m else None
                ssid = ssid_m.group(1).strip() if ssid_m else "Hidden"
                signal = int(sig_m.group(1)) if sig_m else None
                channel = int(chan_m.group(1)) if chan_m else None
                encryption = enc_m.group(1) if enc_m else "OPEN"
                threat_type = _classify_wireless_threat(bssid, ssid, encryption, signal, known_bssids)
                await db.execute(
                    "INSERT INTO wireless_threats (detected_at, threat_type, bssid, ssid, channel, signal_strength, encryption, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (now, threat_type, bssid, ssid, channel, signal, encryption,
                     f"Signal: {signal}dBm, Encryption: {encryption}" if signal else f"Encryption: {encryption}")
                )
                if threat_type in ("EVIL_TWIN", "ROGUE_AP", "OPEN_NETWORK"):
                    from alerts.notifier import buffer_alert
                    await buffer_alert(
                        category="wireless",
                        title=f"📡 {threat_type}",
                        message=f"**SSID:** `{ssid}`\n**BSSID:** `{bssid}`\n**Signal:** {signal}dBm · **Ch:** {channel}",
                        color="high",
                    )
            logger.info(f"[WIRELESS] Scan complete: found APs on {iface}")

        # Scan for wireless clients (phones, TVs, IoT)
        clients = _scan_wireless_clients(iface)
        if clients:
            now = time.time()
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

    except FileNotFoundError:
        logger.warning(f"[WIRELESS] `iw` not found — no wireless scanning available")
    except subprocess.TimeoutExpired:
        logger.warning(f"[WIRELESS] Scan timed out on {iface}")
    except Exception as e:
        logger.warning(f"[WIRELESS] Scan failed: {e}")

async def run_scan(network: str | None = None) -> ScanResult:
    target = network or await get_target_from_db()
    started = time.time()
    scan_row = await db.execute_returning("INSERT INTO scans (scan_type,target,started_at,status) VALUES (?,?,?,'RUNNING') RETURNING id", ("FULL", target, started))
    scan_id = scan_row["id"] if scan_row else None
    res = ScanResult(scan_id=scan_id, target=target, started_at=started)
    try:
        hosts = await discover_hosts(target)
        if not hosts: return res
        scan_data = await scan_hosts_concurrent(hosts)
        host_id_map = await _upsert_hosts(hosts, scan_data)
        ports_found = await _upsert_ports(scan_data, host_id_map)
        # Mark offline
        ips = [h["ip"] for h in hosts]
        if ips:
            await db.execute(f"UPDATE hosts SET is_active=0 WHERE ip NOT IN ({','.join('?'*len(ips))}) AND is_active=1", tuple(ips))
        for nd in scan_data:
            ip, hid = nd["ip"], host_id_map.get(nd["ip"])
            res.hosts.append(Host(id=hid, ip=ip, hostname=nd.get("hostname"), os_name=nd["os"][0]["name"] if nd.get("os") else None))
            res.ports[ip] = [Port(host_id=hid, **p) for p in nd.get("ports", [])]
        if scan_id:
            cancelled = await db.fetch_val("SELECT status FROM scans WHERE id=?", (scan_id,), default='')
            if cancelled == 'CANCELLED':
                logger.warning(f"[IRIS] Scan {scan_id} was cancelled — skipping DONE update")
                from alerts.notifier import send_alert
                await send_alert(title="⛔ **Scan Cancelled**", message=f"Scan **#{scan_id}** was cancelled mid-execution", color="medium", footer="OBSIDIOS v2.0")
            else:
                await db.execute("UPDATE scans SET finished_at=?, hosts_found=?, ports_found=?, status='DONE' WHERE id=?", (time.time(), len(res.hosts), ports_found, scan_id))
    except Exception as e:
        logger.exception(f"[IRIS] Scan failed: {e}")
        if scan_id: await db.execute("UPDATE scans SET status='FAILED', error=? WHERE id=?", (str(e), scan_id))
        from alerts.notifier import send_alert
        await send_alert(title="❌ **Scan Failed**", message=f"Scan **#{scan_id}** encountered an error:\n```{str(e)[:500]}```", color="critical", footer="OBSIDIOS v2.0")
    return res

async def compute_scan_diff(cur_id: int, prev_id: int | None = None) -> list[dict]:
    if not prev_id: return []
    cur = await db.fetch_one("SELECT started_at FROM scans WHERE id=?", (cur_id,))
    prev = await db.fetch_one("SELECT started_at FROM scans WHERE id=?", (prev_id,))
    if not cur or not prev: return []
    
    c_start = cur["started_at"]
    p_start = prev["started_at"]
    
    new_hosts = await db.fetch_all("SELECT id, ip FROM hosts WHERE first_seen >= ?", (c_start - 60,))
    gone_hosts = await db.fetch_all("SELECT id, ip FROM hosts WHERE is_active=0 AND last_seen >= ? AND last_seen < ?", (p_start - 60, c_start - 60))
    
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


async def fast_host_discovery():
    """Perpetual high-speed discovery loop (ARP/Ping) to update dashboard in real-time."""
    from chronicle.db import fetch_val
    target = await fetch_val("SELECT value FROM system_settings WHERE key='target_network'", default="")
    if not target: return
    
    logger.info(f"[IRIS/FAST] Pulse discovery starting on {target}")
    hosts = await discover_hosts(target)
    active_ips = [h['ip'] for h in hosts]
    
    if active_ips:
        # INSERT any new hosts not yet in DB
        existing = set()
        rows = await db.fetch_all("SELECT ip FROM hosts WHERE ip IN ({})".format(','.join('?'*len(active_ips))), tuple(active_ips))
        if rows: existing = {r["ip"] for r in rows}
        new_ips = [ip for ip in active_ips if ip not in existing]
        for ip in new_ips:
            mac = next((h["mac"] for h in hosts if h["ip"] == ip), None)
            try:
                await db.execute("INSERT INTO hosts (ip, mac, is_active, last_seen) VALUES (?, ?, 1, unixepoch()) ON CONFLICT(ip) DO UPDATE SET is_active=1, last_seen=unixepoch()", (ip, mac))
            except Exception:
                pass  # race — another writer inserted it
        # Update is_active status instantly
        await db.execute(f"UPDATE hosts SET is_active=1, last_seen=unixepoch() WHERE ip IN ({','.join('?'*len(active_ips))})", tuple(active_ips))
        await db.execute(f"UPDATE hosts SET is_active=0 WHERE ip NOT IN ({','.join('?'*len(active_ips))}) AND is_active=1", tuple(active_ips))
        logger.success(f"[IRIS/FAST] HUD Synced: {len(active_ips)} assets live ({len(new_ips)} new).")
