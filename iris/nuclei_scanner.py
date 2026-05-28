"""iris/nuclei_scanner.py — High-speed vulnerability scanning via Nuclei"""
from __future__ import annotations
import asyncio, os
import json
import subprocess
from loguru import logger
from chronicle import db

_GENERIC_PROTOCOLS = {"http", "https", "tcp", "udp", "http-proxy", "http-alt"}

def _normalize_service(svc: str) -> str:
    return svc.strip().lower()

async def run_nuclei_scan(ip_list: list[str]):
    """
    Run Nuclei against a list of IPs and store findings as vulnerabilities.
    """
    if not ip_list:
        return
        
    logger.info(f"[IRIS/NUCLEI] Starting template-based scan for {len(ip_list)} hosts...")
    
    # Create a temporary file with targets for nuclei
    with open("/tmp/nuclei_targets.txt", "w") as f:
        for ip in ip_list:
            f.write(f"{ip}\n")
            
    try:
        # Run nuclei: -l (list), -jsonl (json output), -silent, -ni (no-interact)
        cmd = ["nuclei", "-l", "/tmp/nuclei_targets.txt", "-jsonl", "-silent", "-ni", "-stats"]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        findings_count = 0
        for line in stdout.decode().splitlines():
            try:
                data = json.loads(line)
                findings_count += 1
                await _process_nuclei_finding(data)
            except Exception as e:
                logger.error(f"[IRIS/NUCLEI] Error parsing line: {e}")
                
        logger.success(f"[IRIS/NUCLEI] Scan complete. {findings_count} findings recorded.")
        
    except Exception as e:
        logger.error(f"[IRIS/NUCLEI] Execution error: {e}")
    finally:
        if os.path.exists("/tmp/nuclei_targets.txt"):
            os.remove("/tmp/nuclei_targets.txt")

async def _process_nuclei_finding(data: dict):
    """
    Transform a Nuclei finding into the OBSIDIOS vulnerability schema.
    """
    template_id = data.get("template-id")
    info = data.get("info", {})
    severity_str = info.get("severity", "info").upper()
    description = info.get("description", "")
    
    # Map Nuclei severity to our Severity enum
    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFO": "INFO"
    }
    mapped_severity = severity_map.get(severity_str, "LOW")
    
    # Extract CVE ID if available, else use template-id
    cve_id = template_id
    if "classification" in info and "cve-id" in info["classification"]:
        cve_ids = info["classification"]["cve-id"]
        if isinstance(cve_ids, list) and cve_ids:
            cve_id = cve_ids[0]
        elif isinstance(cve_ids, str):
            cve_id = cve_ids

    # Step 1: Upsert into cves table
    cve_row = await db.execute_returning(
        """INSERT INTO cves (cve_id, cvss_v3, severity, description)
           VALUES (?,?,?,?)
           ON CONFLICT(cve_id) DO UPDATE SET
             severity    = COALESCE(excluded.severity, severity),
             description = COALESCE(excluded.description, description)
           RETURNING id""",
        (cve_id, None, mapped_severity, description[:1000])
    )
    
    if not cve_row:
        return
        
    cve_db_id = cve_row["id"]
    ip = data.get("ip")
    port_val = data.get("port")
    
    if ip and port_val:
        # Step 2: Link to port — skip if port is a generic protocol without a known product
        host_row = await db.fetch_one("SELECT id FROM hosts WHERE ip=?", (ip,))
        if host_row:
            port_row = await db.fetch_one(
                """SELECT id, service, product, cpe FROM ports WHERE host_id=? AND port=?""",
                (host_row["id"], port_val)
            )
            if port_row:
                svc = _normalize_service(port_row["service"] or "")
                prod = port_row["product"] or port_row["cpe"]
                if svc in _GENERIC_PROTOCOLS and not prod:
                    return
                await db.execute(
                    """INSERT OR IGNORE INTO port_cves (port_id, cve_id) VALUES (?, ?)""",
                    (port_row["id"], cve_db_id)
                )
