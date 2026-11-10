"""iris/nuclei_scanner.py — High-speed vulnerability scanning via Nuclei"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import tempfile

from loguru import logger

from chronicle import db

_GENERIC_PROTOCOLS = {"http", "https", "tcp", "udp", "http-proxy", "http-alt"}
NUCLEI_TIMEOUT_SECONDS = int(os.environ.get("OBSIDIOS_NUCLEI_TIMEOUT", "1800"))

def _normalize_service(svc: str) -> str:
    return svc.strip().lower()

def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False

async def run_nuclei_scan(ip_list: list[str]):
    """
    Run Nuclei against a list of IPs and store findings as vulnerabilities.
    """
    targets = [ip for ip in ip_list if _valid_ip(ip)]
    if not targets:
        return

    logger.info(f"[IRIS/NUCLEI] Starting template-based scan for {len(targets)} hosts...")
    target_file = None
    try:
        # mkstemp gives an unpredictable, 0600 file; no symlink/race surface.
        fd, target_file = tempfile.mkstemp(prefix="obsidios-nuclei-", suffix=".txt")
        with os.fdopen(fd, "w") as f:
            for ip in targets:
                f.write(f"{ip}\n")

        # Run nuclei: -l (list), -jsonl (json output), -silent, -ni (no-interact)
        cmd = ["nuclei", "-l", target_file, "-jsonl", "-silent", "-ni", "-stats"]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=NUCLEI_TIMEOUT_SECONDS)
        except TimeoutError:
            logger.error(f"[IRIS/NUCLEI] Timed out after {NUCLEI_TIMEOUT_SECONDS}s; terminating")
            process.kill()
            await process.wait()
            return

        findings_count = 0
        for line in stdout.decode(errors="replace").splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.error(f"[IRIS/NUCLEI] Error parsing line: {exc}")
                continue
            try:
                await _process_nuclei_finding(data)
                findings_count += 1
            except Exception as exc:
                logger.error(f"[IRIS/NUCLEI] Could not persist finding: {exc}")

        logger.success(f"[IRIS/NUCLEI] Scan complete. {findings_count} findings recorded.")
    except Exception as e:
        logger.error(f"[IRIS/NUCLEI] Execution error: {e}")
    finally:
        if target_file:
            try:
                os.remove(target_file)
            except OSError:
                pass

async def _process_nuclei_finding(data: dict):
    """
    Transform a Nuclei finding into the OBSIDIOS vulnerability schema.
    """
    if not isinstance(data, dict):
        return
    info = data.get("info")
    if not isinstance(info, dict):
        info = {}
    severity_str = str(info.get("severity", "info")).strip().upper()
    description = info.get("description", "")
    if not isinstance(description, str):
        description = str(description)
    
    # Map Nuclei severity to our Severity enum
    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFO": "INFO"
    }
    mapped_severity = severity_map.get(severity_str, "LOW")
    
    # Extract CVE ID if available, else namespace the template id so it can
    # never masquerade as a real CVE in CVSS/reporting queries.
    template_id = str(data.get("template-id") or "unknown-template")[:120]
    cve_id = f"NUCLEI-{template_id}"
    classification = info.get("classification")
    if isinstance(classification, dict):
        cve_ids = classification.get("cve-id")
        candidate = cve_ids[0] if isinstance(cve_ids, list) and cve_ids else cve_ids
        if isinstance(candidate, str):
            candidate = candidate.strip().upper()
            # Only accept a syntactically real CVE identifier.
            if re.fullmatch(r"CVE-\d{4}-\d{4,}", candidate):
                cve_id = candidate

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
    if not isinstance(ip, str) or not _valid_ip(ip):
        ip = None
    port_val = data.get("port")
    
    try:
        port_val = int(port_val)
    except (TypeError, ValueError):
        port_val = None
    if ip and port_val and 1 <= port_val <= 65535:
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
