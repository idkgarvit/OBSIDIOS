"""
oracle/patch_prioritizer.py
────────────────────────────
AI Patch Prioritization Engine

Analyzes CVEs + network context (exposed ports, asset value, attack paths)
to output a prioritized patch order based on ACTUAL network risk, not just CVSS.
"""
from __future__ import annotations
from typing import Any

from loguru import logger
from chronicle import db


async def generate_patch_priority() -> dict[str, Any]:
    """
    Generate prioritized patch list considering:
    - CVSS score
    - Asset value (critical servers first)
    - Attack path exposure (is this host on a kill chain?)
    - Exploit availability
    - Network exposure (open ports)
    """
    cves_with_context = await db.fetch_all("""
        SELECT 
            h.ip, h.risk_score, h.asset_value,
            c.cve_id, c.cvss_v3, c.severity, c.description,
            p.port, p.service,
            pc.exploit_status, pc.effective_cvss,
            (SELECT COUNT(*) FROM attack_paths WHERE (entry_host_id = h.id OR target_host_id = h.id) AND is_active=1) as path_count
        FROM cves c
        JOIN port_cves pc ON pc.cve_id = c.id
        JOIN ports p ON p.id = pc.port_id
        JOIN hosts h ON h.id = p.host_id
        WHERE h.is_active=1 AND (c.cvss_v3 IS NOT NULL OR c.severity != 'NONE')
        ORDER BY c.cvss_v3 DESC
    """)
    
    if not cves_with_context:
        return {
            'priority_list': [],
            'summary': 'No actionable CVEs found',
            'total_critical': 0,
            'total_high': 0
        }
    
    priority_list = []
    seen_cves = set()
    
    for row in cves_with_context:
        cve_id = row['cve_id']
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        
        cvss = row['effective_cvss'] or row['cvss_v3'] or 0
        asset_val = row['asset_value'] or 5
        path_count = row['path_count'] or 0
        risk_score = row['risk_score'] or 0
        
        network_risk_score = (
            (cvss * 0.35) +
            (asset_val * 2.0) +
            (path_count * 10.0) +
            (risk_score * 0.3)
        )
        
        exploit_status = row['exploit_status'] if row['exploit_status'] else 'THEORETICAL'
        is_exploitable = exploit_status in ['VERIFIED', 'PUBLIC_EXPLOIT', 'MSF_AVAILABLE']
        
        severity = row['severity'] or 'UNKNOWN'
        
        priority_list.append({
            'ip': row['ip'],
            'cve_id': cve_id,
            'cvss': round(cvss, 1),
            'severity': severity,
            'port': row['port'],
            'service': row['service'],
            'asset_value': asset_val,
            'attack_paths': path_count,
            'risk_score': round(risk_score, 1),
            'network_risk': round(network_risk_score, 2),
            'exploitable': is_exploitable,
            'exploit_status': exploit_status
        })
    
    priority_list.sort(key=lambda x: x['network_risk'], reverse=True)
    
    critical_count = sum(1 for p in priority_list if p['severity'] == 'CRITICAL')
    high_count = sum(1 for p in priority_list if p['severity'] == 'HIGH')
    
    return {
        'priority_list': priority_list[:50],
        'summary': f"Prioritized {len(priority_list)} CVEs by network risk",
        'total_critical': critical_count,
        'total_high': high_count,
        'exploitable_count': sum(1 for p in priority_list if p['exploitable'])
    }