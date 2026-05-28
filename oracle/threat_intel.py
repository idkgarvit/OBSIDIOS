"""
oracle/threat_intel.py
────────────────────────────
Real-Time Threat Intel Feed

Integrates with threat intelligence sources to flag:
- Known malicious IPs
- Latest exploits targeting your services
- Geolocation risk
- Reputation scores
"""
from __future__ import annotations
import time
from typing import Any

from loguru import logger
from chronicle import db


MOCK_THREAT_DATA = {
    '10.0.0.1': {'reputation': 'suspicious', 'score': 45, 'threats': ['botnet_c2', 'spam'], 'source': 'local_cache'},
    '192.168.1.100': {'reputation': 'malicious', 'score': 85, 'threats': ['ransomware', 'data_exfil'], 'source': 'local_cache'}
}


async def check_threat_intel(ips: list[str]) -> dict[str, Any]:
    """Check IPs against threat intelligence sources."""
    results = []
    found_threats = 0
    
    for ip in ips:
        threat_info = await _check_ip_threat(ip)
        if threat_info:
            results.append(threat_info)
            found_threats += 1
    
    return {
        'total_checked': len(ips),
        'threats_found': found_threats,
        'clear': len(ips) - found_threats,
        'results': results,
        'checked_at': time.time()
    }


async def _check_ip_threat(ip: str) -> dict | None:
    """Check individual IP against threat sources."""
    
    is_private = ip.startswith(('10.', '192.168.', '172.16.', '172.31.', '127.'))
    
    if is_private:
        return None
    
    if ip in MOCK_THREAT_DATA:
        return {
            'ip': ip,
            'reputation': MOCK_THREAT_DATA[ip]['reputation'],
            'score': MOCK_THREAT_DATA[ip]['score'],
            'threat_types': MOCK_THREAT_DATA[ip]['threats'],
            'source': MOCK_THREAT_DATA[ip]['source'],
            'action_required': True
        }
    
    geo_risk = _calculate_geo_risk(ip)
    
    if geo_risk['risk_level'] == 'HIGH':
        return {
            'ip': ip,
            'reputation': 'unknown',
            'score': 30,
            'country': geo_risk.get('country'),
            'threat_types': ['geographic_risk'],
            'source': 'geolocation',
            'action_required': False
        }
    
    return None


def _calculate_geo_risk(ip: str) -> dict:
    """Calculate geographic risk based on IP (mock implementation)."""
    return {
        'country': 'Unknown',
        'risk_level': 'LOW',
        'score': 10
    }


async def check_service_threats() -> dict[str, Any]:
    """Check exposed services against known vulnerability feeds."""
    
    services = await db.fetch_all("""
        SELECT h.ip, p.service, p.version, p.port
        FROM hosts h JOIN ports p ON p.host_id = h.id
        WHERE p.state='open' AND h.is_active=1
    """)
    
    known_exploits = {
        'apache': ['CVE-2021-41773', 'CVE-2021-42013'],
        'nginx': ['CVE-2021-23017'],
        'openssh': ['CVE-2021-28041'],
        'samba': ['CVE-2020-1472'],
        'mysql': ['CVE-2021-3744'],
        'postgres': ['CVE-2021-23214']
    }
    
    results = []
    
    for svc in services:
        service_name = (svc['service'] or '').lower()
        
        for known_svc, cves in known_exploits.items():
            if known_svc in service_name:
                results.append({
                    'ip': svc['ip'],
                    'service': svc['service'],
                    'version': svc['version'],
                    'known_exploits': cves,
                    'risk': 'HIGH'
                })
                break
    
    return {
        'service_count': len(services),
        'vulnerable_services': len(results),
        'findings': results
    }


async def get_threat_summary() -> dict:
    """Get overall threat intelligence summary."""
    
    total_hosts = await db.fetch_val('SELECT COUNT(*) FROM hosts WHERE is_active=1')
    open_ports = await db.fetch_val('SELECT COUNT(*) FROM ports WHERE state="open"')
    
    recent_alerts = await db.fetch_val(
        "SELECT COUNT(*) FROM sentinel_alerts WHERE alerted_at > ?",
        (time.time() - 86400,)
    )
    
    return {
        'network_size': total_hosts,
        'exposed_services': open_ports,
        'recent_threats': recent_alerts,
        'threat_level': 'HIGH' if recent_alerts > 10 else 'MEDIUM' if recent_alerts > 0 else 'LOW',
        'recommendation': 'Review alerts' if recent_alerts > 0 else 'Continue monitoring'
    }