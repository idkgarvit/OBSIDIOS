"""
oracle/posture_score.py
────────────────────────────
Security Posture Score Algorithm

Composite score 0-100 combining:
- Patch status (%)
- Attack path count
- Anomaly frequency
- Honeypot triggers
- Compliance coverage
- Exposed services
"""
from __future__ import annotations
import time
from typing import Any

from loguru import logger
from chronicle import db


async def calculate_posture_score() -> dict[str, Any]:
    """Calculate comprehensive security posture score."""
    
    total_hosts = await db.fetch_val('SELECT COUNT(*) FROM hosts WHERE is_active=1')
    if total_hosts == 0:
        return {'overall_score': 100, 'message': 'No active hosts to assess'}
    
    patch_score = await _calculate_patch_score()
    attack_path_score = await _calculate_attack_path_score()
    anomaly_score = await _calculate_anomaly_score()
    exposure_score = await _calculate_exposure_score()
    shield_score = await _calculate_shield_score()
    compliance_score = await _calculate_compliance_score()
    
    weights = {
        'patch': 0.25,
        'attack_paths': 0.20,
        'anomalies': 0.15,
        'exposure': 0.15,
        'shield': 0.10,
        'compliance': 0.15
    }
    
    overall_score = (
        patch_score['score'] * weights['patch'] +
        attack_path_score['score'] * weights['attack_paths'] +
        anomaly_score['score'] * weights['anomalies'] +
        exposure_score['score'] * weights['exposure'] +
        shield_score['score'] * weights['shield'] +
        compliance_score['score'] * weights['compliance']
    )
    
    await db.execute(
        """INSERT INTO posture_scores
           (overall_score, wired_score, behavioral_score, exploit_score, osint_score, active_alerts, active_paths, confirmed_vulns)
           VALUES (?,?,?,?,?,?,?,?)""",
        (overall_score, exposure_score['score'], anomaly_score['score'], patch_score['score'],
         0, attack_path_score['active_alerts'], attack_path_score['active_paths'], patch_score['critical_cves'])
    )
    
    risk_level = 'CRITICAL' if overall_score < 40 else 'HIGH' if overall_score < 60 else 'MEDIUM' if overall_score < 80 else 'LOW'
    
    return {
        'overall_score': round(overall_score, 1),
        'risk_level': risk_level,
        'breakdown': {
            'patch_status': patch_score,
            'attack_paths': attack_path_score,
            'behavioral_anomalies': anomaly_score,
            'exposure': exposure_score,
            'active_defense': shield_score,
            'compliance': compliance_score
        },
        'recommendations': _generate_recommendations(patch_score, attack_path_score, anomaly_score),
        'recorded_at': time.time()
    }


async def _calculate_patch_score() -> dict:
    """Calculate patch management score."""
    total_cves = await db.fetch_val('SELECT COUNT(*) FROM cves')
    critical_cves = await db.fetch_val("SELECT COUNT(*) FROM cves WHERE severity='CRITICAL'")
    high_cves = await db.fetch_val("SELECT COUNT(*) FROM cves WHERE severity='HIGH'")
    
    if total_cves == 0:
        return {'score': 100, 'total_cves': 0, 'critical_cves': 0, 'status': 'Fully Patched'}
    
    severity_weight = (critical_cves * 3 + high_cves * 2 + (total_cves - critical_cves - high_cves)) / total_cves
    score = max(0, 100 - (severity_weight * 50))
    
    return {
        'score': round(score, 1),
        'total_cves': total_cves,
        'critical_cves': critical_cves,
        'high_cves': high_cves,
        'status': 'Critical Issues' if critical_cves > 0 else 'Needs Attention' if high_cves > 0 else 'Acceptable'
    }


async def _calculate_attack_path_score() -> dict:
    """Calculate attack path exposure score."""
    total_paths = await db.fetch_val('SELECT COUNT(*) FROM attack_paths WHERE is_active=1')
    active_alerts = await db.fetch_val('SELECT COUNT(*) FROM sentinel_alerts WHERE acknowledged=0')
    shield_blocks = await db.fetch_val('SELECT COUNT(*) FROM shield_actions WHERE is_active=1')
    
    if total_paths == 0:
        return {'score': 100, 'active_paths': 0, 'active_alerts': 0, 'status': 'No Attack Paths'}
    
    path_risk = min(total_paths * 10, 50)
    alert_risk = min(active_alerts * 5, 30)
    mitigation = shield_blocks * 2
    
    score = max(0, 100 - path_risk - alert_risk + mitigation)
    
    return {
        'score': round(score, 1),
        'active_paths': total_paths,
        'active_alerts': active_alerts,
        'mitigations': shield_blocks,
        'status': 'Critical' if total_paths > 10 else 'High' if total_paths > 5 else 'Moderate'
    }


async def _calculate_anomaly_score() -> dict:
    """Calculate behavioral anomaly score."""
    total_anomalies = await db.fetch_val('SELECT COUNT(*) FROM anomalies WHERE acknowledged=0')
    recent_anomalies = await db.fetch_val(
        "SELECT COUNT(*) FROM anomalies WHERE acknowledged=0 AND detected_at > ?",
        (time.time() - 86400,)
    )
    critical_anomalies = await db.fetch_val(
        "SELECT COUNT(*) FROM anomalies WHERE acknowledged=0 AND confidence > 0.7"
    )
    
    if total_anomalies == 0:
        return {'score': 100, 'total': 0, 'recent_24h': 0, 'status': 'Normal Behavior'}
    
    score = max(0, 100 - (total_anomalies * 2 + recent_anomalies * 3 + critical_anomalies * 5))
    
    return {
        'score': round(score, 1),
        'total': total_anomalies,
        'recent_24h': recent_anomalies,
        'critical': critical_anomalies,
        'status': 'Anomalous' if total_anomalies > 10 else 'Suspicious' if total_anomalies > 3 else 'Normal'
    }


async def _calculate_exposure_score() -> dict:
    """Calculate network exposure score."""
    total_hosts = await db.fetch_val('SELECT COUNT(*) FROM hosts WHERE is_active=1')
    open_ports = await db.fetch_val('SELECT COUNT(*) FROM ports WHERE state="open"')
    exposed_services = await db.fetch_val("""
        SELECT COUNT(*) FROM ports p JOIN hosts h ON h.id = p.host_id
        WHERE p.state='open' AND p.service IN ('http', 'https', 'smb', 'ftp', 'ssh', 'rdp', 'telnet')
        AND h.is_active=1
    """)
    
    if total_hosts == 0:
        return {'score': 100, 'exposed_services': 0, 'status': 'No Exposure'}
    
    avg_ports = open_ports / total_hosts if total_hosts > 0 else 0
    service_risk = min(exposed_services * 5, 40)
    port_risk = min(avg_ports * 2, 30)
    
    score = max(0, 100 - service_risk - port_risk)
    
    return {
        'score': round(score, 1),
        'exposed_services': exposed_services,
        'avg_ports_per_host': round(avg_ports, 1),
        'status': 'Highly Exposed' if exposed_services > 20 else 'Moderate' if exposed_services > 10 else 'Acceptable'
    }


async def _calculate_shield_score() -> dict:
    """Calculate active defense score."""
    shield_actions = await db.fetch_val('SELECT COUNT(*) FROM shield_actions WHERE is_active=1')
    honeypots = await db.fetch_val('SELECT COUNT(*) FROM ghost_honeypots WHERE is_active=1')
    rules_deployed = await db.fetch_val('SELECT COUNT(*) FROM forge_rules WHERE is_deployed=1 AND is_active=1')
    
    if shield_actions == 0 and honeypots == 0:
        return {'score': 50, 'active_blocks': 0, 'honeypots': 0, 'ids_rules': 0, 'status': 'Passive Defense'}
    
    score = min(50 + (shield_actions * 5) + (honeypots * 10) + (rules_deployed * 2), 100)
    
    return {
        'score': round(score, 1),
        'active_blocks': shield_actions,
        'honeypots': honeypots,
        'ids_rules': rules_deployed,
        'status': 'Active Defense' if shield_actions > 0 or honeypots > 0 else 'Passive'
    }


async def _calculate_compliance_score() -> dict:
    """Calculate compliance score (mock - would integrate with compliance mapper)."""
    critical_cves = await db.fetch_val("SELECT COUNT(*) FROM cves WHERE severity='CRITICAL'")
    high_cves = await db.fetch_val("SELECT COUNT(*) FROM cves WHERE severity='HIGH'")
    
    if critical_cves == 0 and high_cves == 0:
        return {'score': 100, 'status': 'Compliant'}
    
    score = max(0, 100 - (critical_cves * 15) - (high_cves * 8))
    
    return {
        'score': round(score, 1),
        'critical_issues': critical_cves + high_cves,
        'status': 'Non-Compliant' if critical_cves > 0 else 'Partial'
    }


def _generate_recommendations(patch: dict, paths: dict, anomalies: dict) -> list[str]:
    """Generate prioritized recommendations based on scores."""
    recommendations = []
    
    if patch.get('critical_cves', 0) > 0:
        recommendations.append(f"URGENT: Patch {patch['critical_cves']} critical CVEs immediately")
    
    if paths.get('active_paths', 0) > 5:
        recommendations.append(f"High priority: {paths['active_paths']} attack paths detected - review network segmentation")
    
    if anomalies.get('critical', 0) > 0:
        recommendations.append(f"Investigate {anomalies['critical']} high-confidence behavioral anomalies")
    
    if not recommendations:
        recommendations.append("Continue monitoring - no critical issues detected")
    
    return recommendations