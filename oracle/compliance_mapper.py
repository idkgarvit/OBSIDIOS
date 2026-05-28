"""
oracle/compliance_mapper.py
────────────────────────────
Compliance Mapping Engine

Maps scan findings to compliance frameworks, with honest status levels:
  - COMPLIANT / NON-COMPLIANT  → verifiable by network scan
  - PARTIAL                    → scan finds indicators but cannot fully verify
  - POLICY_REQUIRED            → requires policy/process documentation review

Accuracy matters — requirements that can't be verified by scanning are
marked POLICY_REQUIRED rather than falsely reported as COMPLIANT.
"""
from __future__ import annotations
from typing import Any

from loguru import logger
from chronicle import db


# verification: scan | partial | policy
FRAMEWORK_MAPPINGS = {
    'PCI-DSS': {
        'req_1_1_3': {
            'requirement': '1.1.3 - Restrict inbound/outbound traffic to necessary IPs',
            'findings': ['open_ports'],
            'severity': 'HIGH',
            'verification': 'scan',
        },
        'req_2_2_1': {
            'requirement': '2.2.1 - Disable all unnecessary services',
            'findings': ['open_ports'],
            'severity': 'MEDIUM',
            'verification': 'scan',
        },
        'req_6_1': {
            'requirement': '6.1 - Ensure all system components have latest security patches',
            'findings': ['cves'],
            'severity': 'CRITICAL',
            'verification': 'scan',
        },
        'req_6_5': {
            'requirement': '6.5 - Address common coding vulnerabilities',
            'findings': ['web_vulns'],
            'severity': 'HIGH',
            'verification': 'partial',
        },
        'req_8_2_4': {
            'requirement': '8.2.4 - Password complexity and changes',
            'findings': ['weak_credentials'],
            'severity': 'HIGH',
            'verification': 'partial',
        },
        'req_10_1': {
            'requirement': '10.1 - Implement audit logging',
            'findings': [],
            'severity': 'MEDIUM',
            'verification': 'policy',
        },
    },
    'HIPAA': {
        '164_308_a_1': {
            'requirement': '164.308(a)(1) - Security management process',
            'findings': [],
            'severity': 'HIGH',
            'verification': 'policy',
        },
        '164_308_a_3': {
            'requirement': '164.308(a)(3) - Access control',
            'findings': ['weak_access_control'],
            'severity': 'HIGH',
            'verification': 'partial',
        },
        '164_308_a_5': {
            'requirement': '164.308(a)(5) - Security awareness training',
            'findings': [],
            'severity': 'MEDIUM',
            'verification': 'policy',
        },
        '164_308_a_6': {
            'requirement': '164.308(a)(6) - Security incident procedures',
            'findings': [],
            'severity': 'HIGH',
            'verification': 'policy',
        },
        '164_312_a': {
            'requirement': '164.312(a) - Access control mechanisms',
            'findings': ['encryption'],
            'severity': 'HIGH',
            'verification': 'partial',
        },
        '164_312_e': {
            'requirement': '164.312(e) - Transmission security',
            'findings': ['unencrypted_transmission'],
            'severity': 'HIGH',
            'verification': 'scan',
        },
    },
    'SOC2': {
        'cc6_1': {
            'requirement': 'CC6.1 - Logical access security',
            'findings': ['access_controls'],
            'severity': 'HIGH',
            'verification': 'partial',
        },
        'cc6_7': {
            'requirement': 'CC6.7 - Data retention and disposal',
            'findings': [],
            'severity': 'MEDIUM',
            'verification': 'policy',
        },
        'cc7_1': {
            'requirement': 'CC7.1 - System operations and availability',
            'findings': [],
            'severity': 'HIGH',
            'verification': 'policy',
        },
        'cc7_2': {
            'requirement': 'CC7.2 - Change management',
            'findings': [],
            'severity': 'MEDIUM',
            'verification': 'policy',
        },
        'cc8_1': {
            'requirement': 'CC8.1 - Risk assessment',
            'findings': ['risk_assessment'],
            'severity': 'HIGH',
            'verification': 'partial',
        },
    },
    'NIST': {
        'si_2': {
            'requirement': 'SI-2 - Flaw remediation',
            'findings': ['cves'],
            'severity': 'HIGH',
            'verification': 'scan',
        },
        'si_3': {
            'requirement': 'SI-3 - Malicious code protection',
            'findings': [],
            'severity': 'HIGH',
            'verification': 'policy',
        },
        'ac_3': {
            'requirement': 'AC-3 - Access enforcement',
            'findings': [],
            'severity': 'HIGH',
            'verification': 'policy',
        },
        'au_2': {
            'requirement': 'AU-2 - Event logging and audit trails',
            'findings': [],
            'severity': 'MEDIUM',
            'verification': 'policy',
        },
        'sc_8': {
            'requirement': 'SC-8 - Transmission confidentiality',
            'findings': ['unencrypted_transmission'],
            'severity': 'HIGH',
            'verification': 'scan',
        },
        'ca_7': {
            'requirement': 'CA-7 - Continuous monitoring',
            'findings': ['monitoring_coverage'],
            'severity': 'MEDIUM',
            'verification': 'partial',
        },
    },
}

_POLICY_NOTE = "Cannot verify via network scan. Requires review of policies, procedures, and documentation."
_PARTIAL_NOTE = "Scan detected indicators but cannot fully verify compliance without policy review."


async def map_compliance(framework: str = 'PCI-DSS') -> dict[str, Any]:
    """Map scan findings to the specified compliance framework."""
    if framework not in FRAMEWORK_MAPPINGS:
        return {'error': f'Unknown framework: {framework}. Available: {list(FRAMEWORK_MAPPINGS.keys())}'}

    mapping = FRAMEWORK_MAPPINGS[framework]
    mapped_findings = []

    # Pre-fetch reusable scan data
    hosts_with_issues = await db.fetch_all(
        "SELECT ip, risk_score, os_name FROM hosts WHERE is_active=1 AND risk_score > 30"
    ) or []

    cves = await db.fetch_all(
        "SELECT c.severity, COUNT(*) as cnt FROM cves c JOIN port_cves pc ON pc.cve_id = c.id GROUP BY c.severity"
    ) or []

    open_ports = await db.fetch_val("SELECT COUNT(*) FROM ports WHERE state='open'") or 0
    attack_paths = await db.fetch_val("SELECT COUNT(*) FROM attack_paths WHERE is_active=1") or 0

    for req_id, req_info in mapping.items():
        finding_types = req_info['findings']
        verification = req_info.get('verification', 'policy')

        # ── POLICY-REQUIRED requirements ───────────────────────────────
        if verification == 'policy':
            mapped_findings.append({
                'requirement_id': req_id,
                'requirement': req_info['requirement'],
                'severity': req_info['severity'],
                'status': 'POLICY_REQUIRED',
                'verification': 'policy',
                'issues': [_POLICY_NOTE],
                'affected_systems': 0,
            })
            continue

        # ── SCAN-VERIFIABLE requirements ───────────────────────────────
        relevant_issues = []
        affected_systems = 0

        if 'cves' in finding_types:
            for cve in cves:
                if cve['severity'] in ('CRITICAL', 'HIGH'):
                    count = cve['cnt']
                    relevant_issues.append(f"{count} {cve['severity']}-severity vulnerabilities unpatched")
                    affected_systems = len(hosts_with_issues)

        if 'open_ports' in finding_types:
            if open_ports > 10:
                relevant_issues.append(f"{open_ports} open ports exceed recommended attack surface")
                affected_systems = len(hosts_with_issues)
            elif open_ports > 0:
                relevant_issues.append(f"{open_ports} open ports discovered")

        if 'weak_credentials' in finding_types or 'weak_access_control' in finding_types or 'access_controls' in finding_types:
            weak_hosts = await db.fetch_all(
                "SELECT h.ip, p.port, p.service FROM hosts h "
                "JOIN ports p ON p.host_id = h.id "
                "WHERE p.state='open' AND p.service IN ('ssh', 'ftp', 'telnet', 'rlogin')"
            ) or []
            if weak_hosts:
                services = set(r['service'] for r in weak_hosts)
                relevant_issues.append(f"Weak-auth services on {len(weak_hosts)} hosts: {', '.join(sorted(services))}")
                affected_systems = max(affected_systems, len(weak_hosts))

        if 'encryption' in finding_types or 'unencrypted_transmission' in finding_types:
            cleartext = await db.fetch_all(
                "SELECT h.ip, p.port, p.service FROM hosts h "
                "JOIN ports p ON p.host_id = h.id "
                "WHERE p.state='open' AND p.service IN ('ftp', 'telnet', 'http')"
            ) or []
            if cleartext:
                services = set(r['service'] for r in cleartext)
                relevant_issues.append(f"Unencrypted protocols in use: {', '.join(sorted(services))}")
                affected_systems = max(affected_systems, len(cleartext))

        if 'web_vulns' in finding_types:
            web_ports = await db.fetch_all(
                "SELECT h.ip, p.port, p.service FROM hosts h "
                "JOIN ports p ON p.host_id = h.id "
                "WHERE p.state='open' AND p.service IN ('http', 'https', 'apache', 'nginx', 'iis')"
            ) or []
            if web_ports:
                relevant_issues.append(f"{len(web_ports)} web services present — manual DAST/SAST required")
                affected_systems = max(affected_systems, len(web_ports))
            else:
                relevant_issues.append("No web services detected on scanned ports")
                affected_systems = 0

        if 'risk_assessment' in finding_types or 'monitoring_coverage' in finding_types:
            if attack_paths > 0:
                relevant_issues.append(f"{attack_paths} exploitable attack paths identified")
                affected_systems = len(hosts_with_issues)

        # ── Determine status ───────────────────────────────────────────
        if verification == 'partial':
            if relevant_issues:
                status = 'NON-COMPLIANT'
            else:
                status = 'PARTIAL'
                relevant_issues = [_PARTIAL_NOTE]
        else:
            status = 'NON-COMPLIANT' if relevant_issues else 'COMPLIANT'

        mapped_findings.append({
            'requirement_id': req_id,
            'requirement': req_info['requirement'],
            'severity': req_info['severity'],
            'verification': verification,
            'status': status,
            'issues': relevant_issues,
            'affected_systems': affected_systems,
        })

    # Score calculation: only scan-verifiable requirements count toward score
    scoreable = [f for f in mapped_findings if f['verification'] != 'policy']
    compliant = sum(1 for f in scoreable if f['status'] == 'COMPLIANT')
    partial = sum(1 for f in scoreable if f['status'] == 'PARTIAL')
    fail = sum(1 for f in scoreable if f['status'] == 'NON-COMPLIANT')
    total_scoreable = len(scoreable)

    if total_scoreable > 0:
        # Partial = 50% credit
        score = round(((compliant + (partial * 0.5)) / total_scoreable) * 100, 1)
    else:
        score = 100.0

    return {
        'framework': framework,
        'total_requirements': len(mapped_findings),
        'compliant': compliant,
        'partial': partial,
        'non_compliant': fail,
        'policy_required': sum(1 for f in mapped_findings if f['verification'] == 'policy'),
        'compliance_score': score,
        'score_note': 'Score based on scan-verifiable requirements only',
        'findings': mapped_findings,
    }