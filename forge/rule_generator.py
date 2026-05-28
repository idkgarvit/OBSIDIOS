"""
forge/rule_generator.py
────────────────────────
FORGE — The Rule Factory. The feature that doesn't exist anywhere on earth.

Takes PHANTOM's simulated kill chains and auto-writes custom Suricata
detection rules specifically tuned to YOUR network topology.

Why this is unprecedented:
  Every existing IDS ships with generic rules (Emerging Threats, etc.)
  that watch for known bad signatures across all networks.

  FORGE generates rules that say:
    "Watch for THIS technique, coming FROM this specific subnet,
     targeting THIS specific host, using THIS specific service."

  Generic rules: "alert if someone scans port 22"
  FORGE rules:   "alert if 192.168.56.0/24 sees SSH lateral movement
                  toward 192.168.56.104 matching PHANTOM path #3 step 2"

Rule generation strategy per MITRE technique:
  T1021.* (Lateral Movement) → watch inter-host connections on pivot ports
  T1190   (Initial Access)   → watch inbound exploit attempts on web ports
  T1071.* (C2)               → watch beaconing patterns + unusual outbound
  T1210   (Exploitation)     → watch for specific CVE exploit signatures
  T1078   (Valid Accounts)   → watch for credential stuffing patterns
  T1557   (ARP/LLMNR)       → watch for poisoning attempts
"""
from __future__ import annotations

import asyncio
import time

from loguru import logger

from chronicle import db
from chronicle.models import ForgeRule
from phantom.path_finder import SimulationResult, AttackStep


# ── SID counter (Suricata rule IDs must be unique) ─────────────────────────
# OBSIDIOS uses SID range 9000000–9999999 to avoid conflicts with
# Emerging Threats (2000000+) and Snort community rules (1000000+)
_SID_BASE    = 9_000_000
_sid_counter = 0

async def _next_sid() -> int:
    """Get next available SID from DB + local counter."""
    global _sid_counter
    if _sid_counter == 0:
        max_sid = await db.fetch_val(
            "SELECT MAX(rule_sid) FROM forge_rules", default=_SID_BASE - 1
        )
        if max_sid is None:
            max_sid = _SID_BASE - 1
        _sid_counter = max(max_sid, _SID_BASE - 1)
    _sid_counter += 1
    return _sid_counter


# ─────────────────────────────────────────────────────────────────────────────
# Rule templates per MITRE technique
# ─────────────────────────────────────────────────────────────────────────────

def _rule_lateral_movement_ssh(
    src_ip: str, dst_ip: str, sid: int, path_id: int, step: int
) -> str:
    return (
        f'alert tcp {src_ip} any -> {dst_ip} 22 '
        f'(msg:"OBSIDIOS PHANTOM Path#{path_id} Step#{step} '
        f'Lateral Movement SSH {src_ip}->{dst_ip}"; '
        f'flow:to_server,established; '
        f'content:"SSH"; depth:3; '
        f'threshold:type threshold,track by_src,count 3,seconds 60; '
        f'classtype:attempted-user; '
        f'sid:{sid}; rev:1; '
        f'metadata:mitre_technique T1021.004, obsidios_path {path_id};)'
    )


def _rule_lateral_movement_smb(
    src_ip: str, dst_ip: str, sid: int, path_id: int, step: int
) -> str:
    return (
        f'alert tcp {src_ip} any -> {dst_ip} [139,445] '
        f'(msg:"OBSIDIOS PHANTOM Path#{path_id} Step#{step} '
        f'Lateral Movement SMB {src_ip}->{dst_ip}"; '
        f'flow:to_server,established; '
        f'content:"|FF|SMB"; '
        f'classtype:attempted-user; '
        f'sid:{sid}; rev:1; '
        f'metadata:mitre_technique T1021.002, obsidios_path {path_id};)'
    )


def _rule_lateral_movement_rdp(
    src_ip: str, dst_ip: str, sid: int, path_id: int, step: int
) -> str:
    return (
        f'alert tcp {src_ip} any -> {dst_ip} 3389 '
        f'(msg:"OBSIDIOS PHANTOM Path#{path_id} Step#{step} '
        f'Lateral Movement RDP {src_ip}->{dst_ip}"; '
        f'flow:to_server,established; '
        f'threshold:type threshold,track by_src,count 3,seconds 30; '
        f'classtype:attempted-user; '
        f'sid:{sid}; rev:1; '
        f'metadata:mitre_technique T1021.001, obsidios_path {path_id};)'
    )


def _rule_initial_access_web(
    dst_ip: str, port: int, sid: int, path_id: int, step: int
) -> str:
    return (
        f'alert http any any -> {dst_ip} {port} '
        f'(msg:"OBSIDIOS PHANTOM Path#{path_id} Step#{step} '
        f'Initial Access Web Exploit -> {dst_ip}:{port}"; '
        f'flow:to_server,established; '
        f'http.method; content:"POST"; '
        f'http.uri; content:"/"; '
        f'detection_filter:track by_src,count 20,seconds 30; '
        f'classtype:web-application-attack; '
        f'sid:{sid}; rev:1; '
        f'metadata:mitre_technique T1190, obsidios_path {path_id};)'
    )


def _rule_exploit_ftp_backdoor(
    dst_ip: str, sid: int, path_id: int, step: int
) -> str:
    """CVE-2011-2523 — vsftpd 2.3.4 backdoor trigger (:)"""
    return (
        f'alert tcp any any -> {dst_ip} 21 '
        f'(msg:"OBSIDIOS PHANTOM Path#{path_id} Step#{step} '
        f'CVE-2011-2523 vsftpd 2.3.4 Backdoor Attempt -> {dst_ip}"; '
        f'flow:to_server,established; '
        f'content:"USER "; content:":)"; within:50; '
        f'classtype:attempted-admin; '
        f'sid:{sid}; rev:1; '
        f'metadata:mitre_technique T1210, cve CVE-2011-2523, obsidios_path {path_id};)'
    )


def _rule_exploit_samba(
    dst_ip: str, sid: int, path_id: int, step: int
) -> str:
    """CVE-2007-2447 — Samba username map script RCE"""
    return (
        f'alert tcp any any -> {dst_ip} [139,445] '
        f'(msg:"OBSIDIOS PHANTOM Path#{path_id} Step#{step} '
        f'CVE-2007-2447 Samba Username Map Script RCE -> {dst_ip}"; '
        f'flow:to_server,established; '
        f'content:"|00 00 00|"; depth:4; '
        f'content:"nohup"; '
        f'classtype:attempted-admin; '
        f'sid:{sid}; rev:1; '
        f'metadata:mitre_technique T1210, cve CVE-2007-2447, obsidios_path {path_id};)'
    )


def _rule_c2_beacon(
    src_ip: str, sid: int, path_id: int
) -> str:
    """Detect C2 beaconing — regular outbound intervals from compromised host."""
    return (
        f'alert tcp {src_ip} any -> !192.168.56.0/24 any '
        f'(msg:"OBSIDIOS PHANTOM Path#{path_id} '
        f'C2 Beaconing Pattern from {src_ip}"; '
        f'flow:to_server,established; '
        f'detection_filter:track by_src,count 10,seconds 120; '
        f'classtype:trojan-activity; '
        f'sid:{sid}; rev:1; '
        f'metadata:mitre_technique T1071, obsidios_path {path_id};)'
    )


def _rule_telnet_cleartext(
    src_ip: str, dst_ip: str, sid: int, path_id: int, step: int
) -> str:
    return (
        f'alert tcp {src_ip} any -> {dst_ip} 23 '
        f'(msg:"OBSIDIOS PHANTOM Path#{path_id} Step#{step} '
        f'Telnet Cleartext Lateral Movement {src_ip}->{dst_ip}"; '
        f'flow:to_server,established; '
        f'classtype:attempted-user; '
        f'sid:{sid}; rev:1; '
        f'metadata:mitre_technique T1021.004, obsidios_path {path_id};)'
    )


def _rule_port_scan_detection(
    src_ip: str, dst_ip: str, sid: int, path_id: int
) -> str:
    """Detect reconnaissance scanning from predicted entry point."""
    return (
        f'alert tcp {src_ip} any -> {dst_ip} any '
        f'(msg:"OBSIDIOS PHANTOM Path#{path_id} '
        f'Recon Port Scan from predicted entry {src_ip}"; '
        f'flags:S; '
        f'detection_filter:track by_src,count 20,seconds 10; '
        f'classtype:attempted-recon; '
        f'sid:{sid}; rev:1; '
        f'metadata:mitre_technique T1046, obsidios_path {path_id};)'
    )


def _rule_rservices(
    src_ip: str, dst_ip: str, sid: int, path_id: int, step: int
) -> str:
    """Detect r-services exploitation (rexec/rlogin/rsh — Metasploitable classic)."""
    return (
        f'alert tcp {src_ip} any -> {dst_ip} [512,513,514] '
        f'(msg:"OBSIDIOS PHANTOM Path#{path_id} Step#{step} '
        f'R-Services Exploitation {src_ip}->{dst_ip}"; '
        f'flow:to_server,established; '
        f'classtype:attempted-user; '
        f'sid:{sid}; rev:1; '
        f'metadata:mitre_technique T1021, obsidios_path {path_id};)'
    )


# ─────────────────────────────────────────────────────────────────────────────
# Rule selection logic
# ─────────────────────────────────────────────────────────────────────────────

async def _generate_rules_for_step(
    step: AttackStep,
    prev_step: AttackStep | None,
    path_id: int,
    step_num: int,
) -> list[ForgeRule]:
    """
    Generate Suricata rules for one step in an attack path.
    Returns a list of ForgeRule objects.
    """
    rules: list[ForgeRule] = []
    src_ip = prev_step.ip if prev_step else "any"
    dst_ip = step.ip

    technique = step.technique
    cve_id    = step.cve_id or ""

    # ── CVE-specific rules (highest priority) ─────────────────────────
    if "CVE-2011-2523" in cve_id:
        sid = await _next_sid()
        rules.append(ForgeRule(
            rule_sid       = sid,
            attack_path_id = path_id,
            rule_text      = _rule_exploit_ftp_backdoor(dst_ip, sid, path_id, step_num),
            rule_category  = "EXPLOITATION",
            mitre_technique = "T1210",
        ))
        from alerts.notifier import buffer_alert
        await buffer_alert(
            category="exploit_rules",
            title="🎯 vsftpd Backdoor",
            message=f"Target: `{dst_ip}` · Path **#{path_id}** Step **#{step_num}**",
            color="high",
        )

    elif "CVE-2007-2447" in cve_id:
        sid = await _next_sid()
        rules.append(ForgeRule(
            rule_sid       = sid,
            attack_path_id = path_id,
            rule_text      = _rule_exploit_samba(dst_ip, sid, path_id, step_num),
            rule_category  = "EXPLOITATION",
            mitre_technique = "T1210",
        ))
        from alerts.notifier import buffer_alert
        await buffer_alert(
            category="exploit_rules",
            title="🎯 Samba RCE",
            message=f"Target: `{dst_ip}` · Path **#{path_id}** Step **#{step_num}**",
            color="high",
        )

    # ── Technique-based rules ──────────────────────────────────────────
    elif technique == "T1021.004":  # SSH / Telnet
        ports = {p["port"] for p in
                 (await db.fetch_all(
                     "SELECT port FROM ports WHERE host_id="
                     "(SELECT id FROM hosts WHERE ip=?) AND state='open'",
                     (dst_ip,)
                 ) or [])}
        if 22 in ports:
            sid = await _next_sid()
            rules.append(ForgeRule(
                rule_sid        = sid,
                attack_path_id  = path_id,
                rule_text       = _rule_lateral_movement_ssh(src_ip, dst_ip, sid, path_id, step_num),
                rule_category   = "LATERAL_MOVEMENT",
                mitre_technique = "T1021.004",
            ))
        if 23 in ports:
            sid = await _next_sid()
            rules.append(ForgeRule(
                rule_sid        = sid,
                attack_path_id  = path_id,
                rule_text       = _rule_telnet_cleartext(src_ip, dst_ip, sid, path_id, step_num),
                rule_category   = "LATERAL_MOVEMENT",
                mitre_technique = "T1021.004",
            ))

    elif technique == "T1021.002":  # SMB
        sid = await _next_sid()
        rules.append(ForgeRule(
            rule_sid        = sid,
            attack_path_id  = path_id,
            rule_text       = _rule_lateral_movement_smb(src_ip, dst_ip, sid, path_id, step_num),
            rule_category   = "LATERAL_MOVEMENT",
            mitre_technique = "T1021.002",
        ))

    elif technique == "T1021.001":  # RDP
        sid = await _next_sid()
        rules.append(ForgeRule(
            rule_sid        = sid,
            attack_path_id  = path_id,
            rule_text       = _rule_lateral_movement_rdp(src_ip, dst_ip, sid, path_id, step_num),
            rule_category   = "LATERAL_MOVEMENT",
            mitre_technique = "T1021.001",
        ))

    elif technique == "T1190":  # Initial Access web
        for port in [80, 443, 8080, 8180, 8443]:
            port_exists = await db.fetch_one(
                "SELECT id FROM ports WHERE "
                "host_id=(SELECT id FROM hosts WHERE ip=?) AND port=? AND state='open'",
                (dst_ip, port)
            )
            if port_exists:
                sid = await _next_sid()
                rules.append(ForgeRule(
                    rule_sid        = sid,
                    attack_path_id  = path_id,
                    rule_text       = _rule_initial_access_web(dst_ip, port, sid, path_id, step_num),
                    rule_category   = "INITIAL_ACCESS",
                    mitre_technique = "T1190",
                ))

    elif technique == "T1021":  # r-services
        sid = await _next_sid()
        rules.append(ForgeRule(
            rule_sid        = sid,
            attack_path_id  = path_id,
            rule_text       = _rule_rservices(src_ip, dst_ip, sid, path_id, step_num),
            rule_category   = "LATERAL_MOVEMENT",
            mitre_technique = "T1021",
        ))

    elif technique == "T1071":  # C2
        sid = await _next_sid()
        rules.append(ForgeRule(
            rule_sid        = sid,
            attack_path_id  = path_id,
            rule_text       = _rule_c2_beacon(src_ip, sid, path_id),
            rule_category   = "C2",
            mitre_technique = "T1071",
        ))

    # Always add recon detection on the first step (entry point)
    if step_num == 1 and prev_step is None:
        sid = await _next_sid()
        rules.append(ForgeRule(
            rule_sid        = sid,
            attack_path_id  = path_id,
            rule_text       = _rule_port_scan_detection("any", dst_ip, sid, path_id),
            rule_category   = "RECON",
            mitre_technique = "T1046",
        ))

    return rules


# ─────────────────────────────────────────────────────────────────────────────
# Persist rules to DB
# ─────────────────────────────────────────────────────────────────────────────

async def _persist_rule(rule: ForgeRule) -> int | None:
    row = await db.execute_returning(
        """INSERT OR IGNORE INTO forge_rules
           (rule_sid, attack_path_id, rule_text, rule_category, mitre_technique,
            is_deployed, is_active)
           VALUES (?,?,?,?,?,0,1) RETURNING id""",
        (
            rule.rule_sid,
            rule.attack_path_id,
            rule.rule_text,
            rule.rule_category,
            rule.mitre_technique,
        ),
    )
    return row["id"] if row else None


# ─────────────────────────────────────────────────────────────────────────────
# Write rules file for Suricata
# ─────────────────────────────────────────────────────────────────────────────

def _format_rules_by_category(rules: list[dict]) -> str:
    from collections import defaultdict
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for r in rules:
        by_cat[r.get("rule_category", "OTHER")].append(r)

    cat_descriptions = {
        "RECON":            "Reconnaissance — port scanning at predicted entry points",
        "INITIAL_ACCESS":   "Initial Access — exploit attempts on exposed services",
        "LATERAL_MOVEMENT": "Lateral Movement — inter-host pivoting techniques",
        "EXPLOITATION":     "Exploitation — specific CVE exploit signatures",
        "C2":               "Command & Control — beaconing and C2 channel detection",
        "CREDENTIAL":       "Credential Access — brute force and credential stuffing",
    }

    output = ""
    rule_num = 1
    for cat, cat_rules in sorted(by_cat.items()):
        desc = cat_descriptions.get(cat, cat)
        output += f"# ══════════════════════════════════════════════════════════\n"
        output += f"# [{cat}] — {desc}\n"
        output += f"# {len(cat_rules)} rules in this category\n"
        output += f"# ══════════════════════════════════════════════════════════\n\n"
        for r in cat_rules:
            output += f"# Rule {rule_num:03d} | SID:{r.get('rule_sid','?')} | {r.get('mitre_technique','?')}\n"
            output += r["rule_text"] + "\n\n"
            rule_num += 1
    return output

async def write_rules_file(output_path: str = "/app/forge/rules/suricata.rules") -> int:
    """Write all active FORGE rules to a Suricata rules file — organized by category."""
    import os

    # Fetch rules WITH category
    rules = await db.fetch_all(
        """SELECT rule_text, rule_category, mitre_technique, rule_sid
           FROM forge_rules WHERE is_active=1
           ORDER BY rule_category, rule_sid"""
    )
    if not rules:
        logger.warning("[FORGE] No rules to write")
        return 0

    # Deduplicate by rule_text (removes cross-run duplicates)
    seen = set()
    unique_rules = []
    for r in rules:
        if r["rule_text"] not in seen:
            seen.add(r["rule_text"])
            unique_rules.append(dict(r))

    rule_body = _format_rules_by_category(unique_rules)

    header = (
        "# ══════════════════════════════════════════════════════════\n"
        "# OBSIDIOS FORGE — Auto-generated Suricata Detection Rules\n"
        f"# Generated : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"# Total     : {len(unique_rules)} unique rules\n"
        "# ══════════════════════════════════════════════════════════\n\n"
    )

    # Always write local copy
    local_path = "reports/output/obsidios.rules"
    os.makedirs("reports/output", exist_ok=True)
    with open(local_path, "w") as f:
        f.write(header + rule_body)
    logger.success(f"[FORGE] Wrote {len(unique_rules)} rules to {local_path}")

    # Also write to Suricata if possible
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            f.write(header + rule_body)
    except PermissionError:
        pass

    return len(unique_rules)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def run_forge(simulation: SimulationResult) -> int:
    """
    Main FORGE pipeline:
      For each PHANTOM attack path → generate custom Suricata rules
      → persist to DB → write to rules file

    Returns total rules generated.
    """
    if not simulation.paths:
        logger.warning("[FORGE] No attack paths to generate rules from")
        return 0

    logger.info(f"[FORGE] Generating rules for {len(simulation.paths)} attack paths...")
    t0          = time.perf_counter()
    total_rules = 0
    all_rules:  list[ForgeRule] = []

    for path in simulation.paths:
        if path.id is None:
            continue

        prev_step: AttackStep | None = None
        for step_num, step in enumerate(path.steps, 1):
            rules = await _generate_rules_for_step(
                step, prev_step, path.id, step_num
            )
            for rule in rules:
                rule_id = await _persist_rule(rule)
                if rule_id:
                    rule.id = rule_id
                    all_rules.append(rule)
                    total_rules += 1
            prev_step = step

    # Write Suricata rules file
    await write_rules_file()

    elapsed = time.perf_counter() - t0
    logger.success(
        f"[FORGE] Generated {total_rules} custom Suricata rules "
        f"in {elapsed*1000:.0f}ms"
    )
    if total_rules:
        cats = {}
        for r in all_rules:
            cats[r.rule_category] = cats.get(r.rule_category, 0) + 1
        from alerts.notifier import send_alert
        await send_alert(
            title="⚔ **FORGE Rules Generated**",
            message=f"**{total_rules}** custom Suricata rules from **{len(simulation.paths)}** attack paths in `{elapsed*1000:.0f}ms`",
            color="success",
            fields=[{"name": cat, "value": str(cnt), "inline": True} for cat, cnt in sorted(cats.items())],
            footer="OBSIDIOS v2.0"
        )

    # Pretty print
    _print_rules_summary(all_rules)

    return total_rules


def _print_rules_summary(rules: list[ForgeRule]) -> None:
    from rich.console import Console
    console = Console()

    # Count by category
    cats: dict[str, int] = {}
    for r in rules:
        cats[r.rule_category] = cats.get(r.rule_category, 0) + 1

    console.print("\n[bold yellow]━━━ FORGE: RULES GENERATED ━━━[/]\n")
    console.print(f"  [bold]Total custom Suricata rules:[/] [green]{len(rules)}[/]\n")

    cat_colors = {
        "RECON":            "cyan",
        "INITIAL_ACCESS":   "yellow",
        "LATERAL_MOVEMENT": "red",
        "EXPLOITATION":     "bold red",
        "C2":               "magenta",
        "CREDENTIAL":       "orange3",
    }
    for cat, count in sorted(cats.items()):
        color = cat_colors.get(cat, "white")
        console.print(f"  [{color}]{cat:<20}[/] {count} rules")

    console.print(f"\n  [dim]Rules file: reports/output/obsidios.rules[/]")
    console.print(f"  [dim]All rules stored in CHRONICLE → forge_rules table[/]\n")
