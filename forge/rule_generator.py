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
import ipaddress
import os
import re
import shlex
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass

from loguru import logger

from chronicle import db
from chronicle.models import ForgeRule
from phantom.path_finder import AttackStep, SimulationResult


@dataclass
class RuleDelivery:
    """Outcome of one attempt to put the generated ruleset in front of Suricata.

    ``ok`` means the rules file was written and is loadable. ``reload_ok`` is
    deliberately three-valued: ``None`` when no reload command is configured,
    otherwise True/False from the command's exit status. A written file that
    the sensor has not loaded is not the same as a deployed ruleset, and the
    dashboard is expected to say so.
    """

    ok: bool
    rule_count: int = 0
    path: str | None = None
    error: str | None = None
    written_at: float = 0.0
    reload_ok: bool | None = None
    reload_output: str | None = None
    quarantined: list[int] | None = None

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "rule_count": self.rule_count,
            "path": self.path,
            "error": self.error,
            "written_at": self.written_at,
            "reload_ok": self.reload_ok,
            "reload_output": self.reload_output,
            "quarantined": self.quarantined or [],
        }

    @property
    def state(self) -> str:
        """Single truthful label for the UI."""
        if not self.ok:
            return "FAILED"
        if self.rule_count == 0:
            return "EMPTY"
        if self.reload_ok is None:
            return "WRITTEN"
        return "DEPLOYED" if self.reload_ok else "WRITTEN_NO_RELOAD"


# ── SID counter (Suricata rule IDs must be unique) ─────────────────────────
# OBSIDIOS uses SID range 9000000–9999999 to avoid conflicts with
# Emerging Threats (2000000+) and Snort community rules (1000000+).
# Allocation is delegated to an atomic SQLite sequence row so concurrent
# dashboard/CLI runs can never hand out the same SID.
_SID_BASE = 9_000_000
_SID_PLACEHOLDER = 0
_SID_RE = re.compile(r"sid:(\d+);")


async def _next_sid() -> int:
    """Atomically reserve the next SID from CHRONICLE."""
    row = await db.execute_returning(
        "UPDATE forge_sid_sequence SET next_sid = next_sid + 1 "
        "WHERE id=1 RETURNING next_sid - 1 AS sid"
    )
    if row:
        return int(row["sid"])
    # Defensive fallback (should not happen after db.init seeding).
    max_sid = await db.fetch_val("SELECT MAX(rule_sid) FROM forge_rules", default=_SID_BASE - 1)
    return max(int(max_sid or _SID_BASE - 1), _SID_BASE - 1) + 1


def _replace_sid(rule_text: str, sid: int) -> str:
    """Rewrite the SID placeholder (or a previously assigned SID) in a rule."""
    return _SID_RE.sub(f"sid:{sid};", rule_text, count=1)


# ── Rule validation ────────────────────────────────────────────────────────
# Rule text is built by interpolating scan results, then loaded by Suricata.
# A single malformed rule makes Suricata reject the *entire* ruleset, so the
# sensor silently stops detecting — a self-inflicted outage. Validate before
# anything is written, and never replace a known-good file with a broken one.

_ALLOWED_ACTIONS = ("alert", "drop", "reject", "pass")
_ALLOWED_PROTOCOLS = ("tcp", "udp", "icmp", "ip", "http", "tls", "dns", "ssh", "ftp", "smb")
_SID_MIN, _SID_MAX = 9_000_000, 9_999_999


def _coerce_int(value: object) -> int | None:
    """Return an integer SID, or None when a legacy row holds junk.

    SQLite does not enforce the declared INTEGER type for every writer, so a
    hand-edited or migrated row can carry text here. Rule generation must skip
    such a row, not raise and lose the rule it was trying to persist.
    """
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _valid_address(value: object) -> str | None:
    """Return a Suricata-safe address token, or None when the value is not one.

    Accepts ``any``, a ``$VARIABLE``, an optional ``!`` negation, host
    addresses and CIDR blocks. Everything else is rejected, because these
    values originate in scan output and are spliced straight into rule syntax.
    """
    if not isinstance(value, str):
        return None
    token = value.strip()
    if not token or len(token) > 64:
        return None
    negated = token.startswith("!")
    if negated:
        token = token[1:].strip()
    if token in ("any", "$HOME_NET", "$EXTERNAL_NET"):
        return ("!" if negated else "") + token
    prefix = "!" if negated else ""
    try:
        return prefix + str(ipaddress.ip_address(token))
    except ValueError:
        pass
    try:
        return prefix + str(ipaddress.ip_network(token, strict=False))
    except ValueError:
        return None


def _strip_quoted(text: str) -> tuple[str, bool]:
    """Blank out quoted strings so structural characters can be counted.

    ``content:":)"`` is a legitimate rule, so counting raw parentheses gives a
    false positive. Returns the stripped text and whether a quote was left
    unterminated.
    """
    out: list[str] = []
    in_quote = False
    escaped = False
    for ch in text:
        if in_quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False
                out.append('"')
            continue
        if ch == '"':
            in_quote = True
            out.append('"')
        else:
            out.append(ch)
    return "".join(out), in_quote


def validate_rule(rule_text: object) -> list[str]:
    """Return a list of structural problems with one Suricata rule.

    Strict about the shape OBSIDIOS emits — one ``alert`` line with a single
    parenthesised option block — and permissive about the contents.
    """
    problems: list[str] = []
    if not isinstance(rule_text, str) or not rule_text.strip():
        return ["empty rule"]
    for bad, label in (("\n", "newline"), ("\r", "carriage return"), ("\x00", "NUL byte")):
        if bad in rule_text:
            problems.append(f"contains a {label}")
    if rule_text != rule_text.strip():
        problems.append("leading or trailing whitespace")

    text = rule_text.strip()
    header = text.split("(", 1)[0].split()
    if len(header) < 3:
        problems.append("missing rule header")
    else:
        if header[0] not in _ALLOWED_ACTIONS:
            problems.append(f"unknown action {header[0]!r}")
        if header[1] not in _ALLOWED_PROTOCOLS:
            problems.append(f"unknown protocol {header[1]!r}")
        for token in header[2:]:
            # Port groups like [139,445] never appear as bare header tokens
            # except in the port slots, so only validate obvious address tokens.
            if token in ("->", "<>", "any") or token.startswith(("$", "[", "!")):
                continue
            if _valid_address(token) is None and not token.isdigit():
                if "/" in token or "." in token or ":" in token:
                    problems.append(f"invalid address {token!r}")
    # Only the header carries network direction. Checking the whole rule lets
    # a crafted msg:"->" satisfy the requirement while Suricata still sees an
    # incomplete header.
    header_text = text.split("(", 1)[0]
    if "->" not in header_text and "<>" not in header_text:
        problems.append("missing direction operator")
    if not text.endswith(")") or "(" not in text:
        problems.append("option block is not closed")
        return problems

    options = text[text.find("(") + 1:-1]
    if not options.strip():
        problems.append("empty option block")
    stripped, unterminated = _strip_quoted(options)
    if unterminated:
        problems.append("unbalanced quotes in message")
    if stripped.count("(") != stripped.count(")"):
        problems.append("unbalanced parentheses in options")
    if not re.search(r'(^|;)\s*msg:"[^"]*[^"\s][^"]*"\s*;', options):
        problems.append("missing msg")
    sid_match = re.search(r"sid:(\d+);", options)
    if not sid_match:
        problems.append("missing sid")
    elif not (_SID_MIN <= int(sid_match.group(1)) <= _SID_MAX):
        problems.append(f"sid {sid_match.group(1)} outside the OBSIDIOS range")
    if not re.search(r"rev:\d+;", options):
        problems.append("missing rev")
    return problems


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
    src_ip: str, sid: int, path_id: int, home_net: str | None = None
) -> str:
    """Detect C2 beaconing — regular outbound intervals from compromised host."""
    # Use configured target network as HOME_NET instead of hardcoded lab subnet.
    # OBSIDIOS_TARGET like 192.168.1.0/24 -> negate to !<net> for external C2.
    if not home_net:
        home_net = os.environ.get("OBSIDIOS_TARGET", "")
    if not home_net:
        try:
            from config import settings
            home_net = settings.scan.target_network
        except Exception:
            home_net = "192.168.1.0/24"
    try:
        home_net = str(ipaddress.ip_network(home_net, strict=False))
    except ValueError:
        # Fall back to the Suricata variable rather than emitting invalid syntax.
        home_net = "$HOME_NET"
    return (
        f'alert tcp {src_ip} any -> !{home_net} any '
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

async def _buffer_exploit_rule(
    title: str, dst_ip: str, path_id: int, step_num: int
) -> None:
    """Queue an operator-facing notice without ever failing rule generation.

    Notification is a side channel: a broken notifier import, a full buffer or
    an unexpected notifier bug must never abort writing the detection rule that
    protects the network.
    """
    try:
        from alerts.notifier import buffer_alert
        await buffer_alert(
            category="exploit_rules",
            title=title,
            message=f"Target: `{dst_ip}` · Path **#{path_id}** Step **#{step_num}**",
            color="high",
        )
    except Exception as exc:
        logger.warning(f"[FORGE] Could not queue rule notification: {exc}")


async def _generate_rules_for_step(
    step: AttackStep,
    prev_step: AttackStep | None,
    path_id: int,
    step_num: int,
    home_net: str | None = None,
) -> list[ForgeRule]:
    """
    Generate Suricata rules for one step in an attack path.
    Returns a list of ForgeRule objects.
    """
    rules: list[ForgeRule] = []
    raw_src = prev_step.ip if prev_step else "any"
    src_ip = _valid_address(raw_src)
    dst_ip = _valid_address(step.ip)
    if src_ip is None or dst_ip is None:
        # Never splice unvalidated scan output into IDS syntax.
        logger.error(
            f"[FORGE] Skipping path #{path_id} step #{step_num}: "
            f"invalid address src={raw_src!r} dst={step.ip!r}"
        )
        return []

    technique = step.technique
    cve_id    = step.cve_id or ""

    # ── CVE-specific rules (highest priority) ─────────────────────────
    if "CVE-2011-2523" in cve_id:
        sid = _SID_PLACEHOLDER
        rules.append(ForgeRule(
            rule_sid       = sid,
            attack_path_id = path_id,
            rule_text      = _rule_exploit_ftp_backdoor(dst_ip, sid, path_id, step_num),
            rule_category  = "EXPLOITATION",
            mitre_technique = "T1210",
        ))
        await _buffer_exploit_rule(
            "🎯 vsftpd Backdoor", dst_ip, path_id, step_num
        )

    elif "CVE-2007-2447" in cve_id:
        sid = _SID_PLACEHOLDER
        rules.append(ForgeRule(
            rule_sid       = sid,
            attack_path_id = path_id,
            rule_text      = _rule_exploit_samba(dst_ip, sid, path_id, step_num),
            rule_category  = "EXPLOITATION",
            mitre_technique = "T1210",
        ))
        await _buffer_exploit_rule(
            "🎯 Samba RCE", dst_ip, path_id, step_num
        )

    # ── Technique-based rules ──────────────────────────────────────────
    elif technique == "T1021.004":  # SSH / Telnet
        rows = await db.fetch_all(
            "SELECT port FROM ports WHERE host_id="
            "(SELECT id FROM hosts WHERE ip=?) AND state='open'",
            (dst_ip,),
        ) or []
        # A legacy/partial row must not abort rule generation for this path.
        ports = {
            _row_value(p, "port", None) for p in rows
            if _row_value(p, "port", None) is not None
        }
        if 22 in ports:
            sid = _SID_PLACEHOLDER
            rules.append(ForgeRule(
                rule_sid        = sid,
                attack_path_id  = path_id,
                rule_text       = _rule_lateral_movement_ssh(src_ip, dst_ip, sid, path_id, step_num),
                rule_category   = "LATERAL_MOVEMENT",
                mitre_technique = "T1021.004",
            ))
        if 23 in ports:
            sid = _SID_PLACEHOLDER
            rules.append(ForgeRule(
                rule_sid        = sid,
                attack_path_id  = path_id,
                rule_text       = _rule_telnet_cleartext(src_ip, dst_ip, sid, path_id, step_num),
                rule_category   = "LATERAL_MOVEMENT",
                mitre_technique = "T1021.004",
            ))

    elif technique == "T1021.002":  # SMB
        sid = _SID_PLACEHOLDER
        rules.append(ForgeRule(
            rule_sid        = sid,
            attack_path_id  = path_id,
            rule_text       = _rule_lateral_movement_smb(src_ip, dst_ip, sid, path_id, step_num),
            rule_category   = "LATERAL_MOVEMENT",
            mitre_technique = "T1021.002",
        ))

    elif technique == "T1021.001":  # RDP
        sid = _SID_PLACEHOLDER
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
                sid = _SID_PLACEHOLDER
                rules.append(ForgeRule(
                    rule_sid        = sid,
                    attack_path_id  = path_id,
                    rule_text       = _rule_initial_access_web(dst_ip, port, sid, path_id, step_num),
                    rule_category   = "INITIAL_ACCESS",
                    mitre_technique = "T1190",
                ))

    elif technique == "T1021":  # r-services
        sid = _SID_PLACEHOLDER
        rules.append(ForgeRule(
            rule_sid        = sid,
            attack_path_id  = path_id,
            rule_text       = _rule_rservices(src_ip, dst_ip, sid, path_id, step_num),
            rule_category   = "LATERAL_MOVEMENT",
            mitre_technique = "T1021",
        ))

    elif technique == "T1071":  # C2
        sid = _SID_PLACEHOLDER
        rules.append(ForgeRule(
            rule_sid        = sid,
            attack_path_id  = path_id,
            rule_text       = _rule_c2_beacon(src_ip, sid, path_id, home_net=home_net),
            rule_category   = "C2",
            mitre_technique = "T1071",
        ))

    # Always add recon detection on the first step (entry point)
    if step_num == 1 and prev_step is None:
        sid = _SID_PLACEHOLDER
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

def _row_value(row, key: str, default=0):
    """Read a column from a sqlite3.Row or a plain dict (tests use dicts)."""
    try:
        return row[key]
    except (KeyError, IndexError):
        return default


async def _persist_rule(rule: ForgeRule) -> int | None:
    """
    Persist one generated rule.

    Rules are generated with a SID placeholder so regeneration can reuse the
    SID already assigned to an identical rule instead of minting a new one on
    every run. Unchanged rules stay stable for alert correlation.
    """
    norm = _SID_RE.sub("sid:0;", rule.rule_text, count=1)
    existing = await db.fetch_all(
        """SELECT id, rule_sid, rule_text, is_active, operator_excluded
           FROM forge_rules
           WHERE attack_path_id IS ? ORDER BY is_active DESC, id DESC""",
        (rule.attack_path_id,),
    )
    for row in existing:
        if _SID_RE.sub("sid:0;", row["rule_text"] or "", count=1) != norm:
            continue
        sid = _coerce_int(row["rule_sid"])
        if sid is None:
            logger.warning(
                f"[FORGE] Rule {_row_value(row, 'id', '?')} matches but has "
                "no usable SID; minting a fresh one"
            )
            continue
        candidate = _replace_sid(rule.rule_text, sid)
        problems = validate_rule(candidate)
        if problems:
            logger.error(
                f"[FORGE] Refusing to reuse rule {row['id']} (SID {sid}): "
                f"{'; '.join(problems)}"
            )
            return None
        rule.rule_sid = sid
        rule.rule_text = candidate
        excluded = _row_value(row, "operator_excluded", 0)
        if not row["is_active"]:
            if excluded:
                logger.info(
                    f"[FORGE] Rule {row['id']} (SID {sid}) stays excluded by "
                    f"operator decision"
                )
                return None
            await db.execute(
                "UPDATE forge_rules SET is_active=1 WHERE id=?", (row["id"],)
            )
        return row["id"]

    sid = await _next_sid()
    rule.rule_sid = sid
    rule.rule_text = _replace_sid(rule.rule_text, sid)

    problems = validate_rule(rule.rule_text)
    if problems:
        # Generated from scan data; never let a malformed rule reach the DB
        # because write_rules_file() would then hand it to Suricata.
        logger.error(
            f"[FORGE] Dropping invalid rule for path #{rule.attack_path_id} "
            f"(SID {sid}): {'; '.join(problems)}\n  {rule.rule_text[:200]}"
        )
        return None

    for attempt in range(3):
        try:
            row = await db.execute_returning(
                """INSERT INTO forge_rules
                   (rule_sid, attack_path_id, rule_text, rule_category,
                    mitre_technique, is_deployed, is_active)
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
        except Exception as exc:
            # SID unique-constraint race: reserve a fresh one and retry.
            if "UNIQUE" not in str(exc).upper():
                raise
            if attempt == 2:
                # No attempt left to use a freshly reserved SID.
                break
            sid = await _next_sid()
            candidate = _replace_sid(rule.rule_text, sid)
            # Revalidate: the retry must not smuggle a malformed rule into the
            # ruleset just because the first candidate happened to be valid.
            problems = validate_rule(candidate)
            if problems:
                logger.error(
                    f"[FORGE] Dropping rule after SID retry for path "
                    f"#{rule.attack_path_id} (SID {sid}): {'; '.join(problems)}"
                )
                return None
            rule.rule_sid = sid
            rule.rule_text = candidate
    return None


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
        output += "# ══════════════════════════════════════════════════════════\n"
        output += f"# [{cat}] — {desc}\n"
        output += f"# {len(cat_rules)} rules in this category\n"
        output += "# ══════════════════════════════════════════════════════════\n\n"
        for r in cat_rules:
            output += f"# Rule {rule_num:03d} | SID:{r.get('rule_sid','?')} | {r.get('mitre_technique','?')}\n"
            output += r["rule_text"] + "\n\n"
            rule_num += 1
    return output

def _rules_output_path() -> str:
    """Resolve the Suricata rules path (env override, else repo/container path)."""
    env_path = os.environ.get("FORGE_RULES_PATH", "").strip()
    if env_path:
        return env_path
    try:
        from config import settings
        return str(settings.BASE_DIR / "forge" / "rules" / "suricata.rules")
    except Exception:
        return "forge/rules/suricata.rules"


def ensure_rules_file(output_path: str | None = None) -> str:
    """Create an empty, loadable ruleset if FORGE has never written one.

    Suricata refuses to start when a configured rule file is missing. A fresh
    checkout therefore needs a valid placeholder before the first scan.
    """
    path = output_path or _rules_output_path()
    if os.path.exists(path):
        return path
    header = (
        "# ══════════════════════════════════════════════════════════\n"
        "# OBSIDIOS FORGE — no rules generated yet\n"
        f"# Generated : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"# Total     : 0 unique rules\n"
        "# ══════════════════════════════════════════════════════════\n"
    )
    _atomic_write(path, header)
    logger.info(f"[FORGE] Created empty ruleset at {path}")
    return path


def _atomic_write(path: str, content: str, mode: int = 0o644) -> None:
    """Write a file atomically so Suricata never reads a half-written ruleset."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".obsidios-rules-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    finally:
        # Cleanup must never replace the real write error with an unlink error
        # (the temp file can already be gone, or live on a read-only mount).
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass


async def _persist_delivery(delivery: RuleDelivery) -> None:
    """Record a delivery attempt so the dashboard can report the truth."""
    try:
        await db.execute(
            """INSERT INTO forge_delivery
               (attempted_at, ok, rule_count, path, error, reload_ok, reload_output)
               VALUES (?,?,?,?,?,?,?)""",
            (
                delivery.written_at or time.time(),
                1 if delivery.ok else 0,
                delivery.rule_count,
                delivery.path,
                delivery.error,
                None if delivery.reload_ok is None else (1 if delivery.reload_ok else 0),
                delivery.reload_output,
            ),
        )
        await db.execute(
            "DELETE FROM forge_delivery WHERE id NOT IN "
            "(SELECT id FROM forge_delivery ORDER BY id DESC LIMIT 50)"
        )
    except Exception as exc:
        logger.warning(f"[FORGE] Could not record delivery state: {exc}")


async def _run_reload() -> tuple[bool | None, str]:
    """Run the configured Suricata reload hook. ``None`` = not configured."""
    cmd = os.environ.get("FORGE_RELOAD_CMD", "").strip()
    if not cmd:
        return None, "FORGE_RELOAD_CMD not configured"
    try:
        argv = shlex.split(cmd)
    except ValueError as exc:
        return False, f"invalid FORGE_RELOAD_CMD: {exc}"
    if not argv:
        return None, "FORGE_RELOAD_CMD not configured"
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        text = (out or b"").decode("utf-8", "replace").strip()
        return proc.returncode == 0, text[-500:]
    except TimeoutError:
        if proc is not None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        return False, "reload command timed out after 15s"
    except OSError as exc:
        return False, f"could not run reload command: {exc}"


async def write_rules_file(output_path: str | None = None) -> RuleDelivery:
    """Validate, write and reload the active ruleset.

    Returns a :class:`RuleDelivery` describing exactly what happened. Callers
    that ignore the return value still get truthful logs, but the dashboard
    reads the persisted record instead of guessing.
    """
    output_path = output_path or _rules_output_path()
    delivery = RuleDelivery(ok=False, path=output_path, written_at=time.time())

    # Fetch rules WITH category
    rules = await db.fetch_all(
        """SELECT id, rule_text, rule_category, mitre_technique, rule_sid
           FROM forge_rules WHERE is_active=1
           ORDER BY rule_category, rule_sid"""
    )

    # Deduplicate by rule_text (removes cross-run duplicates)
    seen = set()
    unique_rules = []
    for r in rules:
        if r["rule_text"] not in seen:
            seen.add(r["rule_text"])
            unique_rules.append(dict(r))

    if not unique_rules:
        # An empty ruleset is still a ruleset: writing it removes detections
        # for paths that no longer exist. Returning without touching the file
        # left Suricata enforcing stale rules indefinitely.
        logger.warning("[FORGE] No active rules — writing an empty ruleset to retire stale detections")

    delivery.rule_count = len(unique_rules)

    # A single malformed rule makes Suricata drop the whole ruleset, so the
    # previous (known-good) file stays in place and the bad rows are retired.
    invalid: list[tuple[dict, list[str]]] = []
    for r in unique_rules:
        problems = validate_rule(r.get("rule_text"))
        if problems:
            invalid.append((r, problems))
    if invalid:
        sids: list[int] = []
        row_ids: list[int] = []
        for r, problems in invalid:
            sid = _coerce_int(r.get("rule_sid"))
            row_id = _coerce_int(r.get("id"))
            if sid is not None:
                sids.append(sid)
            if row_id is not None:
                row_ids.append(row_id)
            logger.error(
                f"[FORGE] Invalid rule SID {r.get('rule_sid')!r}: "
                f"{'; '.join(problems)} — quarantined, ruleset not rewritten"
            )

        # Prefer the primary key: a row with a corrupt SID can still be
        # deactivated, so the same bad row does not abort every future write.
        clauses: list[str] = []
        params: list[int] = []
        if row_ids:
            clauses.append(f"id IN ({','.join('?' for _ in row_ids)})")
            params.extend(row_ids)
        if sids:
            clauses.append(f"rule_sid IN ({','.join('?' for _ in sids)})")
            params.extend(sids)
        if clauses:
            try:
                await db.execute(
                    "UPDATE forge_rules SET is_active=0, is_deployed=0 WHERE "  # nosec B608 - placeholders only
                    + " OR ".join(clauses),
                    tuple(params),
                )
            except Exception as exc:
                logger.warning(f"[FORGE] Could not quarantine invalid rules: {exc}")
        delivery.error = (
            f"refused to write: {len(invalid)} invalid rule(s) "
            f"({', '.join(str(s) for s in sids[:10]) or 'unidentified'})"
        )
        delivery.quarantined = sids
        await _persist_delivery(delivery)
        return delivery

    rule_body = _format_rules_by_category(unique_rules)

    header = (
        "# ══════════════════════════════════════════════════════════\n"
        "# OBSIDIOS FORGE — Auto-generated Suricata Detection Rules\n"
        f"# Generated : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"# Total     : {len(unique_rules)} unique rules\n"
        "# ══════════════════════════════════════════════════════════\n\n"
    )

    payload = header + rule_body

    # Always write local copy (used by reports / operators). A failure here is
    # reported but does not block the sensor from getting its rules.
    try:
        from config import settings
        local_path = str(settings.REPORTS_DIR / "obsidios.rules")
    except Exception:
        local_path = "reports/output/obsidios.rules"
    try:
        _atomic_write(local_path, payload)
        logger.success(f"[FORGE] Wrote {len(unique_rules)} rules to {local_path}")
    except OSError as exc:
        # Read-only mounts are expected (the dashboard only needs the sensor
        # path); this copy is a convenience for reports.
        logger.warning(f"[FORGE] Could not write local rules copy {local_path}: {exc}")

    try:
        _atomic_write(output_path, payload)
    except OSError as exc:
        delivery.ok = False
        delivery.error = f"could not write {output_path}: {exc}"
        logger.error(f"[FORGE] {delivery.error}")
        await _persist_delivery(delivery)
        return delivery

    delivery.ok = True
    logger.success(f"[FORGE] Wrote {len(unique_rules)} rules to {output_path}")

    # The file on disk is now the source of truth: a rule is "deployed" iff it
    # is active and was present in this write.
    try:
        await db.execute(
            "UPDATE forge_rules SET is_deployed = is_active, "
            "delivered_at = CASE WHEN is_active=1 THEN ? ELSE delivered_at END",
            (delivery.written_at,),
        )
    except Exception as exc:
        logger.warning(f"[FORGE] Could not update per-rule delivery state: {exc}")

    delivery.reload_ok, delivery.reload_output = await _run_reload()
    if delivery.reload_ok is False:
        logger.error(f"[FORGE] Rules written but reload failed: {delivery.reload_output}")
    elif delivery.reload_ok is None:
        logger.warning(
            "[FORGE] Rules written; set FORGE_RELOAD_CMD (e.g. "
            "'suricatasc -c reload-rules') so Suricata picks them up"
        )
    else:
        logger.success("[FORGE] Suricata reloaded the new ruleset")

    await _persist_delivery(delivery)
    return delivery


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def _retire_stale_rules() -> None:
    """Deactivate rules whose attack path is no longer active."""
    try:
        await db.execute(
            """UPDATE forge_rules SET is_active=0
               WHERE is_active=1 AND attack_path_id IS NOT NULL
                 AND attack_path_id NOT IN
                     (SELECT id FROM attack_paths WHERE is_active=1)"""
        )
    except Exception as exc:
        logger.warning(f"[FORGE] Could not retire stale rules: {exc}")


async def _forge_home_net() -> str | None:
    """HOME_NET for C2 rules: the dashboard target, not the start-up env."""
    target = ""
    try:
        if getattr(db, "_initialized", False):
            target = await db.fetch_val(
                "SELECT value FROM system_settings WHERE key='target_network'",
                default="") or ""
    except Exception as exc:
        logger.warning(f"[FORGE] Could not read target network: {exc}")
    if not target:
        return None
    try:
        return str(ipaddress.ip_network(target.strip(), strict=False))
    except ValueError:
        return None


async def run_forge(simulation: SimulationResult) -> int:
    """
    Main FORGE pipeline:
      For each PHANTOM attack path → generate custom Suricata rules
      → persist to DB → write to rules file

    Returns total rules generated.
    """
    if not simulation.paths:
        await _retire_stale_rules()
        # Rewrite/reload even with zero paths: this is how rules belonging to
        # retired paths leave the sensor. An early return left them loaded.
        delivery = await write_rules_file()
        logger.warning(
            f"[FORGE] No attack paths to generate rules from — ruleset "
            f"rewritten ({delivery.state}, {delivery.rule_count} active rule(s))"
        )
        return 0

    logger.info(f"[FORGE] Generating rules for {len(simulation.paths)} attack paths...")
    home_net = await _forge_home_net()
    t0          = time.perf_counter()
    total_rules = 0
    all_rules:  list[ForgeRule] = []
    touched:    dict[int, set[int]] = defaultdict(set)

    for path in simulation.paths:
        if path.id is None:
            continue

        prev_step: AttackStep | None = None
        for step_num, step in enumerate(path.steps, 1):
            rules = await _generate_rules_for_step(
                step, prev_step, path.id, step_num, home_net=home_net
            )
            for rule in rules:
                try:
                    rule_id = await _persist_rule(rule)
                except Exception as exc:
                    # One unwritable rule must not throw away every rule
                    # generated after it.
                    logger.error(
                        f"[FORGE] Could not persist rule for path #{path.id} "
                        f"step #{step_num}: {exc}"
                    )
                    continue
                if rule_id:
                    rule.id = rule_id
                    touched[path.id].add(rule_id)
                    all_rules.append(rule)
                    total_rules += 1
            prev_step = step

        # Rules that this path no longer produces must not stay deployed.
        keep = touched.get(path.id, set())
        if keep:
            placeholders = ",".join("?" for _ in keep)
            try:
                await db.execute(
                    f"UPDATE forge_rules SET is_active=0 "  # nosec B608 - placeholders only
                    f"WHERE attack_path_id=? AND is_active=1 "
                    f"AND id NOT IN ({placeholders})",
                    (path.id, *sorted(keep)),
                )
            except Exception as exc:
                logger.warning(f"[FORGE] Could not prune rules for path #{path.id}: {exc}")

    await _retire_stale_rules()

    # Write and reload. The result is the only honest source of "deployed".
    delivery = await write_rules_file()

    elapsed = time.perf_counter() - t0
    if delivery.ok:
        logger.success(
            f"[FORGE] Generated {total_rules} custom Suricata rules in "
            f"{elapsed*1000:.0f}ms ({delivery.state}, {delivery.rule_count} written)"
        )
    else:
        logger.error(
            f"[FORGE] Generated {total_rules} rules in {elapsed*1000:.0f}ms but "
            f"delivery FAILED: {delivery.error}"
        )
    if total_rules:
        cats = {}
        for r in all_rules:
            cats[r.rule_category] = cats.get(r.rule_category, 0) + 1
        # Delivery already happened; a dead webhook must not turn a successful
        # ruleset write into an exception the scheduler reports as a failure.
        try:
            from alerts.notifier import send_alert
            await send_alert(
                title="⚔ **FORGE Rules Generated**",
                message=(
                    f"**{total_rules}** custom Suricata rules from "
                    f"**{len(simulation.paths)}** attack paths in `{elapsed*1000:.0f}ms` — "
                    f"delivery: **{delivery.state}**"
                    + (f" ({delivery.error})" if delivery.error else "")
                ),
                color="success" if delivery.ok else "warning",
                fields=[{"name": cat, "value": str(cnt), "inline": True} for cat, cnt in sorted(cats.items())],
                footer="OBSIDIOS v2.0"
            )
        except Exception as exc:
            logger.warning(f"[FORGE] Could not deliver rule summary: {exc}")

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

    console.print("\n  [dim]Rules file: reports/output/obsidios.rules[/]")
    console.print("  [dim]All rules stored in CHRONICLE → forge_rules table[/]\n")
