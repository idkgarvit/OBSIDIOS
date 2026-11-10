"""
shield/reconfigurer.py
───────────────────────
SHIELD — Autonomous Firewall Reconfiguration Engine.

When PHANTOM identifies a kill chain and SENTINEL or ECHO fires an alert
matching that prediction, SHIELD automatically closes the attack path
by injecting iptables rules — without human intervention.

Every action is:
  • Logged to CHRONICLE with full justification
  • Reversible with one command
  • Tagged with the PHANTOM path that triggered it
  • Reviewed in the ORACLE report

Actions SHIELD can take:
  BLOCK_IP        — Drop all traffic from a source IP
  BLOCK_PATH      — Block a specific src→dst port combination
  QUARANTINE_HOST — Isolate a host (block all inbound + outbound)
  CLOSE_PORT      — Block a specific port network-wide

Confidence thresholds:
  > 0.9  → SHIELD acts autonomously
  > 0.7  → SHIELD acts + sends alert
  < 0.7  → SHIELD only alerts, human decides

Safety model:
  • SHIELD_DRY_RUN=1 by default (nothing is enforced until explicitly enabled)
  • Allowlisted hosts (gateway, DNS, loopback) are never blocked
  • Rate-limited to SHIELD_MAX_ACTIONS_PER_HOUR enforced blocks/hour
  • Rules are inserted at the head of the chain, so they cannot be bypassed
    by a preceding ACCEPT
  • Partial rule sets are rolled back — SHIELD never leaves orphan rules
  • Every applied rule is removable via revert_action()/stop_shield()
"""
from __future__ import annotations

import asyncio
import math
import os
import shlex
import time

from loguru import logger

from chronicle import db
from chronicle.models import ShieldActionType

# ── Confidence threshold for autonomous action ─────────────────────────────
AUTO_ACT_THRESHOLD = 0.85
ALERT_THRESHOLD    = 0.70

IPTABLES_BIN = os.environ.get("IPTABLES_BIN", "iptables")
IPTABLES_WAIT_SECS = 5
IPTABLES_TIMEOUT_SECS = 20  # hard cap even if -w somehow blocks forever

# iptables prints one of these when `-C` proves the rule is absent. Any other
# failure (EPERM, xtables lock, missing binary, timeout) is inconclusive.
_IPTABLES_ABSENT_MARKERS = (
    "does not exist",
    "no chain/target/match",
    "bad rule",
)

# Chains used by each action type. Revert logic mirrors these exactly.
_QUARANTINE_RULES = (
    ("INPUT",   ("-s", "{ip}", "-j", "DROP")),
    ("OUTPUT",  ("-d", "{ip}", "-j", "DROP")),
    ("FORWARD", ("-s", "{ip}", "-j", "DROP")),
    ("FORWARD", ("-d", "{ip}", "-j", "DROP")),
)


def _shield_cfg():
    try:
        from config.settings import is_ip_allowlisted, parse_shield_allowlist
        from config.settings import shield_cfg as _c
        return _c, parse_shield_allowlist, is_ip_allowlisted
    except Exception:
        return None, None, None


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _truthy(value: object) -> bool:
    """Interpret DB/API flags without treating the string ``"0"`` as true."""
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "predicted")
    return bool(value)


def _coerce_confidence(value: object) -> float | None:
    """Return a finite 0..1 confidence, or ``None`` when it is unusable.

    ECHO derives confidence from network statistics. A NaN (empty/malformed
    sample) compares false against every threshold, so the old
    ``confidence < AUTO_ACT_THRESHOLD`` guard let it through and could
    quarantine a host on garbage. Fail closed instead.
    """
    if isinstance(value, bool):
        return None
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(confidence):
        return None
    return max(0.0, min(1.0, confidence))


async def _shield_guard(target_ip: str | None, action: str) -> tuple[bool, str]:
    """Company safety: dry-run, allowlist, rate-limit. Returns (allowed, reason).

    ``target_ip`` is ``None`` for actions that only concern a port (there is no
    address to allowlist); dry-run and the rate limit still apply.
    """
    cfg, parse_fn, match_fn = _shield_cfg()

    # Dry-run is on unless explicitly disabled. Env is authoritative; the
    # settings object is only a fallback (it is cached at import time).
    default_dry = bool(getattr(cfg, "dry_run", True)) if cfg is not None else True
    dry = _env_flag("SHIELD_DRY_RUN", default_dry)
    if dry:
        subject = target_ip if target_ip is not None else "all traffic"
        return False, f"DRY-RUN active — would {action} {subject} (set SHIELD_DRY_RUN=0 to enforce)"

    # Allowlist: never block gateway, DNS, loopback, or operator list.
    if target_ip is not None:
        try:
            if match_fn is None:
                # If the allowlist implementation cannot be imported we have no way
                # to know whether the target is the gateway or a DNS server.
                return False, f"Allowlist unavailable — refusing to {action} {target_ip}"
            gw = os.environ.get("OBSIDIOS_GATEWAY", "192.168.1.1")
            allow = parse_fn(gw) if parse_fn else [gw]
            if match_fn(target_ip, allow):
                return False, f"Allowlisted — refusing to {action} protected {target_ip}"
        except Exception:
            # Fail closed: if the allowlist cannot be evaluated, do not enforce.
            return False, f"Allowlist check failed — refusing to {action} {target_ip}"

    # Rate-limit: max N active enforcements per hour (prevents block storms).
    # Fail closed: if the counter cannot be read, do not enforce, because an
    # un-auditable block is worse than a missed block.
    try:
        # Env is authoritative, matching the dry-run flag above; the settings
        # object is only a fallback (it is cached at import time).
        raw_limit = os.environ.get("SHIELD_MAX_ACTIONS_PER_HOUR", "").strip()
        if raw_limit:
            max_n = int(raw_limit)
        elif cfg is not None:
            max_n = int(getattr(cfg, "max_actions_per_hour", 10))
        else:
            max_n = 10
        cnt = await db.fetch_val(
            "SELECT COUNT(*) FROM shield_actions WHERE taken_at > ? AND is_active=1",
            (time.time() - 3600,),
            default=0,
        )
        if (cnt or 0) >= max_n:
            return False, f"Rate-limited ({cnt}/{max_n} blocks this hour) — alert only"
    except Exception as exc:
        logger.error(f"[SHIELD] Rate-limit check failed — refusing to {action} {target_ip or 'all traffic'}: {exc}")
        return False, "rate-limit check failed — refusing to enforce"
    return True, "ok"


# ─────────────────────────────────────────────────────────────────────────────
# iptables wrapper
# ─────────────────────────────────────────────────────────────────────────────

async def _run_iptables(args: list[str], check: bool = True) -> tuple[bool, str]:
    """
    Run an iptables command asynchronously.
    Returns (success, output).
    """
    cmd = [IPTABLES_BIN, "-w", str(IPTABLES_WAIT_SECS)] + args
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout = asyncio.subprocess.PIPE,
            stderr = asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=IPTABLES_TIMEOUT_SECS
            )
        except TimeoutError:
            # The child may have exited between wait_for() cancelling the read
            # and kill(); losing that race must still produce a timeout result,
            # not raise out of a fail-closed path.
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except ProcessLookupError:
                pass
            logger.error(f"[SHIELD] iptables timed out after {IPTABLES_TIMEOUT_SECS}s: {' '.join(cmd)}")
            return False, "iptables timed out"
        success = proc.returncode == 0
        output  = (stdout + stderr).decode(errors="replace").strip()
        if not success:
            logger.warning(f"[SHIELD] iptables failed: {' '.join(cmd)} → {output}")
        return success, output
    except FileNotFoundError:
        logger.error("[SHIELD] iptables not found — cannot enforce blocks")
        return False, "SIMULATION"
    except Exception as exc:
        logger.error(f"[SHIELD] iptables error: {exc}")
        return False, str(exc)


async def _iptables_rule_state(chain: str, spec: tuple[str, ...] | list[str]) -> bool | None:
    """Return True if the rule exists, False if it is definitely absent.

    ``None`` means the check itself failed (iptables missing, permission
    denied, locked xtables, timeout). Callers that remove rules must not treat
    "could not check" as "already gone": that would mark a still-live DROP rule
    as reverted and make it unremovable by ``stop_shield()``.
    """
    success, output = await _run_iptables(["-C", chain, *spec], check=False)
    if success:
        return True
    if output == "SIMULATION" or "timed out" in output:
        return None
    lowered = output.lower()
    if any(marker in lowered for marker in _IPTABLES_ABSENT_MARKERS):
        return False
    return None


async def _iptables_rule_exists(chain: str, spec: tuple[str, ...] | list[str]) -> bool:
    """True only if the exact rule is confirmed present in `chain`."""
    return await _iptables_rule_state(chain, spec) is True


async def _delete_rule(chain: str, spec: tuple[str, ...] | list[str], max_tries: int = 5) -> bool:
    """Delete every copy of a rule. Returns True only when absence is confirmed."""
    for _ in range(max_tries):
        state = await _iptables_rule_state(chain, spec)
        if state is False:
            return True
        if state is None:
            # Cannot prove the rule is gone, so never report the revert as done.
            logger.error(
                f"[SHIELD] Cannot verify whether {chain} rule was removed: {spec}"
            )
            return False
        ok, _ = await _run_iptables(["-D", chain, *spec], check=False)
        if not ok:
            # A concurrent revert may have removed it; re-check next loop.
            continue
    return await _iptables_rule_state(chain, spec) is False


async def _apply_rules(rules: list[tuple[str, tuple[str, ...]]]) -> tuple[bool, str]:
    """
    Insert rules at the head of their chain. Rolls back every rule added in
    this call if any insert fails, so no partial/orphan state is left behind.
    """
    added: list[tuple[str, tuple[str, ...]]] = []
    for chain, spec in rules:
        if await _iptables_rule_exists(chain, spec):
            continue
        ok, output = await _run_iptables(["-I", chain, "1", *spec])
        if not ok:
            for added_chain, added_spec in added:
                await _delete_rule(added_chain, added_spec)
            return False, output
        added.append((chain, spec))
    return True, "ok"


async def _remove_rules(rules: list[tuple[str, tuple[str, ...]]]) -> bool:
    """Remove every copy of every rule. Returns True only if all are absent."""
    results = [await _delete_rule(chain, spec) for chain, spec in rules]
    return all(results)


def _quarantine_rules(ip: str) -> list[tuple[str, tuple[str, ...]]]:
    return [(chain, tuple(part.format(ip=ip) for part in spec))
            for chain, spec in _QUARANTINE_RULES]


def _block_ip_rules(ip: str) -> list[tuple[str, tuple[str, ...]]]:
    """Drop traffic from `ip` addressed to this host and traffic it forwards."""
    return [
        ("INPUT",   ("-s", ip, "-j", "DROP")),
        ("FORWARD", ("-s", ip, "-j", "DROP")),
    ]


def _close_port_rules(port: int, protocol: str = "tcp") -> list[tuple[str, tuple[str, ...]]]:
    """Drop new traffic to `port` on this host and on traffic it forwards."""
    return [
        ("INPUT",   ("-p", protocol, "--dport", str(port), "-j", "DROP")),
        ("FORWARD", ("-p", protocol, "--dport", str(port), "-j", "DROP")),
    ]


def _rule_protocol(rule: object) -> str:
    """Protocol recorded in a rule string, defaulting to tcp."""
    text = rule if isinstance(rule, str) else ""
    for proto in ("tcp", "udp"):
        if f"-p {proto}" in text:
            return proto
    return "tcp"


def _block_path_rule(
    src_ip: str, dst_ip: str, dst_port: int | None, protocol: str
) -> tuple[str, tuple[str, ...]]:
    spec: tuple[str, ...] = ("-s", src_ip, "-d", dst_ip, "-p", protocol)
    if protocol in ("tcp", "udp") and dst_port:
        spec = spec + ("--dport", str(dst_port))
    return "FORWARD", spec + ("-j", "DROP")


async def _audit_refused(
    action_type: ShieldActionType,
    target_ip: str | None,
    reason: str,
    trigger_type: str,
    trigger_id: int | None,
    confidence: float,
    justification: str,
    src_ip: str | None = None,
    target_port: int | None = None,
) -> None:
    """Record a refused/failed attempt so the intent is auditable."""
    try:
        await db.execute(
            """INSERT INTO shield_actions
               (action_type, target_ip, src_ip, target_port, rule_applied,
                trigger_type, trigger_id, confidence, justification, is_active)
               VALUES (?,?,?,?,?,?,?,?,?,0)""",
            (
                str(action_type), target_ip, src_ip, target_port,
                f"REFUSED: {reason}", trigger_type, trigger_id, confidence,
                f"{justification} [{reason}]",
            ),
        )
    except Exception:
        pass


async def _record_action(
    sql: str,
    params: tuple,
    rules: list[tuple[str, tuple[str, ...]]],
) -> int | None:
    """Persist an applied action, or undo the firewall change.

    A live iptables rule with no matching `shield_actions` row is invisible to
    `revert_action()` and `stop_shield()` — an operator could never remove it.
    If the write fails (locked/full/corrupt DB), the rules are removed again
    and the action is reported as failed instead.
    """
    try:
        row = await db.execute_returning(sql, params)
        action_id = row["id"] if row else None
    except Exception as exc:
        logger.error(f"[SHIELD] Could not record action — rolling back rules: {exc}")
        action_id = None
    if action_id is None:
        await _remove_rules(rules)
    return action_id


# ─────────────────────────────────────────────────────────────────────────────
# Shield actions
# ─────────────────────────────────────────────────────────────────────────────

async def block_ip(
    src_ip:      str,
    justification: str,
    trigger_type:  str = "MANUAL",
    trigger_id:    int | None = None,
    confidence:    float = 1.0,
) -> dict:
    """
    Block all traffic from a source IP.
    Inserts DROP rules at the head of INPUT and FORWARD.
    """
    import ipaddress as _ip
    src_ip = str(src_ip).strip()
    try:
        _ip.ip_address(src_ip)
    except Exception:
        return {"status": "rejected", "ip": src_ip, "reason": "invalid IP"}

    allowed, reason = await _shield_guard(src_ip, "BLOCK_IP")
    if not allowed:
        logger.warning(f"[SHIELD] Guard refused BLOCK_IP {src_ip}: {reason}")
        await _audit_refused(
            ShieldActionType.BLOCK_IP, src_ip, reason,
            trigger_type, trigger_id, confidence, justification,
        )
        return {"status": "refused", "ip": src_ip, "reason": reason}

    rules = _block_ip_rules(src_ip)
    rule = "; ".join(f"-I {chain} {' '.join(spec)}" for chain, spec in rules)

    if all([await _iptables_rule_exists(chain, spec) for chain, spec in rules]):
        logger.info(f"[SHIELD] IP {src_ip} already blocked")
        return {"status": "already_exists", "ip": src_ip}

    # The DB can claim this IP is blocked after a reboot/flush removed the
    # kernel rules. Re-apply and refresh that row; inserting a second active
    # row made every drift cycle add another "active block" entry that all
    # describe the same rule.
    already = await db.fetch_one(
        """SELECT id FROM shield_actions
           WHERE action_type='BLOCK_IP' AND target_ip=? AND is_active=1
           ORDER BY id DESC LIMIT 1""",
        (src_ip,),
    )

    success, output = await _apply_rules(rules)

    action_id = None
    if success:
        if already:
            action_id = already["id"]
            try:
                await db.execute(
                    "UPDATE shield_actions SET taken_at=?, confidence=?, "
                    "trigger_id=?, justification=? WHERE id=?",
                    (time.time(), confidence, trigger_id, justification,
                     action_id),
                )
            except Exception as exc:
                logger.warning(
                    f"[SHIELD] Re-applied block #{action_id} but could not "
                    f"refresh its audit row: {exc}"
                )
        else:
            action_id = await _record_action(
                """INSERT INTO shield_actions
                   (action_type, target_ip, rule_applied, trigger_type,
                    trigger_id, confidence, justification, is_active)
                   VALUES (?,?,?,?,?,?,?,1) RETURNING id""",
                (
                    str(ShieldActionType.BLOCK_IP), src_ip, rule,
                    trigger_type, trigger_id, confidence, justification,
                ),
                rules,
            )
        success = action_id is not None
        if not success:
            output = "action could not be recorded"

    if success:
        logger.success(f"[SHIELD] Blocked IP: {src_ip} (action_id={action_id})")
    else:
        logger.error(f"[SHIELD] Failed to block IP {src_ip}: {output}")
        await _audit_refused(
            ShieldActionType.BLOCK_IP, src_ip, f"iptables failed: {output}",
            trigger_type, trigger_id, confidence, justification,
        )

    return {
        "status":    "blocked" if success else "failed",
        "ip":        src_ip,
        "rule":      rule,
        "action_id": action_id,
    }


async def block_path(
    src_ip:  str,
    dst_ip:  str,
    dst_port: int | None,
    protocol: str = "tcp",
    justification: str = "",
    trigger_type:  str = "PHANTOM",
    trigger_id:    int | None = None,
    confidence:    float = 1.0,
) -> dict:
    """
    Block traffic from src_ip to dst_ip:dst_port.
    More surgical than block_ip — only blocks this specific attack path.
    """
    import ipaddress as _ip
    protocol = str(protocol or "tcp").strip().lower()
    src_ip = str(src_ip).strip()
    dst_ip = str(dst_ip).strip()
    try:
        _ip.ip_address(src_ip); _ip.ip_address(dst_ip)
        if protocol not in ("tcp", "udp", "icmp"):
            raise ValueError("protocol")
        if protocol == "icmp":
            _port: int | None = None
        else:
            _port = int(dst_port)  # type: ignore[arg-type]
            if not 1 <= _port <= 65535:
                raise ValueError("port")
    except Exception:
        return {"status": "rejected", "reason": "invalid src/dst/port/protocol"}

    for _t in (src_ip, dst_ip):
        allowed, reason = await _shield_guard(_t, "BLOCK_PATH")
        if not allowed:
            logger.warning(f"[SHIELD] Guard refused BLOCK_PATH {src_ip}->{dst_ip}:{dst_port}: {reason}")
            await _audit_refused(
                ShieldActionType.BLOCK_PATH, dst_ip, reason,
                trigger_type, trigger_id, confidence, justification,
                src_ip=src_ip, target_port=_port,
            )
            return {"status": "refused", "src_ip": src_ip, "dst_ip": dst_ip,
                    "dst_port": _port, "reason": reason}

    chain, spec = _block_path_rule(src_ip, dst_ip, _port, protocol)
    rule = f"-A {chain} {' '.join(spec)}"

    # Dedupe on the full 4-tuple (src, dst, port, protocol); the previous
    # check ignored both the source and the protocol, so a TCP block
    # suppressed a legitimate UDP block of the same port.
    already = await db.fetch_one(
        """SELECT id FROM shield_actions
           WHERE action_type='BLOCK_PATH' AND src_ip=? AND target_ip=?
             AND target_port IS ? AND is_active=1
             AND rule_applied LIKE ?""",
        (src_ip, dst_ip, _port, f"%-p {protocol}%"),
    )

    if await _iptables_rule_exists(chain, spec):
        logger.info(f"[SHIELD] Path {src_ip}→{dst_ip}:{_port}/{protocol} already blocked")
        return {"status": "already_exists", "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": _port}

    if already:
        # The DB says this path is blocked but the kernel has no matching rule
        # (host rebooted, ruleset flushed, manual iptables -F). Reporting
        # "already_exists" here would advertise protection that does not exist
        # and never re-install it. Re-apply and refresh the existing audit row.
        success, output = await _apply_rules([(chain, spec)])
        if success:
            try:
                await db.execute(
                    "UPDATE shield_actions SET taken_at=?, confidence=?, "
                    "trigger_id=?, justification=? WHERE id=?",
                    (time.time(), confidence, trigger_id, justification,
                     already["id"]),
                )
            except Exception as exc:
                logger.warning(
                    f"[SHIELD] Re-applied block #{already['id']} but could not "
                    f"refresh its audit row: {exc}"
                )
            logger.success(
                f"[SHIELD] Re-applied drifted block: {src_ip} → "
                f"{dst_ip}:{_port}/{protocol} (action_id={already['id']})"
            )
            return {
                "status":    "blocked",
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "dst_port":  _port,
                "action_id": already["id"],
                "reapplied": True,
            }

        logger.error(
            f"[SHIELD] Failed to re-apply drifted block {src_ip}→{dst_ip}:{_port}: {output}"
        )
        await _audit_refused(
            ShieldActionType.BLOCK_PATH, dst_ip, f"iptables failed: {output}",
            trigger_type, trigger_id, confidence, justification,
            src_ip=src_ip, target_port=_port,
        )
        return {
            "status":   "failed",
            "src_ip":   src_ip,
            "dst_ip":   dst_ip,
            "dst_port": _port,
        }

    success, output = await _apply_rules([(chain, spec)])

    action_id = None
    if success:
        action_id = await _record_action(
            """INSERT INTO shield_actions
               (action_type, target_ip, src_ip, target_port, rule_applied,
                trigger_type, trigger_id, confidence, justification, is_active)
               VALUES (?,?,?,?,?,?,?,?,?,1) RETURNING id""",
            (
                str(ShieldActionType.BLOCK_PATH), dst_ip, src_ip, _port, rule,
                trigger_type, trigger_id, confidence, justification,
            ),
            [(chain, spec)],
        )
        success = action_id is not None
        if not success:
            output = "action could not be recorded"

    if success:
        logger.success(
            f"[SHIELD] Blocked path: {src_ip} → {dst_ip}:{_port}/{protocol} "
            f"(action_id={action_id})"
        )
    else:
        logger.error(f"[SHIELD] Failed to block path {src_ip}→{dst_ip}:{_port}: {output}")
        await _audit_refused(
            ShieldActionType.BLOCK_PATH, dst_ip, f"iptables failed: {output}",
            trigger_type, trigger_id, confidence, justification,
            src_ip=src_ip, target_port=_port,
        )

    return {
        "status":    "blocked" if success else "failed",
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "dst_port":  _port,
        "action_id": action_id,
    }


async def quarantine_host(
    ip: str,
    justification: str,
    trigger_type: str = "ECHO",
    trigger_id: int | None = None,
    confidence: float = 1.0,
) -> dict:
    """
    Full quarantine — block all inbound AND outbound traffic for a host.

    INPUT/OUTPUT cover traffic to/from the sensor itself; FORWARD covers
    traffic the sensor routes on behalf of the quarantined host. Rules are
    inserted at the head of each chain and rolled back as a set on failure.

    Company default: disabled unless SHIELD_AUTO_QUARANTINE=1.
    """
    import ipaddress as _ip
    ip = str(ip).strip()
    try:
        _ip.ip_address(ip)
    except Exception:
        return {"status": "rejected", "ip": ip, "reason": "invalid IP"}

    cfg, _, _ = _shield_cfg()
    cfg_auto = bool(getattr(cfg, "auto_quarantine", False)) if cfg is not None else False
    auto_q = _env_flag("SHIELD_AUTO_QUARANTINE", cfg_auto)
    if not auto_q:
        logger.warning(f"[SHIELD] Quarantine refused for {ip}: SHIELD_AUTO_QUARANTINE=0 (alert only)")
        await _audit_refused(
            ShieldActionType.QUARANTINE_HOST, ip,
            "auto-quarantine disabled [requires SHIELD_AUTO_QUARANTINE=1]",
            trigger_type, trigger_id, confidence, justification,
        )
        return {"status": "refused", "ip": ip, "reason": "auto-quarantine disabled"}

    allowed, reason = await _shield_guard(ip, "QUARANTINE_HOST")
    if not allowed:
        logger.warning(f"[SHIELD] Guard refused QUARANTINE {ip}: {reason}")
        await _audit_refused(
            ShieldActionType.QUARANTINE_HOST, ip, reason,
            trigger_type, trigger_id, confidence, justification,
        )
        return {"status": "refused", "ip": ip, "reason": reason}

    rules = _quarantine_rules(ip)
    if all([await _iptables_rule_exists(chain, spec) for chain, spec in rules]):
        logger.info(f"[SHIELD] Host {ip} is already quarantined")
        return {"status": "already_exists", "ip": ip}

    success, output = await _apply_rules(rules)
    rule = f"QUARANTINE {ip} (INPUT/OUTPUT/FORWARD DROP)"

    action_id = None
    if success:
        action_id = await _record_action(
            """INSERT INTO shield_actions
               (action_type, target_ip, rule_applied, trigger_type,
                trigger_id, confidence, justification, is_active)
               VALUES (?,?,?,?,?,?,?,1) RETURNING id""",
            (
                str(ShieldActionType.QUARANTINE_HOST), ip, rule,
                trigger_type, trigger_id, confidence, justification,
            ),
            rules,
        )
        success = action_id is not None
        if not success:
            output = "action could not be recorded"

    if success:
        logger.success(f"[SHIELD] HOST QUARANTINED: {ip} (action_id={action_id})")
    else:
        logger.error(f"[SHIELD] Failed to quarantine {ip}: {output}")
        await _audit_refused(
            ShieldActionType.QUARANTINE_HOST, ip, f"iptables failed: {output}",
            trigger_type, trigger_id, confidence, justification,
        )

    return {"status": "quarantined" if success else "failed", "ip": ip, "action_id": action_id}


async def close_port(
    port: int,
    protocol: str = "tcp",
    justification: str = "",
    trigger_type: str = "MANUAL",
    trigger_id: int | None = None,
    confidence: float = 1.0,
) -> dict:
    """Close one port on this host and on traffic it forwards (network-wide).

    This is the port-scoped counterpart of BLOCK_IP: INPUT drops connections to
    the sensor, FORWARD drops traffic routed to protected hosts. Like every
    other SHIELD action it is reversible by ``revert_action()``.
    """
    protocol = str(protocol or "tcp").strip().lower()
    try:
        port = int(port)
        if protocol not in ("tcp", "udp") or not 1 <= port <= 65535:
            raise ValueError("port/protocol")
    except (TypeError, ValueError):
        return {"status": "rejected", "reason": "invalid port/protocol"}

    allowed, reason = await _shield_guard(None, "CLOSE_PORT")
    if not allowed:
        logger.warning(f"[SHIELD] Guard refused CLOSE_PORT {port}/{protocol}: {reason}")
        await _audit_refused(
            ShieldActionType.CLOSE_PORT, None, reason,
            trigger_type, trigger_id, confidence, justification,
            target_port=port,
        )
        return {"status": "refused", "port": port, "protocol": protocol,
                "reason": reason}

    rules = _close_port_rules(port, protocol)
    rule = "; ".join(f"-I {chain} {' '.join(spec)}" for chain, spec in rules)

    already = await db.fetch_one(
        """SELECT id FROM shield_actions
           WHERE action_type='CLOSE_PORT' AND target_port IS ? AND is_active=1
             AND rule_applied LIKE ?
           ORDER BY id DESC LIMIT 1""",
        (port, f"%-p {protocol}%"),
    )

    if all([await _iptables_rule_exists(chain, spec) for chain, spec in rules]):
        logger.info(f"[SHIELD] Port {port}/{protocol} already closed")
        return {"status": "already_exists", "port": port, "protocol": protocol}

    success, output = await _apply_rules(rules)

    action_id = None
    if success:
        if already:
            action_id = already["id"]
            try:
                await db.execute(
                    "UPDATE shield_actions SET taken_at=?, confidence=?, "
                    "trigger_id=?, justification=? WHERE id=?",
                    (time.time(), confidence, trigger_id, justification,
                     action_id),
                )
            except Exception as exc:
                logger.warning(
                    f"[SHIELD] Re-applied close #{action_id} but could not "
                    f"refresh its audit row: {exc}"
                )
        else:
            action_id = await _record_action(
                """INSERT INTO shield_actions
                   (action_type, target_port, rule_applied, trigger_type,
                    trigger_id, confidence, justification, is_active)
                   VALUES (?,?,?,?,?,?,?,1) RETURNING id""",
                (
                    str(ShieldActionType.CLOSE_PORT), port, rule,
                    trigger_type, trigger_id, confidence, justification,
                ),
                rules,
            )
        success = action_id is not None
        if not success:
            output = "action could not be recorded"

    if success:
        logger.success(f"[SHIELD] Closed port {port}/{protocol} (action_id={action_id})")
    else:
        logger.error(f"[SHIELD] Failed to close port {port}/{protocol}: {output}")
        await _audit_refused(
            ShieldActionType.CLOSE_PORT, None, f"iptables failed: {output}",
            trigger_type, trigger_id, confidence, justification,
            target_port=port,
        )

    return {
        "status": "closed" if success else "failed",
        "port": port,
        "protocol": protocol,
        "rule": rule,
        "action_id": action_id,
    }


async def _rules_kept_by_other_actions(
    exclude_id: int,
) -> set[tuple[str, tuple[str, ...]]]:
    """Specs that another active action still relies on.

    QUARANTINE_HOST installs the same INPUT/FORWARD drops as BLOCK_IP for the
    same address, and `_apply_rules` skips rules that already exist. Reverting
    either action used to delete rules the other still depended on while its
    row stayed `is_active=1` — the dashboard advertised a block that no longer
    existed in the kernel.
    """
    rows = await db.fetch_all(
        "SELECT action_type, target_ip, target_port, rule_applied "
        "FROM shield_actions "
        "WHERE is_active=1 AND id != ?",
        (exclude_id,),
    ) or []
    kept: set[tuple[str, tuple[str, ...]]] = set()
    for row in rows:
        row = dict(row)
        target = row.get("target_ip")
        action = row.get("action_type")
        if action == str(ShieldActionType.CLOSE_PORT):
            # Port blocks have no target IP, so they must be handled before
            # the address check below.
            try:
                port = int(row.get("target_port"))
            except (TypeError, ValueError):
                continue
            if not 1 <= port <= 65535:
                continue
            kept.update(_close_port_rules(port, _rule_protocol(row.get("rule_applied"))))
            continue
        if not target:
            continue
        if action == str(ShieldActionType.BLOCK_IP):
            kept.update(_block_ip_rules(str(target)))
        elif action == str(ShieldActionType.QUARANTINE_HOST):
            kept.update(_quarantine_rules(str(target)))
    return kept


async def revert_action(action_id: int, reverted_by: str = "HUMAN") -> bool:
    """
    Revert a SHIELD action — remove every rule it installed.
    Every SHIELD action is reversible, and reverting is idempotent.
    """
    row = await db.fetch_one(
        "SELECT * FROM shield_actions WHERE id=?", (action_id,)
    )
    if not row:
        logger.warning(f"[SHIELD] Action {action_id} not found")
        return False

    row = dict(row)
    rule    = row.get("rule_applied") or ""
    action  = row.get("action_type")
    target  = row.get("target_ip")
    src_ip  = row.get("src_ip")

    # Refused rows never installed a rule. Reverting one must not delete a
    # live rule that another (legitimate) action installed for the same target.
    if str(rule).startswith("REFUSED"):
        logger.warning(f"[SHIELD] Action #{action_id} was refused; nothing to revert")
        return False

    if action == str(ShieldActionType.BLOCK_IP):
        if not target:
            return False
        kept = await _rules_kept_by_other_actions(action_id)
        ok = await _remove_rules(
            [r for r in _block_ip_rules(target) if r not in kept])
    elif action == str(ShieldActionType.BLOCK_PATH):
        port = row.get("target_port")
        # Both must be defined before the branches: a legacy row with no
        # src_ip and an unparseable rule used to raise UnboundLocalError here,
        # making the dashboard return 500 for an otherwise harmless revert.
        chain: str | None = None
        spec: tuple[str, ...] | None = None
        # Preferred: parse the recorded rule — it is the exact spec that was
        # installed, including --dport. Rebuilding from columns loses the port
        # when target_port is NULL, which deleted a portless rule that never
        # existed and marked the still-live DROP rule as reverted.
        if isinstance(rule, str) and rule.startswith(("-A ", "-I ")):
            try:
                tokens = shlex.split(rule)
                if tokens[0] == "-I":
                    chain, rest = tokens[1], tokens[2:]
                    if rest and rest[0].isdigit():
                        rest = rest[1:]
                    spec = tuple(rest)
                else:
                    chain, spec = tokens[1], tuple(tokens[2:])
                if not chain or not spec:
                    chain, spec = None, None
            except Exception:
                chain, spec = None, None
        # Fallback: rebuild from structured columns (no recorded rule).
        if not (chain and spec) and src_ip and target:
            protocol = "tcp"
            for proto in ("tcp", "udp", "icmp"):
                if f"-p {proto}" in rule:
                    protocol = proto
                    break
            if protocol in ("tcp", "udp") and port is None:
                # block_path() always records a port for tcp/udp, so a portless
                # rebuild cannot match the installed rule. Deleting it would
                # report success while the real DROP rule stays live.
                logger.warning(
                    f"[SHIELD] Cannot reconstruct ported rule for action "
                    f"#{action_id}; refusing revert"
                )
                return False
            chain, spec = _block_path_rule(src_ip, target, port, protocol)
        if chain and spec:
            ok = await _delete_rule(chain, spec)
        else:
            logger.warning(f"[SHIELD] Cannot reconstruct rule for action #{action_id}")
            return False
    elif action == str(ShieldActionType.QUARANTINE_HOST):
        if not target:
            return False
        kept = await _rules_kept_by_other_actions(action_id)
        ok = await _remove_rules(
            [r for r in _quarantine_rules(target) if r not in kept])
    elif action == str(ShieldActionType.CLOSE_PORT):
        try:
            port = int(row.get("target_port"))
            if not 1 <= port <= 65535:
                raise ValueError(port)
        except (TypeError, ValueError):
            logger.warning(
                f"[SHIELD] Cannot reconstruct CLOSE_PORT rule for action "
                f"#{action_id}; refusing revert"
            )
            return False
        wanted = _close_port_rules(port, _rule_protocol(rule))
        kept = await _rules_kept_by_other_actions(action_id)
        ok = await _remove_rules([r for r in wanted if r not in kept])
    else:
        logger.warning(f"[SHIELD] Unknown action type: {action}")
        return False

    subject = target or f"port {row.get('target_port')}"
    if ok:
        await db.execute(
            "UPDATE shield_actions SET is_active=0, reverted_at=?, reverted_by=? WHERE id=?",
            (time.time(), reverted_by, action_id)
        )
        logger.success(f"[SHIELD] Reverted action #{action_id} ({action} on {subject})")
    else:
        logger.error(f"[SHIELD] Failed to fully revert action #{action_id} ({action} on {subject})")

    return ok


# ─────────────────────────────────────────────────────────────────────────────
# Intelligent auto-response
# ─────────────────────────────────────────────────────────────────────────────

async def respond_to_sentinel_alert(alert: dict) -> dict | None:
    """
    Called when SENTINEL fires an alert matching a PHANTOM prediction.
    Decides whether to act autonomously based on confidence.

    Alert dict: {src_ip, dst_ip, dst_port, protocol, attack_path_id, predicted, severity}
    """
    src_ip      = alert.get("src_ip")
    dst_ip      = alert.get("dst_ip")
    dst_port    = alert.get("dst_port")
    protocol    = str(alert.get("protocol") or "tcp").strip().lower()
    path_id     = alert.get("attack_path_id")
    is_predicted = _truthy(alert.get("predicted", False))

    if not src_ip or not dst_ip:
        return None

    try:
        trigger_id = int(path_id) if path_id is not None else None
    except (TypeError, ValueError):
        trigger_id = None
    if protocol != "icmp" and not dst_port:
        logger.info(f"[SHIELD] Alert for {src_ip}→{dst_ip} has no destination port — not blocking")
        return None

    # Confidence based on whether PHANTOM predicted this
    confidence = 0.9 if is_predicted else 0.5

    if confidence < ALERT_THRESHOLD:
        logger.info(f"[SHIELD] Alert confidence {confidence:.0%} — below threshold, monitoring only")
        return None

    justification = (
        f"SENTINEL alert matched PHANTOM attack path #{path_id}. "
        f"Source {src_ip} targeting {dst_ip}:{dst_port}. "
        f"Confidence: {confidence:.0%}. Auto-blocked by SHIELD."
    )

    if confidence >= AUTO_ACT_THRESHOLD:
        logger.warning(f"[SHIELD] HIGH CONFIDENCE ({confidence:.0%}) — auto-blocking {src_ip}")
        return await block_path(
            src_ip        = src_ip,
            dst_ip        = dst_ip,
            dst_port      = dst_port,
            protocol      = protocol,
            justification = justification,
            trigger_type  = "SENTINEL_ALERT",
            trigger_id    = trigger_id,
            confidence    = confidence,
        )

    return None


async def respond_to_anomaly(anomaly_id: int, host_id: int, confidence: float) -> dict | None:
    """
    Called when ECHO detects a high-confidence behavioral anomaly.
    May quarantine the affected host (opt-in via SHIELD_AUTO_QUARANTINE).
    """
    conf = _coerce_confidence(confidence)
    if conf is None:
        logger.warning(
            f"[SHIELD] ECHO anomaly #{anomaly_id} has unusable confidence "
            f"{confidence!r} — not quarantining"
        )
        return None
    if conf < AUTO_ACT_THRESHOLD:
        return None

    host_row = await db.fetch_one("SELECT ip FROM hosts WHERE id=?", (host_id,))
    if not host_row:
        return None

    ip = host_row["ip"]
    justification = (
        f"ECHO detected behavioral anomaly with {conf:.0%} confidence. "
        f"Host {ip} quarantined automatically by SHIELD."
    )

    logger.warning(f"[SHIELD] ECHO anomaly confidence {conf:.0%} — quarantining {ip}")
    return await quarantine_host(
        ip            = ip,
        justification = justification,
        trigger_type  = "ECHO_ANOMALY",
        trigger_id    = anomaly_id,
        confidence    = conf,
    )


async def close_phantom_paths() -> list[dict]:
    """
    Proactively close the highest-ROI PHANTOM attack paths.
    Called after each PHANTOM simulation to pre-block predicted attack vectors.
    """
    from rich.console import Console
    from rich.markup import escape
    console = Console()

    paths = await db.fetch_all(
        """SELECT id, entry_host_id, target_host_id, path_json, attacker_roi
           FROM attack_paths WHERE is_active=1 AND attacker_roi > 1.0
           ORDER BY attacker_roi DESC LIMIT 3"""
    )

    if not paths:
        return []

    actions = []
    console.print("[bold yellow]🔰 SHIELD — Pre-blocking high-ROI attack paths[/]\n")

    for path in paths:
        try:
            import json
            steps = json.loads(path["path_json"])
        except Exception:
            continue

        if not isinstance(steps, list) or len(steps) < 2:
            continue
        first_hop, second_hop = steps[0], steps[1]
        if not isinstance(first_hop, dict) or not isinstance(second_hop, dict):
            continue

        # Block the most critical edge: entry → first hop
        src_ip = first_hop.get("ip")
        dst_ip = second_hop.get("ip")

        if not src_ip or not dst_ip:
            continue

        # Determine port from technique
        technique = second_hop.get("technique", "")
        if not isinstance(technique, str):
            # path_json is untrusted graph data; an unhashable value would
            # raise inside port_map.get() and abort every later path.
            technique = ""
        port_map = {
            "T1021.004": 22,
            "T1021.002": 445,
            "T1021.001": 3389,
            "T1190":     80,
            "T1210":     21,
        }
        port = port_map.get(technique, 0)

        if port == 0:
            continue

        # A numeric string is fine; a malformed column means we cannot even
        # estimate confidence, so skip this path instead of blocking blind.
        try:
            roi = float(path["attacker_roi"] or 0)
        except (TypeError, ValueError, KeyError) as exc:
            logger.warning(
                f"[SHIELD] Skipping path #{path['id']} — unreadable ROI: {exc}"
            )
            continue

        justification = (
            f"Proactive SHIELD block — PHANTOM Path #{path['id']} "
            f"ROI={roi:.1f}. "
            f"Pre-blocking {src_ip}→{dst_ip}:{port} ({technique})"
        )

        try:
            result = await block_path(
                src_ip        = src_ip,
                dst_ip        = dst_ip,
                dst_port      = port,
                justification = justification,
                trigger_type  = "PHANTOM_PREDICTION",
                trigger_id    = path["id"],
                confidence    = min(roi / 5.0, 0.99),
            )
        except Exception as exc:
            logger.error(f"[SHIELD] Could not pre-block path #{path['id']}: {exc}")
            actions.append({"status": "failed", "reason": str(exc)})
            continue
        actions.append(result)

        status = result.get("status") if isinstance(result, dict) else "failed"
        status_color = "green" if status == "blocked" else "yellow"
        console.print(
            f"  [{status_color}]{'✅' if status == 'blocked' else '⚠'}[/] "
            f"Path #{path['id']} — Blocked "
            f"[cyan]{escape(str(src_ip))}[/] → "
            f"[red]{escape(str(dst_ip))}:{port}[/] "
            f"({escape(str(technique))})"
        )

    return actions


async def get_shield_summary() -> dict:
    """Get summary of all SHIELD actions."""
    rows = await db.fetch_all(
        """SELECT action_type, COUNT(*) as cnt, AVG(confidence) as avg_conf
           FROM shield_actions
           GROUP BY action_type"""
    )
    active = await db.fetch_val(
        "SELECT COUNT(*) FROM shield_actions WHERE is_active=1", default=0
    )
    return {
        "total_actions": sum(r["cnt"] for r in rows),
        "active_blocks": active,
        "by_type": [dict(r) for r in rows],
    }


async def stop_shield() -> int:
    """Revert all active firewall blocks. Returns the number reverted."""
    active_actions = await db.fetch_all(
        "SELECT id FROM shield_actions WHERE is_active=1 ORDER BY id DESC"
    )

    reverted = 0
    for action in active_actions:
        try:
            if await revert_action(action["id"], reverted_by="COMMAND_CENTER"):
                reverted += 1
        except Exception as exc:
            logger.error(f"[SHIELD] Failed to revert action #{action['id']}: {exc}")

    logger.info(f"[SHIELD] Reverted {reverted}/{len(active_actions)} active blocks")
    return reverted
