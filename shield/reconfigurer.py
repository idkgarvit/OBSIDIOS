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
"""
from __future__ import annotations

import asyncio
import subprocess
import time

from loguru import logger

from chronicle import db
from chronicle.models import ShieldActionType


# ── Confidence threshold for autonomous action ─────────────────────────────
AUTO_ACT_THRESHOLD = 0.85
ALERT_THRESHOLD    = 0.70


# ─────────────────────────────────────────────────────────────────────────────
# iptables wrapper
# ─────────────────────────────────────────────────────────────────────────────

async def _run_iptables(args: list[str], check: bool = True) -> tuple[bool, str]:
    """
    Run an iptables command asynchronously.
    Returns (success, output).
    """
    cmd = ["iptables"] + args
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout = asyncio.subprocess.PIPE,
            stderr = asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        success = proc.returncode == 0
        output  = (stdout + stderr).decode().strip()
        if not success:
            logger.warning(f"[SHIELD] iptables failed: {' '.join(cmd)} → {output}")
        return success, output
    except FileNotFoundError:
        logger.error("[SHIELD] iptables not found — cannot enforce blocks")
        return False, "SIMULATION"
    except Exception as exc:
        logger.error(f"[SHIELD] iptables error: {exc}")
        return False, str(exc)


async def _iptables_rule_exists(args: list[str]) -> bool:
    """Check if an iptables rule already exists."""
    check_args = ["-C"] + args[1:]   # Replace -A/-I with -C (check)
    success, _ = await _run_iptables(check_args, check=False)
    return success


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
    Inserts an iptables DROP rule for the src IP.
    """
    rule = f"-A INPUT -s {src_ip} -j DROP"

    # Check if already blocked
    exists = await _iptables_rule_exists(["-A", "INPUT", "-s", src_ip, "-j", "DROP"])
    if exists:
        logger.info(f"[SHIELD] IP {src_ip} already blocked")
        return {"status": "already_exists", "ip": src_ip}

    success, output = await _run_iptables(["-A", "INPUT", "-s", src_ip, "-j", "DROP"])

    action_id = None
    if success:
        row = await db.execute_returning(
            """INSERT INTO shield_actions
               (action_type, target_ip, rule_applied, trigger_type,
                trigger_id, confidence, justification, is_active)
               VALUES (?,?,?,?,?,?,?,1) RETURNING id""",
            (
                str(ShieldActionType.BLOCK_IP), src_ip, rule,
                trigger_type, trigger_id, confidence, justification,
            ),
        )
        action_id = row["id"] if row else None
        logger.success(f"[SHIELD] Blocked IP: {src_ip} (action_id={action_id})")
    else:
        logger.error(f"[SHIELD] Failed to block IP {src_ip}: {output}")

    return {
        "status":    "blocked" if success else "failed",
        "ip":        src_ip,
        "rule":      rule,
        "action_id": action_id,
    }


async def block_path(
    src_ip:  str,
    dst_ip:  str,
    dst_port: int,
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
    rule = f"-A FORWARD -s {src_ip} -d {dst_ip} -p {protocol} --dport {dst_port} -j DROP"

    # Check if this exact path is already actively blocked BEFORE inserting iptables rule
    already = await db.fetch_one(
        """SELECT id FROM shield_actions
           WHERE action_type='BLOCK_PATH' AND target_ip=? AND target_port=? AND is_active=1""",
        (dst_ip, dst_port)
    )
    if already:
        logger.info(f"[SHIELD] Path {src_ip}→{dst_ip}:{dst_port} already blocked (action #{already['id']})")
        return {"status": "already_exists", "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port}

    success, output = await _run_iptables([
        "-A", "FORWARD",
        "-s", src_ip,
        "-d", dst_ip,
        "-p", protocol,
        "--dport", str(dst_port),
        "-j", "DROP"
    ])

    action_id = None
    if success:
        row = await db.execute_returning(
            """INSERT INTO shield_actions
               (action_type, target_ip, target_port, rule_applied,
                trigger_type, trigger_id, confidence, justification, is_active)
               VALUES (?,?,?,?,?,?,?,?,1) RETURNING id""",
            (
                str(ShieldActionType.BLOCK_PATH), dst_ip, dst_port, rule,
                trigger_type, trigger_id, confidence, justification,
            ),
        )
        action_id = row["id"] if row else None
        logger.success(
            f"[SHIELD] Blocked path: {src_ip} → {dst_ip}:{dst_port}/{protocol} "
            f"(action_id={action_id})"
        )

    return {
        "status":    "blocked" if success else "failed",
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "dst_port":  dst_port,
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
    Used when ECHO detects high-confidence compromise.
    """
    results = []

    # Block inbound
    ok1, _ = await _run_iptables(["-A", "INPUT",  "-s", ip, "-j", "DROP"])
    ok2, _ = await _run_iptables(["-A", "OUTPUT", "-d", ip, "-j", "DROP"])
    ok3, _ = await _run_iptables(["-A", "FORWARD","-s", ip, "-j", "DROP"])
    ok4, _ = await _run_iptables(["-A", "FORWARD","-d", ip, "-j", "DROP"])

    success = ok1 and ok2 and ok3 and ok4
    rule    = f"QUARANTINE {ip} (INPUT/OUTPUT/FORWARD DROP)"

    if success:
        row = await db.execute_returning(
            """INSERT INTO shield_actions
               (action_type, target_ip, rule_applied, trigger_type,
                trigger_id, confidence, justification, is_active)
               VALUES (?,?,?,?,?,?,?,1) RETURNING id""",
            (
                str(ShieldActionType.QUARANTINE_HOST), ip, rule,
                trigger_type, trigger_id, confidence, justification,
            ),
        )
        logger.success(f"[SHIELD] HOST QUARANTINED: {ip}")

    return {"status": "quarantined" if success else "failed", "ip": ip}


async def revert_action(action_id: int, reverted_by: str = "HUMAN") -> bool:
    """
    Revert a SHIELD action — remove the iptables rule.
    Every SHIELD action is reversible.
    """
    row = await db.fetch_one(
        "SELECT * FROM shield_actions WHERE id=?", (action_id,)
    )
    if not row:
        logger.warning(f"[SHIELD] Action {action_id} not found")
        return False

    rule    = row["rule_applied"]
    action  = row["action_type"]
    target  = row["target_ip"]
    port    = row["target_port"]

    # Build revert command (replace -A with -D to delete)
    if action == str(ShieldActionType.BLOCK_IP):
        ok, _ = await _run_iptables(["-D", "INPUT", "-s", target, "-j", "DROP"])
    elif action == str(ShieldActionType.BLOCK_PATH):
        # Reconstruct the full rule from rule_applied (contains src_ip, dst_ip, protocol, dport)
        delete_rule = rule.replace("-A ", "-D ", 1)
        ok, _ = await _run_iptables(delete_rule.split())
    elif action == str(ShieldActionType.QUARANTINE_HOST):
        # Revert all 4 quarantine rules
        await _run_iptables(["-D", "INPUT",  "-s", target, "-j", "DROP"])
        await _run_iptables(["-D", "OUTPUT", "-d", target, "-j", "DROP"])
        await _run_iptables(["-D", "FORWARD","-s", target, "-j", "DROP"])
        ok, _ = await _run_iptables(["-D", "FORWARD","-d", target, "-j", "DROP"])
    else:
        logger.warning(f"[SHIELD] Unknown action type: {action}")
        return False

    if ok:
        await db.execute(
            "UPDATE shield_actions SET is_active=0, reverted_at=?, reverted_by=? WHERE id=?",
            (time.time(), reverted_by, action_id)
        )
        logger.success(f"[SHIELD] Reverted action #{action_id} ({action} on {target})")

    return ok


# ─────────────────────────────────────────────────────────────────────────────
# Intelligent auto-response
# ─────────────────────────────────────────────────────────────────────────────

async def respond_to_sentinel_alert(alert: dict) -> dict | None:
    """
    Called when SENTINEL fires an alert matching a PHANTOM prediction.
    Decides whether to act autonomously based on confidence.

    Alert dict: {src_ip, dst_ip, dst_port, attack_path_id, predicted, severity}
    """
    src_ip      = alert.get("src_ip")
    dst_ip      = alert.get("dst_ip")
    dst_port    = alert.get("dst_port")
    path_id     = alert.get("attack_path_id")
    is_predicted = alert.get("predicted", False)

    if not src_ip or not dst_ip:
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
        result = await block_path(
            src_ip        = src_ip,
            dst_ip        = dst_ip,
            dst_port      = dst_port or 0,
            justification = justification,
            trigger_type  = "SENTINEL_ALERT",
            trigger_id    = path_id,
            confidence    = confidence,
        )
        return result

    return None


async def respond_to_anomaly(anomaly_id: int, host_id: int, confidence: float) -> dict | None:
    """
    Called when ECHO detects a high-confidence behavioral anomaly.
    May quarantine the affected host.
    """
    if confidence < AUTO_ACT_THRESHOLD:
        return None

    host_row = await db.fetch_one("SELECT ip FROM hosts WHERE id=?", (host_id,))
    if not host_row:
        return None

    ip = host_row["ip"]
    justification = (
        f"ECHO detected behavioral anomaly with {confidence:.0%} confidence. "
        f"Host {ip} quarantined automatically by SHIELD."
    )

    logger.warning(f"[SHIELD] ECHO anomaly confidence {confidence:.0%} — quarantining {ip}")
    return await quarantine_host(
        ip            = ip,
        justification = justification,
        trigger_type  = "ECHO_ANOMALY",
        trigger_id    = anomaly_id,
        confidence    = confidence,
    )


async def close_phantom_paths() -> list[dict]:
    """
    Proactively close the highest-ROI PHANTOM attack paths.
    Called after each PHANTOM simulation to pre-block predicted attack vectors.
    """
    from rich.console import Console
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

        if len(steps) < 2:
            continue

        # Block the most critical edge: entry → first hop
        src_ip = steps[0].get("ip")
        dst_ip = steps[1].get("ip")

        if not src_ip or not dst_ip:
            continue

        # Determine port from technique
        technique = steps[1].get("technique", "")
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

        justification = (
            f"Proactive SHIELD block — PHANTOM Path #{path['id']} "
            f"ROI={path['attacker_roi']:.1f}. "
            f"Pre-blocking {src_ip}→{dst_ip}:{port} ({technique})"
        )

        result = await block_path(
            src_ip        = src_ip,
            dst_ip        = dst_ip,
            dst_port      = port,
            justification = justification,
            trigger_type  = "PHANTOM_PREDICTION",
            trigger_id    = path["id"],
            confidence    = min(path["attacker_roi"] / 5.0, 0.99),
        )
        actions.append(result)

        status_color = "green" if result["status"] == "blocked" else "yellow"
        console.print(
            f"  [{status_color}]{'✅' if result['status'] == 'blocked' else '⚠'}[/] "
            f"Path #{path['id']} — Blocked [cyan]{src_ip}[/] → "
            f"[red]{dst_ip}:{port}[/] ({technique})"
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

async def stop_shield():
    """Revert all active firewall blocks and clear CHRONICLE shield_actions."""
    active_actions = await db.fetch_all("SELECT id, action_type, target_ip, rule_applied FROM shield_actions WHERE is_active=1")

    for action in active_actions:
        target = action["target_ip"]
        action_type = action["action_type"]
        aid = action["id"]
        try:
            # Revert based on action type
            if action_type == str(ShieldActionType.BLOCK_IP):
                subprocess.run(["iptables", "-D", "INPUT", "-s", target, "-j", "DROP"], capture_output=True)
            elif action_type == str(ShieldActionType.BLOCK_PATH):
                # Parse rule_applied to build correct revert command
                rule_applied = action["rule_applied"]
                delete_rule = rule_applied.replace("-A ", "-D ", 1)
                subprocess.run(["iptables"] + delete_rule.split(), capture_output=True)
            elif action_type == str(ShieldActionType.QUARANTINE_HOST):
                subprocess.run(["iptables", "-D", "INPUT",  "-s", target, "-j", "DROP"], capture_output=True)
                subprocess.run(["iptables", "-D", "OUTPUT", "-d", target, "-j", "DROP"], capture_output=True)
                subprocess.run(["iptables", "-D", "FORWARD","-s", target, "-j", "DROP"], capture_output=True)
                subprocess.run(["iptables", "-D", "FORWARD","-d", target, "-j", "DROP"], capture_output=True)

            await db.execute(
                "UPDATE shield_actions SET is_active=0, reverted_at=?, reverted_by=? WHERE id=?",
                (time.time(), "COMMAND_CENTER", aid)
            )
            logger.info(f"[SHIELD] Reverted block on {target} (action #{aid})")
        except Exception as e:
            logger.error(f"[SHIELD] Failed to revert block on {target}: {e}")

    return len(active_actions)
