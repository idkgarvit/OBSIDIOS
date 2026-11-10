"""antibody/service.py — DB wiring for the learning loop.

Pure decision logic lives in antibody/tuning.py (no DB imports).
This module handles persistence:

  verdict (human TP/FP) -> bump forge_rules counters
                        -> insert antibody_feedback row
                        -> compute suggestion via tuning.suggest_for_rule
                        -> optionally auto-apply disable (safe default: off)

All functions accept an optional ``db`` param for test injection.
Defaults to chronicle.db (async).
"""
from __future__ import annotations

from typing import Any

from antibody.tuning import (
    normalize_verdict,
    suggest_for_rule,
)


async def record_feedback(
    *,
    forge_rule_id: int,
    verdict: str,
    note: str = "",
    sentinel_alert_id: int | None = None,
    attack_path_id: int | None = None,
    auto_apply: bool = False,
    fp_threshold: float = 0.5,
    min_samples: int = 3,
    tp_promote_rate: float = 0.8,
    tp_min_samples: int = 5,
    db: Any | None = None,
) -> dict:
    """Record one TP/FP verdict and return updated counters + suggestion.

    Returns: {"rule_id","verdict","true_positives","false_positives",
              "suggestion": dict|None, "applied": bool}
    Raises ValueError on bad verdict, LookupError if rule missing.
    """
    if db is None:
        from chronicle import db as db  # type: ignore[no-redef]

    norm = normalize_verdict(verdict)  # raises ValueError

    row = await db.fetch_one(
        "SELECT id, rule_sid, attack_path_id, true_positives, false_positives, is_active, is_deployed"
        " FROM forge_rules WHERE id=?",
        (int(forge_rule_id),),
    )
    if not row:
        raise LookupError(f"forge_rule {forge_rule_id} not found")
    # Row may be sqlite3.Row / dict / aiosqlite.Row — normalize via keys
    try:
        d = dict(row)
    except Exception:
        try:
            d = {
                "id": row[0], "rule_sid": row[1], "attack_path_id": row[2],
                "true_positives": row[3], "false_positives": row[4],
                "is_active": row[5], "is_deployed": row[6],
            }
        except Exception:
            d = {
                "id": row["id"], "rule_sid": row["rule_sid"],
                "true_positives": row["true_positives"],
                "false_positives": row["false_positives"],
                "is_active": row["is_active"], "is_deployed": row["is_deployed"],
            }

    tp = int(d.get("true_positives") or 0) + (1 if norm == "TP" else 0)
    fp = int(d.get("false_positives") or 0) + (1 if norm == "FP" else 0)

    col = "true_positives" if norm == "TP" else "false_positives"
    await db.execute(
        f"UPDATE forge_rules SET {col}={col}+1 WHERE id=?",  # nosec B608 — col is a literal whitelist
        (int(forge_rule_id),),
    )
    await db.execute(
        "INSERT INTO antibody_feedback"
        " (event_type, attack_path_id, forge_rule_id, sentinel_alert_id, learning_note, applied)"
        " VALUES (?,?,?,?,?,0)",
        (
            norm,
            attack_path_id if attack_path_id is not None else d.get("attack_path_id"),
            int(forge_rule_id),
            sentinel_alert_id,
            note or f"manual verdict {norm}",
        ),
    )

    suggestion = suggest_for_rule(
        rule_id=int(forge_rule_id),
        rule_sid=d.get("rule_sid"),
        true_positives=tp,
        false_positives=fp,
        is_active=bool(d.get("is_active", 1)),
        is_deployed=bool(d.get("is_deployed", 0)),
        fp_threshold=fp_threshold,
        min_samples=min_samples,
        tp_promote_rate=tp_promote_rate,
        tp_min_samples=tp_min_samples,
    )

    applied = False
    if auto_apply and suggestion and suggestion.get("action") == "disable":
        await db.execute(
            "UPDATE forge_rules SET is_active=0 WHERE id=?",
            (int(forge_rule_id),),
        )
        await db.execute(
            "UPDATE antibody_feedback SET applied=1 WHERE forge_rule_id=? AND applied=0",
            (int(forge_rule_id),),
        )
        applied = True

    return {
        "rule_id": int(forge_rule_id),
        "verdict": norm,
        "true_positives": tp,
        "false_positives": fp,
        "suggestion": suggestion,
        "applied": applied,
    }


async def list_suggestions(
    *,
    fp_threshold: float = 0.5,
    min_samples: int = 3,
    tp_promote_rate: float = 0.8,
    tp_min_samples: int = 5,
    limit: int = 100,
    db: Any | None = None,
) -> list[dict]:
    """Scan active rules and return tuning suggestions."""
    if db is None:
        from chronicle import db as db  # type: ignore[no-redef]

    rows = await db.fetch_all(
        "SELECT id, rule_sid, true_positives, false_positives, is_active, is_deployed"
        " FROM forge_rules WHERE is_active=1 ORDER BY id DESC LIMIT ?",
        (int(limit),),
    )
    out: list[dict] = []
    for r in rows or []:
        try:
            d = dict(r)
        except Exception:
            continue
        # One malformed legacy row must not hide every other suggestion.
        try:
            rule_id = int(d.get("id"))
            true_positives = int(d.get("true_positives") or 0)
            false_positives = int(d.get("false_positives") or 0)
        except (TypeError, ValueError):
            continue
        s = suggest_for_rule(
            rule_id=rule_id,
            rule_sid=d.get("rule_sid"),
            true_positives=true_positives,
            false_positives=false_positives,
            is_active=bool(d.get("is_active", 1)),
            is_deployed=bool(d.get("is_deployed", 0)),
            fp_threshold=fp_threshold,
            min_samples=min_samples,
            tp_promote_rate=tp_promote_rate,
            tp_min_samples=tp_min_samples,
        )
        if s:
            out.append(s)
    return out
