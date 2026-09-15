"""antibody/tuning.py — pure, testable decision logic for the learning loop.

No DB imports here. Given per-rule TP/FP counters (already stored on
``forge_rules.true_positives / false_positives``), decide whether a rule is
noisy (suggest disable) or reliable (suggest deploy). All thresholds are
explicit parameters so the dashboard/CLI can expose them later.
"""
from __future__ import annotations

FP_THRESHOLD_DEFAULT = 0.5
MIN_SAMPLES_DEFAULT = 3
TP_PROMOTE_RATE_DEFAULT = 0.8
TP_PROMOTE_MIN_SAMPLES_DEFAULT = 5

_TP_ALIASES = {"tp", "true_positive", "true-positive", "true", "confirmed", "malicious", "real"}
_FP_ALIASES = {"fp", "false_positive", "false-positive", "false", "benign", "noise", "expected"}


def normalize_verdict(verdict: str) -> str:
    """Normalize a human verdict to ``"TP"`` or ``"FP"``. Raises ValueError."""
    if verdict is None:
        raise ValueError("verdict is required (tp/fp)")
    key = str(verdict).strip().lower().replace(" ", "_")
    if key in _TP_ALIASES:
        return "TP"
    if key in _FP_ALIASES:
        return "FP"
    raise ValueError(f"unknown verdict {verdict!r}: use tp / fp")


def fp_rate(true_positives: int, false_positives: int) -> float:
    """False-positive rate in [0,1]. No samples -> 0.0 (never punish cold rules)."""
    tp = max(int(true_positives or 0), 0)
    fp = max(int(false_positives or 0), 0)
    total = tp + fp
    if total == 0:
        return 0.0
    return fp / total


def suggest_for_rule(
    *,
    rule_id: int,
    rule_sid: int | None = None,
    true_positives: int = 0,
    false_positives: int = 0,
    is_active: bool = True,
    is_deployed: bool = False,
    fp_threshold: float = FP_THRESHOLD_DEFAULT,
    min_samples: int = MIN_SAMPLES_DEFAULT,
    tp_promote_rate: float = TP_PROMOTE_RATE_DEFAULT,
    tp_min_samples: int = TP_PROMOTE_MIN_SAMPLES_DEFAULT,
) -> dict | None:
    """Return a suggestion dict, or None if the rule needs no action.

    Suggestion shapes:
      {"forge_rule_id":..,"rule_sid":..,"action":"disable","reason":..,"fp_rate":..,"samples":..}
      {"forge_rule_id":..,"rule_sid":..,"action":"deploy","reason":..,"tp_rate":..,"samples":..}
    """
    tp = max(int(true_positives or 0), 0)
    fp = max(int(false_positives or 0), 0)
    total = tp + fp
    if total < max(int(min_samples or 0), 1):
        return None
    rate = fp / total if total else 0.0
    if rate >= fp_threshold and bool(is_active):
        return {
            "forge_rule_id": rule_id,
            "rule_sid": rule_sid,
            "action": "disable",
            "reason": (
                f"FP rate {rate:.0%} over {total} verdicts "
                f"({fp} FP / {tp} TP) >= threshold {fp_threshold:.0%}"
            ),
            "fp_rate": round(rate, 4),
            "samples": total,
        }
    tp_rate = (tp / total) if total else 0.0
    if (
        tp_rate >= tp_promote_rate
        and total >= max(int(tp_min_samples or 0), 1)
        and bool(is_active)
        and not bool(is_deployed)
    ):
        return {
            "forge_rule_id": rule_id,
            "rule_sid": rule_sid,
            "action": "deploy",
            "reason": (
                f"TP rate {tp_rate:.0%} over {total} verdicts "
                f"({tp} TP / {fp} FP) — reliable, not yet deployed"
            ),
            "tp_rate": round(tp_rate, 4),
            "samples": total,
        }
    return None
