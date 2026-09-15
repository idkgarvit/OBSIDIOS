"""antibody — adaptive learning loop: TP/FP feedback -> auto-tune."""
from antibody.tuning import (
    FP_THRESHOLD_DEFAULT,
    MIN_SAMPLES_DEFAULT,
    TP_PROMOTE_MIN_SAMPLES_DEFAULT,
    TP_PROMOTE_RATE_DEFAULT,
    fp_rate,
    normalize_verdict,
    suggest_for_rule,
)

__all__ = [
    "fp_rate",
    "normalize_verdict",
    "suggest_for_rule",
    "FP_THRESHOLD_DEFAULT",
    "MIN_SAMPLES_DEFAULT",
    "TP_PROMOTE_RATE_DEFAULT",
    "TP_PROMOTE_MIN_SAMPLES_DEFAULT",
]
