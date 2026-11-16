"""Group-level bootstrap for development comparisons."""

from __future__ import annotations

import numpy as np

from src.metrics import tpr_at_fpr


def group_bootstrap_tpr_diff(
    y_true: np.ndarray,
    scores_a: np.ndarray,
    scores_b: np.ndarray,
    groups: np.ndarray,
    fpr_target: float,
    *,
    n_boot: int = 500,
    seed: int = 42,
) -> dict:
    y_true = np.asarray(y_true, dtype=int)
    scores_a = np.asarray(scores_a, dtype=float)
    scores_b = np.asarray(scores_b, dtype=float)
    groups = np.asarray(groups)
    uniq = np.unique(groups)
    if len(uniq) < 3:
        ta = tpr_at_fpr(y_true, scores_a, fpr_target)["tpr"]
        tb = tpr_at_fpr(y_true, scores_b, fpr_target)["tpr"]
        return {
            "tpr_a": ta,
            "tpr_b": tb,
            "delta_b_minus_a": float(tb - ta),
            "ci_low": float("nan"),
            "ci_high": float("nan"),
            "n_groups": int(len(uniq)),
            "note": "insufficient_groups",
        }
    rng = np.random.default_rng(seed)
    diffs = []
    for _ in range(n_boot):
        sampled = rng.choice(uniq, size=len(uniq), replace=True)
        mask = np.isin(groups, sampled)
        if mask.sum() < 10 or len(np.unique(y_true[mask])) < 2:
            continue
        ta = tpr_at_fpr(y_true[mask], scores_a[mask], fpr_target)["tpr"]
        tb = tpr_at_fpr(y_true[mask], scores_b[mask], fpr_target)["tpr"]
        if not (np.isnan(ta) or np.isnan(tb)):
            diffs.append(tb - ta)
    arr = np.array(diffs, dtype=float)
    pa = tpr_at_fpr(y_true, scores_a, fpr_target)["tpr"]
    pb = tpr_at_fpr(y_true, scores_b, fpr_target)["tpr"]
    return {
        "tpr_a": pa,
        "tpr_b": pb,
        "delta_b_minus_a": float(pb - pa),
        "ci_low": float(np.quantile(arr, 0.025)) if len(arr) else float("nan"),
        "ci_high": float(np.quantile(arr, 0.975)) if len(arr) else float("nan"),
        "n_boot": n_boot,
        "n_groups": int(len(uniq)),
    }
