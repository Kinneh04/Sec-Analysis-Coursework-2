"""Fixed-threshold statistics for V3 (no threshold re-selection on evaluation rows)."""

from __future__ import annotations

import math

import numpy as np


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def rates_at_threshold(y: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float]:
    y = np.asarray(y, dtype=int)
    pred = np.asarray(scores, dtype=float) >= threshold
    n_mal, n_ben = int((y == 1).sum()), int((y == 0).sum())
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    tpr_ci = wilson_interval(tp, n_mal)
    fpr_ci = wilson_interval(fp, n_ben)
    return {
        "tpr": tp / n_mal if n_mal else float("nan"),
        "fpr": fp / n_ben if n_ben else float("nan"),
        "tp": tp, "fp": fp, "n_malicious": n_mal, "n_benign": n_ben,
        "tpr_ci95": list(tpr_ci), "fpr_ci95": list(fpr_ci),
        "min_attainable_fpr": 1 / n_ben if n_ben else float("nan"),
    }


def paired_group_bootstrap_fixed(
    y: np.ndarray,
    scores_a: np.ndarray,
    thr_a: float,
    scores_b: np.ndarray,
    thr_b: float,
    groups: np.ndarray,
    *,
    n_boot: int = 2000,
    seed: int = 42,
) -> dict[str, float]:
    """Bootstrap over groups of (TPR_b - TPR_a) and (FPR_b - FPR_a) at fixed thresholds."""
    y = np.asarray(y, dtype=int)
    pa = np.asarray(scores_a) >= thr_a
    pb = np.asarray(scores_b) >= thr_b
    groups = np.asarray(groups).astype(str)
    uniq, inv = np.unique(groups, return_inverse=True)
    g = len(uniq)
    mal = (y == 1).astype(float)
    ben = (y == 0).astype(float)
    # Per-group sufficient statistics make each replicate O(groups).
    mal_g = np.bincount(inv, weights=mal, minlength=g)
    ben_g = np.bincount(inv, weights=ben, minlength=g)
    tpa_g = np.bincount(inv, weights=pa * mal, minlength=g)
    tpb_g = np.bincount(inv, weights=pb * mal, minlength=g)
    fpa_g = np.bincount(inv, weights=pa * ben, minlength=g)
    fpb_g = np.bincount(inv, weights=pb * ben, minlength=g)
    rng = np.random.default_rng(seed)
    d_tpr, d_fpr = [], []
    for _ in range(n_boot):
        w = np.bincount(rng.integers(0, g, size=g), minlength=g)
        m, b = (w * mal_g).sum(), (w * ben_g).sum()
        if m == 0 or b == 0:
            continue
        d_tpr.append(((w * tpb_g).sum() - (w * tpa_g).sum()) / m)
        d_fpr.append(((w * fpb_g).sum() - (w * fpa_g).sum()) / b)
    d_tpr_a, d_fpr_a = np.array(d_tpr), np.array(d_fpr)
    point_tpr = (tpb_g.sum() - tpa_g.sum()) / mal_g.sum()
    point_fpr = (fpb_g.sum() - fpa_g.sum()) / ben_g.sum()
    return {
        "delta_tpr_b_minus_a": float(point_tpr),
        "delta_tpr_ci95": [float(np.quantile(d_tpr_a, 0.025)), float(np.quantile(d_tpr_a, 0.975))],
        "delta_fpr_b_minus_a": float(point_fpr),
        "delta_fpr_ci95": [float(np.quantile(d_fpr_a, 0.025)), float(np.quantile(d_fpr_a, 0.975))],
        "fraction_b_better_tpr": float((d_tpr_a > 0).mean()),
        "n_groups": int(g),
        "n_boot": int(len(d_tpr_a)),
        "seed": seed,
    }
