"""Uncertainty-aware review policy (V2-B)."""

from __future__ import annotations

import numpy as np


def review_flags(
    p_final: np.ndarray,
    *,
    threshold: float,
    band_half_width: float,
    p_pe: np.ndarray | None = None,
    p_pebn: np.ndarray | None = None,
    bn_used: np.ndarray | None = None,
    disagreement_min: float = 0.15,
) -> np.ndarray:
    p = np.asarray(p_final, dtype=float)
    review = np.abs(p - threshold) <= band_half_width
    if p_pe is not None and p_pebn is not None and bn_used is not None:
        bn = np.asarray(bn_used, dtype=bool)
        disagree = np.abs(np.asarray(p_pe) - np.asarray(p_pebn)) >= disagreement_min
        review |= bn & disagree
    return review.astype(bool)


def selective_metrics(
    y_true: np.ndarray,
    p_final: np.ndarray,
    threshold: float,
    review: np.ndarray,
) -> dict[str, float]:
    y = np.asarray(y_true, dtype=int)
    review = np.asarray(review, dtype=bool)
    auto = ~review
    n = len(y)
    review_rate = float(review.mean())
    auto_coverage = float(auto.mean())
    out: dict[str, float] = {
        "n": float(n),
        "review_rate": review_rate,
        "automation_coverage": auto_coverage,
    }
    if auto.sum() == 0:
        out.update(
            {
                "selective_error_rate": float("nan"),
                "auto_malware_recall": float("nan"),
                "auto_benign_fpr": float("nan"),
                "overall_recall_undecided_as_miss": float((y == 1).mean()),
            }
        )
        return out
    pred = (p_final[auto] >= threshold).astype(int)
    ya = y[auto]
    fp = int(((pred == 1) & (ya == 0)).sum())
    fn = int(((pred == 0) & (ya == 1)).sum())
    tp = int(((pred == 1) & (ya == 1)).sum())
    benign = int((ya == 0).sum())
    mal = int((ya == 1).sum())
    err = (fp + fn) / len(ya)
    out["selective_error_rate"] = float(err)
    out["auto_malware_recall"] = float(tp / mal) if mal else float("nan")
    out["auto_benign_fpr"] = float(fp / benign) if benign else float("nan")
    # Reviewed malware counts as not detected for overall recall.
    tp_all = tp
    mal_all = int((y == 1).sum())
    out["overall_recall_undecided_as_miss"] = float(tp_all / mal_all) if mal_all else float("nan")
    return out
