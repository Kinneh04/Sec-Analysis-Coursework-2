"""Coverage-aware PE / PE+BN fusion (V2-A)."""

from __future__ import annotations

import numpy as np
import pandas as pd


def attach_eligibility(df: pd.DataFrame) -> pd.DataFrame:
    from src.v2.quality import compute_eligibility

    extra = df.apply(compute_eligibility, axis=1, result_type="expand")
    out = df.copy()
    out["eligibility_score"] = extra["eligibility_score"]
    return out


def fusion_probs(
    p_pe: np.ndarray,
    p_pebn: np.ndarray,
    eligibility: np.ndarray,
    *,
    threshold: float,
    weight: float,
) -> tuple[np.ndarray, np.ndarray]:
    """Return fused probability and mask of BN-fusion used (for reporting)."""
    elig = np.asarray(eligibility, dtype=float)
    use_bn = elig >= threshold
    w = float(weight)
    fused = np.asarray(p_pe, dtype=float).copy()
    if use_bn.any():
        fused[use_bn] = (1.0 - w) * p_pe[use_bn] + w * p_pebn[use_bn]
    return fused, use_bn.astype(int)


def threshold_from_train_quantile(eligibility_train: np.ndarray, quantile: float) -> float:
    return float(np.quantile(eligibility_train, quantile))
