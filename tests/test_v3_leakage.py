import numpy as np
import pandas as pd

from src.v3.leakage import group_cv_auc, single_feature_auc


def _frame(n=200, seed=0):
    rng = np.random.default_rng(seed)
    y = rng.integers(0, 2, size=n)
    return pd.DataFrame({
        "label": y,
        "group_id": [f"g{i // 2}" for i in range(n)],
        "pe3_leaky": y.astype(float),
        "pe3_noise": rng.normal(size=n),
    })


def test_single_feature_auc_flags_label_copy():
    df = _frame()
    sfa = single_feature_auc(df, ["pe3_leaky", "pe3_noise"])
    flagged = set(sfa[sfa["suspect"]]["feature"])
    assert flagged == {"pe3_leaky"}


def test_permutation_sentinel_near_chance():
    df = _frame(n=400)
    y_perm = np.random.default_rng(1).permutation(df["label"].to_numpy())
    res = group_cv_auc(df, ["pe3_noise"], y_perm, seed=0)
    assert abs(res["mean_auc"] - 0.5) < 0.15
