import numpy as np

from src.metrics import bootstrap_tpr_at_fpr, paired_bootstrap_metric_diff, tpr_at_fpr


def test_bootstrap_tpr_returns_ci():
    rng = np.random.default_rng(0)
    y = np.array([0] * 50 + [1] * 50)
    s = np.concatenate([rng.normal(0, 1, 50), rng.normal(2, 1, 50)])
    out = bootstrap_tpr_at_fpr(y, s, 0.01, n_boot=500, seed=1)
    assert out["ci_low"] <= out["tpr"] <= out["ci_high"] or np.isnan(out["ci_low"])


def test_paired_delta_sign():
    rng = np.random.default_rng(3)
    y = np.array([0] * 20 + [1] * 20)
    a = np.concatenate([rng.normal(0, 1, 20), rng.normal(0.5, 1, 20)])
    b = np.concatenate([rng.normal(0, 1, 20), rng.normal(2.5, 1, 20)])
    assert tpr_at_fpr(y, b, 0.2)["tpr"] >= tpr_at_fpr(y, a, 0.2)["tpr"]
    diff = paired_bootstrap_metric_diff(y, a, b, 0.2, n_boot=200, seed=2)
    assert diff["delta_b_minus_a"] > 0
