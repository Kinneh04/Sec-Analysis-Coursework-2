import numpy as np

from src.v2.experiments import fixed_threshold_metrics, select_review_band


def _band(err, rate):
    return {"V2B_review": {"selective_error_rate": err, "review_rate": rate}}


def test_select_review_band_picks_lowest_error_within_budget():
    by_band = {"0.05": _band(0.20, 0.05), "0.1": _band(0.10, 0.10)}
    assert select_review_band(by_band, max_review_rate=0.15) == 0.1


def test_select_review_band_respects_budget():
    by_band = {"0.05": _band(0.20, 0.05), "0.1": _band(0.10, 0.30)}
    assert select_review_band(by_band, max_review_rate=0.15) == 0.05


def test_fixed_threshold_does_not_refit():
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    s = np.array([0.1, 0.2, 0.3, 0.9, 0.4, 0.6, 0.8, 0.95])
    m = fixed_threshold_metrics(y, s, 0.5)
    assert m["tpr_fixed"] == 0.75
    assert m["fpr_fixed"] == 0.25
    # Same threshold regardless of labels: oracle search would pick a different cut.
    m2 = fixed_threshold_metrics(1 - y, s, 0.5)
    assert m2["tpr_fixed"] == 0.25
