import numpy as np

from src.v2.selective import review_flags, selective_metrics


def test_reviewed_not_counted_in_selective_error_only_auto():
    y = np.array([0, 0, 1, 1])
    p = np.array([0.2, 0.8, 0.9, 0.1])
    thr = 0.5
    review = np.array([False, True, False, False])
    m = selective_metrics(y, p, thr, review)
    assert m["review_rate"] == 0.25
    # Auto: idx 0 TN, 2 TP, 3 FN -> 1 error / 3 auto
    assert abs(m["selective_error_rate"] - 1 / 3) < 1e-9


def test_review_flag_near_threshold():
    p = np.array([0.48, 0.52, 0.2])
    thr = 0.5
    r = review_flags(p, threshold=thr, band_half_width=0.05)
    assert r[0] and r[1]
    assert not r[2]
