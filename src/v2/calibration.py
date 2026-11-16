"""Leakage-safe probability calibration."""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import brier_score_loss


def brier_score(y_true: np.ndarray, y_prob: np.ndarray) -> float:
    return float(brier_score_loss(y_true, y_prob))


def fit_calibrated(
    base_estimator,
    X_fit: np.ndarray | Any,
    y_fit: np.ndarray,
    X_cal: np.ndarray | Any,
    y_cal: np.ndarray,
) -> CalibratedClassifierCV:
    base_estimator.fit(X_fit, y_fit)
    cal = CalibratedClassifierCV(base_estimator, method="sigmoid", cv="prefit")
    cal.fit(X_cal, y_cal)
    return cal


def train_cal_split(n: int, *, fraction: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    idx = np.arange(n)
    rng.shuffle(idx)
    n_cal = min(max(2, int(n * fraction)), max(1, n - 2))
    return idx[n_cal:], idx[:n_cal]
