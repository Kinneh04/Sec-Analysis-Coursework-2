"""V3.1 fitting: isotonic calibration, sample weights, strict training FPR target."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier, early_stopping
from sklearn.isotonic import IsotonicRegression
from sklearn.model_selection import GroupKFold

from src.metrics import tpr_at_fpr
from src.v3.search import ModelConfig, _cfg_by_name, inner_split
from src.v3.stats import rates_at_threshold

PE64_MACHINE = 34404
X64_MAL_WEIGHT = 3.0


class CalibratedModel:
    """Wraps a binary classifier and isotonic calibration on the positive class."""

    def __init__(self, base: Any, iso: IsotonicRegression):
        self.base = base
        self.iso = iso

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        p = self.base.predict_proba(X)[:, 1]
        c = np.clip(self.iso.predict(p), 0.0, 1.0)
        return np.column_stack([1.0 - c, c])


def training_weights(df: pd.DataFrame) -> np.ndarray:
    w = np.ones(len(df), dtype=float)
    if "pe1s_machine" in df.columns:
        x64 = df["pe1s_machine"].astype(float) == float(PE64_MACHINE)
        w[(df["label"].to_numpy() == 1) & x64.to_numpy()] = X64_MAL_WEIGHT
    return w


def _fit_lgbm(
    cfg: ModelConfig, X_fit, y_fit, X_es, y_es, seed: int,
    w_fit: np.ndarray | None = None, w_es: np.ndarray | None = None,
):
    p = cfg.p()
    m = LGBMClassifier(
        n_estimators=1000, learning_rate=0.05, num_leaves=p["num_leaves"],
        min_child_samples=p["min_child_samples"], colsample_bytree=p["feature_fraction"],
        class_weight="balanced", random_state=seed, verbosity=-1,
    )
    m.fit(
        X_fit, y_fit, sample_weight=w_fit,
        eval_set=[(X_es, y_es)], eval_sample_weight=[w_es] if w_es is not None else None,
        callbacks=[early_stopping(50, verbose=False)],
    )
    return m


def fit_with_inner_weighted(
    df: pd.DataFrame, cols: list[str], cfg: ModelConfig, seed: int, *, use_weights: bool,
) -> dict[str, Any]:
    fit_idx, hold_idx = inner_split(df, seed)
    X, y = df[cols], df["label"].to_numpy()
    sw = training_weights(df) if use_weights else None
    wf = sw[fit_idx] if sw is not None else None
    we = sw[hold_idx] if sw is not None else None
    model = _fit_lgbm(cfg, X.iloc[fit_idx], y[fit_idx], X.iloc[hold_idx], y[hold_idx], seed, wf, we)
    p_hold = model.predict_proba(X.iloc[hold_idx])[:, 1]
    return {"model": model, "p_hold": p_hold, "y_hold": y[hold_idx], "cols": cols}


def fit_oof_calibrated(
    train: pd.DataFrame,
    cols: list[str],
    cfg_name: str,
    seed: int,
    *,
    target_fpr: float = 0.005,
    use_weights: bool = True,
    calibrate: bool = True,
    threshold_mode: str = "pooled",
    rule: str = "V3.1",
) -> dict[str, Any]:
    if cfg_name.startswith("ensemble__"):
        raise ValueError("V3.1 supports single LightGBM configurations only")
    cfg = _cfg_by_name(cfg_name)
    if cfg.family != "lgbm":
        raise ValueError("V3.1 expects the preregistered LightGBM configuration")
    y = train["label"].to_numpy()
    groups = train["group_id"].astype(str).to_numpy()
    oof = np.full(len(train), np.nan)
    iters: list[int] = []
    fold_thresholds: list[float] = []
    sw = training_weights(train) if use_weights else None
    X = train[cols]
    gkf = GroupKFold(n_splits=5)
    for k, (tr, va) in enumerate(gkf.split(train, y, groups)):
        fit = fit_with_inner_weighted(train.iloc[tr].reset_index(drop=True), cols, cfg, seed + k, use_weights=use_weights)
        p_va = fit["model"].predict_proba(train.iloc[va][cols])[:, 1]
        oof[va] = p_va
        iters.append(int(fit["model"].best_iteration_ or fit["model"].n_estimators))
        if threshold_mode == "median_fold":
            fold_thresholds.append(float(tpr_at_fpr(y[va], p_va, target_fpr)["threshold"]))

    scores = oof.copy()
    iso = None
    if calibrate:
        iso = IsotonicRegression(out_of_bounds="clip")
        iso.fit(oof, y)
        scores = iso.predict(oof)

    if threshold_mode == "median_fold":
        threshold = float(np.median(fold_thresholds))
    elif threshold_mode == "pooled":
        threshold = float(tpr_at_fpr(y, scores, target_fpr)["threshold"])
    else:
        raise ValueError(f"unknown threshold_mode {threshold_mode!r}")
    p = cfg.p()
    n_est = int(np.median(iters))
    base = LGBMClassifier(
        n_estimators=n_est, learning_rate=0.05, num_leaves=p["num_leaves"],
        min_child_samples=p["min_child_samples"], colsample_bytree=p["feature_fraction"],
        class_weight="balanced", random_state=seed, verbosity=-1,
    )
    base.fit(X, y, sample_weight=sw)
    model: Any = CalibratedModel(base, iso) if iso is not None else base

    return {
        "model": model,
        "threshold": threshold,
        "cols": cols,
        "config": cfg_name,
        "rule": rule,
        "target_fpr": target_fpr,
        "threshold_mode": threshold_mode,
        "n_estimators": n_est,
        "calibrate": calibrate,
        "use_weights": use_weights,
        "fold_thresholds": fold_thresholds if threshold_mode == "median_fold" else None,
        "oof_rates": rates_at_threshold(y, scores, threshold),
        "oof_rates_uncalibrated": rates_at_threshold(y, oof, threshold) if calibrate else None,
    }
