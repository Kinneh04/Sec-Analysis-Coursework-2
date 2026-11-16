"""Validation-only ablation; never loads frozen test labels."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from src.audit.diagnostics import train_drop_redundant_bn, train_filter_bn_cols
from src.audit.schema import bn_predictor_columns, pe_predictor_columns
from src.metrics import classification_metrics, paired_bootstrap_metric_diff, tpr_at_fpr
from src.train import _make_model


ARMS = {
    "P0_pe_baseline": "pe",
    "P1_pe_plus_bn_all": "pe_bn_all",
    "P2_pe_plus_bn_filtered": "pe_bn_filtered",
    "P3_pe_plus_bn_reduced": "pe_bn_reduced",
    "P4_bn_only": "bn_only",
}


def _feature_cols_for_arm(
    arm_key: str,
    train: pd.DataFrame,
    *,
    bn_all: list[str],
    bn_filtered: list[str],
    bn_reduced: list[str],
) -> list[str]:
    pe = pe_predictor_columns(train)
    if arm_key == "pe":
        return pe
    if arm_key == "pe_bn_all":
        return pe + bn_all
    if arm_key == "pe_bn_filtered":
        return pe + bn_filtered
    if arm_key == "pe_bn_reduced":
        return pe + bn_reduced
    if arm_key == "bn_only":
        return bn_all
    raise ValueError(arm_key)


def _train_cal_indices(n: int, *, cal_fraction: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    idx = np.arange(n)
    rng.shuffle(idx)
    n_cal = min(max(2, int(n * cal_fraction)), max(1, n - 2))
    return idx[n_cal:], idx[:n_cal]


def _threshold_from_calibration(
    y_cal: np.ndarray,
    scores_cal: np.ndarray,
    fpr_target: float,
) -> dict[str, Any]:
    cal = tpr_at_fpr(y_cal, scores_cal, fpr_target)
    benign_cal = int((y_cal == 0).sum())
    return {
        "threshold": cal["threshold"],
        "cal_metrics": cal,
        "benign_in_cal_subset": benign_cal,
        "min_attainable_fpr": float(1 / benign_cal) if benign_cal else float("nan"),
        "threshold_source": "train_calibration_subset",
    }


def run_validation_ablation(
    train: pd.DataFrame,
    val: pd.DataFrame,
    *,
    seed: int,
    fpr_target: float,
    models: tuple[str, ...] = ("random_forest", "lightgbm", "logistic_regression"),
    n_boot: int = 2000,
    pairs_redundancy: pd.DataFrame | None = None,
) -> tuple[pd.DataFrame, dict[str, Any], dict[str, Any]]:
    bn_all = bn_predictor_columns(train)
    bn_filtered = train_filter_bn_cols(train, bn_all)
    bn_reduced = train_drop_redundant_bn(train, bn_filtered, pairs_redundancy if pairs_redundancy is not None else pd.DataFrame())

    y_train = train["label"].astype(int).values
    y_val = val["label"].astype(int).values
    benign_val = int((y_val == 0).sum())
    resolution = {
        "benign_validation_n": benign_val,
        "min_attainable_fpr_validation": float(1 / benign_val) if benign_val else float("nan"),
        "fpr_target": fpr_target,
        "note": "TPR@FPR uses discrete thresholds; 1% FPR may be interpolated when benign count is small.",
    }

    rows = []
    paired_out: dict[str, Any] = {}
    val_scores_cache: dict[tuple[str, str], np.ndarray] = {}

    for model_name in models:
        for arm_label, arm_key in ARMS.items():
            feat_cols = _feature_cols_for_arm(
                arm_key, train, bn_all=bn_all, bn_filtered=bn_filtered, bn_reduced=bn_reduced
            )
            if not feat_cols:
                continue
            X_train = train[feat_cols]
            X_val = val[feat_cols]
            fit_idx, cal_idx = _train_cal_indices(len(y_train), cal_fraction=0.25, seed=seed)
            pipe = _make_model(model_name, seed)
            pipe.fit(X_train.iloc[fit_idx], y_train[fit_idx])
            scores_cal = pipe.predict_proba(X_train.iloc[cal_idx])[:, 1]
            scores_val = pipe.predict_proba(X_val)[:, 1]
            thr_info = _threshold_from_calibration(y_train[cal_idx], scores_cal, fpr_target)
            thr = thr_info["threshold"]
            val_tpr = tpr_at_fpr(y_val, scores_val, fpr_target)
            cls = classification_metrics(y_val, scores_val, thr)
            rows.append(
                {
                    "model": model_name,
                    "arm": arm_label,
                    "n_features": len(feat_cols),
                    "validation_tpr_at_target_fpr": val_tpr["tpr"],
                    "validation_fpr_at_same_threshold": cls["fp"] / benign_val if benign_val else float("nan"),
                    "threshold": thr,
                    "roc_auc_val": cls["roc_auc"],
                    "pr_auc_val": cls["pr_auc"],
                    "precision_val": cls["precision"],
                    "recall_val": cls["recall"],
                    "f1_val": cls["f1"],
                    "tp": cls["tp"],
                    "fp": cls["fp"],
                    "fn": cls["fn"],
                    "tn": cls["tn"],
                }
            )
            val_scores_cache[(model_name, arm_label)] = scores_val

        p0_key = (model_name, "P0_pe_baseline")
        p1_key = (model_name, "P1_pe_plus_bn_all")
        if p0_key in val_scores_cache and p1_key in val_scores_cache:
            if benign_val < 10:
                paired_out[model_name] = {"note": "insufficient_resolution", "benign_validation_n": benign_val}
            else:
                paired_out[model_name] = paired_bootstrap_metric_diff(
                    y_val,
                    val_scores_cache[p0_key],
                    val_scores_cache[p1_key],
                    fpr_target,
                    n_boot=n_boot,
                    seed=seed,
                )
                paired_out[model_name]["comparison"] = "P1_minus_P0"

    ablation_df = pd.DataFrame(rows)
    filters = {
        "bn_all_count": len(bn_all),
        "bn_filtered_count": len(bn_filtered),
        "bn_reduced_count": len(bn_reduced),
        "bn_filtered_dropped": sorted(set(bn_all) - set(bn_filtered)),
        "bn_reduced_dropped": sorted(set(bn_filtered) - set(bn_reduced)),
    }
    return ablation_df, paired_out, {**resolution, **filters}


def permutation_family_importance(
    train: pd.DataFrame,
    val: pd.DataFrame,
    *,
    seed: int,
    n_repeats: int = 5,
) -> pd.DataFrame:
    """Group permutation on validation (ROC-AUC drop), PE+BN all arm, RF only."""
    from sklearn.metrics import roc_auc_score

    pe = pe_predictor_columns(train)
    bn = bn_predictor_columns(train)
    feat_cols = pe + bn
    pipe = _make_model("random_forest", seed)
    pipe.fit(train[feat_cols], train["label"].astype(int))
    X_val = val[feat_cols].copy()
    y_val = val["label"].astype(int).values
    base = pipe.predict_proba(X_val)[:, 1]
    base_auc = roc_auc_score(y_val, base) if len(np.unique(y_val)) > 1 else float("nan")
    rng = np.random.default_rng(seed)
    families: dict[str, list[str]] = {}
    for c in feat_cols:
        fam = c.split("_")[0] if c.startswith("pe_") else ("quality" if c.startswith("quality_") else "bn")
        if c.startswith(("pe_import", "pe_imphash_h", "pe_imp_bucket_")):
            fam = "pe_imports"
        elif c.startswith("pe_section") or "entropy" in c:
            fam = "pe_sections"
        elif c.startswith("pe_"):
            fam = "pe_meta"
        elif "mlil" in c or "il_" in c:
            fam = "bn_mlil"
        elif "cfg" in c or "cyclomatic" in c:
            fam = "bn_cfg"
        elif c.startswith("quality_"):
            fam = "bn_quality"
        else:
            fam = "bn_other"
        families.setdefault(fam, []).append(c)
    rows = []
    for fam, cols in sorted(families.items()):
        drops = []
        for _ in range(n_repeats):
            Xp = X_val.copy()
            for c in cols:
                Xp[c] = rng.permutation(Xp[c].values)
            sc = pipe.predict_proba(Xp)[:, 1]
            auc = roc_auc_score(y_val, sc)
            drops.append(base_auc - auc)
        arr = np.array(drops)
        rows.append(
            {
                "family": fam,
                "n_features": len(cols),
                "baseline_roc_auc": float(base_auc),
                "mean_auc_drop": float(arr.mean()),
                "std_auc_drop": float(arr.std()),
            }
        )
    return pd.DataFrame(rows)


def validation_error_analysis(val: pd.DataFrame, val_pred: pd.DataFrame) -> pd.DataFrame:
    """Merge predictions with coverage metadata for validation FN/FP counts."""
    m = val.merge(val_pred, on="sha256", how="inner")
    m["error_type"] = "tn"
    m.loc[(m["label"] == 1) & (m["pred"] == 0), "error_type"] = "fn"
    m.loc[(m["label"] == 0) & (m["pred"] == 1), "error_type"] = "fp"
    m.loc[(m["label"] == 1) & (m["pred"] == 1), "error_type"] = "tp"
    cols = ["sha256", "label", "pred", "score", "error_type", "bn_extraction_status", "file_size"]
    cols = [c for c in cols if c in m.columns]
    return m[cols]
