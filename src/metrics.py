from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def tpr_at_fpr(y_true: np.ndarray, y_score: np.ndarray, fpr_target: float) -> dict:
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score).astype(float)
    benign = y_true == 0
    mal = y_true == 1
    if benign.sum() == 0 or mal.sum() == 0:
        return {"tpr": float("nan"), "threshold": float("nan"), "fpr": float("nan")}

    thresholds = np.unique(y_score)
    if len(thresholds) > 5000:
        thresholds = np.quantile(y_score, np.linspace(0, 1, 5000))
    best = {"tpr": 0.0, "threshold": 1.0, "fpr": 1.0}
    for t in thresholds:
        pred = y_score >= t
        fp = int((pred & benign).sum())
        tp = int((pred & mal).sum())
        fpr = fp / benign.sum()
        tpr = tp / mal.sum()
        if fpr <= fpr_target + 1e-12 and tpr >= best["tpr"]:
            best = {"tpr": float(tpr), "threshold": float(t), "fpr": float(fpr)}
    return best


def classification_metrics(y_true: np.ndarray, y_score: np.ndarray, threshold: float) -> dict:
    y_pred = (y_score >= threshold).astype(int)
    out = {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_score)) if len(np.unique(y_true)) > 1 else float("nan"),
        "pr_auc": float(average_precision_score(y_true, y_score))
        if len(np.unique(y_true)) > 1
        else float("nan"),
    }
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out.update({"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)})
    return out


def bootstrap_tpr_at_fpr(
    y_true: np.ndarray,
    y_score: np.ndarray,
    fpr_target: float,
    n_boot: int = 2000,
    seed: int = 42,
) -> dict:
    """Percentile CI for TPR@FPR on resampled test points (i.i.d.; use group bootstrap when groups available)."""
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score).astype(float)
    n = len(y_true)
    if n < 10 or len(np.unique(y_true)) < 2:
        point = tpr_at_fpr(y_true, y_score, fpr_target)
        return {**point, "ci_low": float("nan"), "ci_high": float("nan"), "n_boot": 0, "note": "insufficient_n"}
    rng = np.random.default_rng(seed)
    samples = []
    for _ in range(n_boot):
        idx = rng.integers(0, n, size=n)
        samples.append(tpr_at_fpr(y_true[idx], y_score[idx], fpr_target)["tpr"])
    arr = np.array(samples, dtype=float)
    point = tpr_at_fpr(y_true, y_score, fpr_target)
    return {
        **point,
        "ci_low": float(np.quantile(arr, 0.025)),
        "ci_high": float(np.quantile(arr, 0.975)),
        "n_boot": n_boot,
    }


def paired_bootstrap_metric_diff(
    y_true: np.ndarray,
    scores_a: np.ndarray,
    scores_b: np.ndarray,
    fpr_target: float,
    n_boot: int = 2000,
    seed: int = 42,
) -> dict:
    """Paired bootstrap for difference in TPR@FPR (B minus A) on identical test rows."""
    y_true = np.asarray(y_true).astype(int)
    scores_a = np.asarray(scores_a, dtype=float)
    scores_b = np.asarray(scores_b, dtype=float)
    n = len(y_true)
    if n < 10:
        ta = tpr_at_fpr(y_true, scores_a, fpr_target)["tpr"]
        tb = tpr_at_fpr(y_true, scores_b, fpr_target)["tpr"]
        return {
            "delta_b_minus_a": float(tb - ta) if not (np.isnan(ta) or np.isnan(tb)) else float("nan"),
            "ci_low": float("nan"),
            "ci_high": float("nan"),
            "n_boot": 0,
            "note": "insufficient_n",
        }
    rng = np.random.default_rng(seed)
    diffs = []
    for _ in range(n_boot):
        idx = rng.integers(0, n, size=n)
        ta = tpr_at_fpr(y_true[idx], scores_a[idx], fpr_target)["tpr"]
        tb = tpr_at_fpr(y_true[idx], scores_b[idx], fpr_target)["tpr"]
        if not (np.isnan(ta) or np.isnan(tb)):
            diffs.append(tb - ta)
    arr = np.array(diffs, dtype=float)
    point_a = tpr_at_fpr(y_true, scores_a, fpr_target)["tpr"]
    point_b = tpr_at_fpr(y_true, scores_b, fpr_target)["tpr"]
    return {
        "tpr_a": point_a,
        "tpr_b": point_b,
        "delta_b_minus_a": float(point_b - point_a),
        "ci_low": float(np.quantile(arr, 0.025)) if len(arr) else float("nan"),
        "ci_high": float(np.quantile(arr, 0.975)) if len(arr) else float("nan"),
        "n_boot": n_boot,
        "fraction_b_greater_than_a": float((arr > 0).mean()) if len(arr) else float("nan"),
    }
