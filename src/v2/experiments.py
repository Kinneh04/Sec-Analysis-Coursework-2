"""Group CV development and validation gate for V2 arms."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupKFold

from src.metrics import classification_metrics, tpr_at_fpr
from src.train import _make_model
from src.v2.calibration import brier_score, fit_calibrated, train_cal_split
from src.v2.features import bn_cols, pe_bn_cols, pe_cols
from src.v2.fusion import attach_eligibility, fusion_probs, threshold_from_train_quantile
from src.v2.selective import review_flags, selective_metrics
from src.v2.statistics import group_bootstrap_tpr_diff

FUSION_QUANTILES = (0.25, 0.50, 0.75)
FUSION_WEIGHTS = (0.25, 0.50, 0.75)
REVIEW_BANDS = (0.05, 0.10)
FPR_DEV_TARGET = 0.02


@dataclass
class FoldModels:
    cal_pe: Any
    cal_pebn: Any
    pe_features: list[str]
    pebn_features: list[str]


def _xy(df: pd.DataFrame, cols: list[str]) -> tuple[np.ndarray, np.ndarray]:
    y = df["label"].astype(int).to_numpy()
    X = df[cols]
    return X, y


def _fit_fold_models(
    train_df: pd.DataFrame,
    *,
    algo: str,
    seed: int,
    cal_fraction: float,
) -> FoldModels:
    pc, bc = pe_cols(train_df), bn_cols(train_df)
    pbc = pe_bn_cols(train_df)
    X, y = _xy(train_df, pc)
    fit_idx, cal_idx = train_cal_split(len(y), fraction=cal_fraction, seed=seed)
    base_pe = _make_model(algo, seed)
    base_pebn = _make_model(algo, seed + 1)
    cal_pe = fit_calibrated(base_pe, X.iloc[fit_idx], y[fit_idx], X.iloc[cal_idx], y[cal_idx])
    Xb, _ = _xy(train_df, pbc)
    cal_pebn = fit_calibrated(
        base_pebn, Xb.iloc[fit_idx], y[fit_idx], Xb.iloc[cal_idx], y[cal_idx]
    )
    return FoldModels(cal_pe=cal_pe, cal_pebn=cal_pebn, pe_features=pc, pebn_features=pbc)


def _predict_cal(m: FoldModels, df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    p_pe = m.cal_pe.predict_proba(df[m.pe_features])[:, 1]
    p_bn = m.cal_pebn.predict_proba(df[m.pebn_features])[:, 1]
    return p_pe, p_bn


def _objective_tpr_constrained_fpr(y: np.ndarray, scores: np.ndarray, fpr_cap: float) -> float:
    r = tpr_at_fpr(y, scores, fpr_cap)
    if np.isnan(r["tpr"]):
        return -1.0
    if r["fpr"] > fpr_cap + 1e-9:
        return r["tpr"] - 10.0 * (r["fpr"] - fpr_cap)
    return r["tpr"]


def inner_cv_select_fusion(
    train_df: pd.DataFrame,
    *,
    algo: str,
    seed: int,
    n_folds: int,
    cal_fraction: float,
    budget: int,
) -> dict[str, Any]:
    train_df = attach_eligibility(train_df)
    gkf = GroupKFold(n_splits=n_folds)
    groups = train_df["group_id"].astype(str).to_numpy()
    grid = [(q, w) for q in FUSION_QUANTILES for w in FUSION_WEIGHTS][:budget]
    scores_sum: dict[tuple[float, float], float] = {g: 0.0 for g in grid}
    fold_count = 0
    for fold_i, (tr_idx, va_idx) in enumerate(gkf.split(train_df, groups=groups)):
        fold_train = train_df.iloc[tr_idx]
        fold_val = train_df.iloc[va_idx]
        models = _fit_fold_models(fold_train, algo=algo, seed=seed + fold_i, cal_fraction=cal_fraction)
        p_pe, p_pebn = _predict_cal(models, fold_val)
        y = fold_val["label"].astype(int).to_numpy()
        elig_tr = fold_train["eligibility_score"].to_numpy()
        elig_va = fold_val["eligibility_score"].to_numpy()
        for q, w in grid:
            thr = threshold_from_train_quantile(elig_tr, q)
            fused, _ = fusion_probs(p_pe, p_pebn, elig_va, threshold=thr, weight=w)
            scores_sum[(q, w)] += _objective_tpr_constrained_fpr(y, fused, FPR_DEV_TARGET)
        fold_count += 1
    best = max(grid, key=lambda k: scores_sum[k] / max(fold_count, 1))
    return {
        "selected_quantile": best[0],
        "selected_weight": best[1],
        "grid_scores": {f"q{q}_w{w}": scores_sum[(q, w)] / fold_count for q, w in grid},
        "n_folds": fold_count,
        "algo": algo,
    }


def fit_full_train_models(
    train_df: pd.DataFrame,
    *,
    algo: str,
    seed: int,
    cal_fraction: float,
) -> FoldModels:
    return _fit_fold_models(train_df, algo=algo, seed=seed, cal_fraction=cal_fraction)


def fixed_threshold_metrics(y: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float]:
    """TPR/FPR at a threshold chosen elsewhere; never re-fit on these rows."""
    y = np.asarray(y, dtype=int)
    pred = np.asarray(scores, dtype=float) >= threshold
    n_ben = int((y == 0).sum())
    n_mal = int((y == 1).sum())
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    return {
        "tpr_fixed": float(tp / n_mal) if n_mal else float("nan"),
        "fpr_fixed": float(fp / n_ben) if n_ben else float("nan"),
        "n_benign": n_ben,
        "n_malicious": n_mal,
        "min_attainable_fpr": float(1 / n_ben) if n_ben else float("nan"),
    }


def select_review_band(by_band: dict[str, dict[str, Any]], *, max_review_rate: float) -> float:
    """Lowest selective error among bands within the review budget; falls back to smallest band."""
    feasible = []
    for band, res in by_band.items():
        rv = res["V2B_review"]
        err = rv.get("selective_error_rate", float("nan"))
        if np.isnan(err) or rv.get("review_rate", 1.0) > max_review_rate:
            continue
        feasible.append((err, float(band)))
    if not feasible:
        return min(float(b) for b in by_band)
    return min(feasible)[1]


def _train_cal_threshold(
    y_tr: np.ndarray, scores_tr: np.ndarray, *, cal_fraction: float, seed: int, fpr_target: float
) -> float:
    _, cal_idx = train_cal_split(len(y_tr), fraction=cal_fraction, seed=seed)
    return float(tpr_at_fpr(y_tr[cal_idx], scores_tr[cal_idx], fpr_target)["threshold"])


def evaluate_arms_on_split_with_train_eligibility(
    models: FoldModels,
    train_df: pd.DataFrame,
    eval_df: pd.DataFrame,
    *,
    fusion_quantile: float,
    fusion_weight: float,
    review_band: float,
    fpr_target: float,
    cal_fraction: float,
    seed: int,
) -> dict[str, Any]:
    train_df = attach_eligibility(train_df)
    eval_df = attach_eligibility(eval_df)
    thr_elig = threshold_from_train_quantile(train_df["eligibility_score"].to_numpy(), fusion_quantile)

    p_pe_tr, p_pebn_tr = _predict_cal(models, train_df)
    fused_tr, _ = fusion_probs(
        p_pe_tr, p_pebn_tr, train_df["eligibility_score"].to_numpy(), threshold=thr_elig, weight=fusion_weight
    )
    y_tr = train_df["label"].astype(int).to_numpy()

    p_pe, p_pebn = _predict_cal(models, eval_df)
    fused, bn_used = fusion_probs(
        p_pe, p_pebn, eval_df["eligibility_score"].to_numpy(), threshold=thr_elig, weight=fusion_weight
    )
    y_eval = eval_df["label"].astype(int).to_numpy()
    groups = eval_df["group_id"].astype(str).to_numpy()

    arms = {
        "B0_pe": (p_pe, p_pe_tr),
        "B1_pe_bn": (p_pebn, p_pebn_tr),
        "V2A_fusion": (fused, fused_tr),
    }
    results: dict[str, Any] = {}
    thresholds: dict[str, float] = {}
    for name, (scores, scores_tr) in arms.items():
        thr = _train_cal_threshold(y_tr, scores_tr, cal_fraction=cal_fraction, seed=seed, fpr_target=fpr_target)
        thresholds[name] = thr
        oracle = tpr_at_fpr(y_eval, scores, fpr_target)
        results[name] = {
            **classification_metrics(y_eval, scores, thr),
            **fixed_threshold_metrics(y_eval, scores, thr),
            "threshold": thr,
            "threshold_source": "train_calibration_subset",
            "oracle_tpr_at_fpr_target": oracle["tpr"],
            "oracle_note": "threshold re-selected on evaluation rows; optimistic, secondary only",
            "brier": brier_score(y_eval, scores),
        }
    review = review_flags(
        fused,
        threshold=thresholds["V2A_fusion"],
        band_half_width=review_band,
        p_pe=p_pe,
        p_pebn=p_pebn,
        bn_used=bn_used,
    )
    results["V2B_review"] = {
        **selective_metrics(y_eval, fused, thresholds["V2A_fusion"], review),
        "review_band": review_band,
    }
    results["V2A_bn_fusion_rate"] = float(bn_used.mean())
    results["eligibility_threshold"] = thr_elig
    results["paired_group_bootstrap"] = {
        "metric": "oracle_tpr_at_fpr_target (CI shape only)",
        "V2A_vs_B0": group_bootstrap_tpr_diff(y_eval, p_pe, fused, groups, fpr_target, seed=seed),
        "B1_vs_B0": group_bootstrap_tpr_diff(y_eval, p_pe, p_pebn, groups, fpr_target, seed=seed),
    }
    results["_scores"] = {"B0_pe": p_pe, "B1_pe_bn": p_pebn, "V2A_fusion": fused, "y": y_eval}
    return results


REVIEW_BUDGET = 0.15


def run_development(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    *,
    seed: int,
    n_folds: int,
    cal_fraction: float,
    budget: int,
    fpr_target: float,
) -> dict[str, Any]:
    primary_algo = "random_forest"
    selection = inner_cv_select_fusion(
        train_df, algo=primary_algo, seed=seed, n_folds=n_folds, cal_fraction=cal_fraction, budget=budget
    )
    q, w = selection["selected_quantile"], selection["selected_weight"]
    models = fit_full_train_models(train_df, algo=primary_algo, seed=seed, cal_fraction=cal_fraction)

    val_by_band = {
        str(band): evaluate_arms_on_split_with_train_eligibility(
            models, train_df, val_df,
            fusion_quantile=q, fusion_weight=w, review_band=band,
            fpr_target=fpr_target, cal_fraction=cal_fraction, seed=seed,
        )
        for band in REVIEW_BANDS
    }
    best_band = select_review_band(val_by_band, max_review_rate=REVIEW_BUDGET)
    val_results = val_by_band[str(best_band)]
    val_results["selected_review_band"] = best_band

    lgbm_models = fit_full_train_models(train_df, algo="lightgbm", seed=seed + 99, cal_fraction=cal_fraction)
    val_lgbm = evaluate_arms_on_split_with_train_eligibility(
        lgbm_models, train_df, val_df,
        fusion_quantile=q, fusion_weight=w, review_band=best_band,
        fpr_target=fpr_target, cal_fraction=cal_fraction, seed=seed + 99,
    )

    scores = val_results["_scores"]
    yv = scores["y"]
    b0, b1, v2a = (val_results[k] for k in ("B0_pe", "B1_pe_bn", "V2A_fusion"))
    b0_err = float(((scores["B0_pe"] >= b0["threshold"]).astype(int) != yv).mean())
    sel = val_results["V2B_review"]
    detection_win = v2a["tpr_fixed"] > b0["tpr_fixed"] + 0.02 and v2a["fpr_fixed"] <= b0["fpr_fixed"]
    triage_win = sel["selective_error_rate"] < b0_err and sel["automation_coverage"] >= 0.5

    for block in list(val_by_band.values()) + [val_lgbm]:
        block.pop("_scores", None)

    best_arm = max(("B0_pe", "B1_pe_bn", "V2A_fusion"), key=lambda k: val_results[k]["tpr_fixed"])
    return {
        "fusion_selection": selection,
        "validation_random_forest": val_results,
        "validation_lightgbm": val_lgbm,
        "validation_by_review_band": val_by_band,
        "development_summary": {
            "headline_metric": "tpr_fixed at train-calibrated threshold (target FPR %.3f)" % fpr_target,
            "B0_tpr_fixed": b0["tpr_fixed"],
            "B0_fpr_fixed": b0["fpr_fixed"],
            "B1_tpr_fixed": b1["tpr_fixed"],
            "B1_fpr_fixed": b1["fpr_fixed"],
            "V2A_tpr_fixed": v2a["tpr_fixed"],
            "V2A_fpr_fixed": v2a["fpr_fixed"],
            "V2A_minus_B0_tpr_fixed": float(v2a["tpr_fixed"] - b0["tpr_fixed"]),
            "B1_minus_B0_tpr_fixed": float(b1["tpr_fixed"] - b0["tpr_fixed"]),
            "B0_oracle_tpr": b0["oracle_tpr_at_fpr_target"],
            "B1_oracle_tpr": b1["oracle_tpr_at_fpr_target"],
            "V2A_oracle_tpr": v2a["oracle_tpr_at_fpr_target"],
            "V2B_selective_error_rate": sel["selective_error_rate"],
            "B0_full_auto_error_rate": b0_err,
            "V2B_automation_coverage": sel["automation_coverage"],
            "V2B_review_rate": sel["review_rate"],
            "selected_review_band": best_band,
            "review_budget": REVIEW_BUDGET,
            "detection_improvement_on_val": bool(detection_win),
            "triage_improvement_on_val": bool(triage_win),
            "best_detection_on_val_arm": best_arm,
            "confirmatory_blind_required": True,
            "sota_claim_supported": False,
        },
        "models": {"random_forest": models, "lightgbm": lgbm_models},
    }

