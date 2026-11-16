"""Score a fixed cohort with frozen V2 protocol (no retraining)."""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.metrics import classification_metrics, tpr_at_fpr
from src.v2.calibration import brier_score, train_cal_split
from src.v2.experiments import FoldModels, _predict_cal
from src.v2.experiments import evaluate_arms_on_split_with_train_eligibility
from src.v2.fusion import attach_eligibility


def load_model_bundle(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        return pickle.load(f)


def run_frozen_scoring(
    train_df: pd.DataFrame,
    eval_df: pd.DataFrame,
    *,
    model_bundle: dict[str, Any],
    protocol: dict[str, Any],
    fpr_target: float,
    seed: int,
) -> dict[str, Any]:
    policy = protocol["policy"]
    models: FoldModels = model_bundle["models"]
    return evaluate_arms_on_split_with_train_eligibility(
        models,
        train_df,
        eval_df,
        fusion_quantile=float(policy["fusion_eligibility_quantile"]),
        fusion_weight=float(policy["fusion_weight"]),
        review_band=float(policy["review_band_half_width"]),
        fpr_target=fpr_target,
        cal_fraction=float(policy["calibration_fraction"]),
        seed=seed,
    )


def resolution_note(eval_df: pd.DataFrame) -> dict[str, Any]:
    y = eval_df["label"].astype(int)
    n_benign = int((y == 0).sum())
    n_mal = int((y == 1).sum())
    return {
        "n_eval": int(len(eval_df)),
        "n_benign": n_benign,
        "n_malicious": n_mal,
        "min_attainable_fpr": float(1 / n_benign) if n_benign else None,
        "benign_for_1pct_fpr_note": "1% FPR label approximate when n_benign < 100",
    }
