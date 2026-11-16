"""Leakage and source-proxy checks for PE-v3 (train split only)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold

from src.audit.schema import is_forbidden_predictor
from src.v3.data import load_dev_frames

SUSPECT_AUC = 0.95


def single_feature_auc(train: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    y = train["label"].to_numpy()
    rows = []
    for c in cols:
        x = pd.to_numeric(train[c], errors="coerce").fillna(-1).to_numpy()
        if np.unique(x).size < 2:
            continue
        auc = roc_auc_score(y, x)
        rows.append({"feature": c, "auc": float(auc), "separation": float(abs(auc - 0.5) * 2)})
    df = pd.DataFrame(rows).sort_values("separation", ascending=False).reset_index(drop=True)
    df["suspect"] = df["auc"].apply(lambda a: max(a, 1 - a) >= SUSPECT_AUC)
    return df


def group_cv_auc(train: pd.DataFrame, cols: list[str], y: np.ndarray, *, seed: int, n_splits: int = 5) -> dict[str, float]:
    groups = train["group_id"].astype(str).to_numpy()
    aucs = []
    for tr, va in GroupKFold(n_splits=n_splits).split(train, y, groups):
        if np.unique(y[va]).size < 2:
            continue
        clf = RandomForestClassifier(n_estimators=200, class_weight="balanced_subsample", random_state=seed, n_jobs=-1)
        clf.fit(train.iloc[tr][cols].fillna(-1), y[tr])
        aucs.append(roc_auc_score(y[va], clf.predict_proba(train.iloc[va][cols].fillna(-1))[:, 1]))
    return {"mean_auc": float(np.mean(aucs)), "std_auc": float(np.std(aucs)), "folds": len(aucs)}


def source_predictability(train: pd.DataFrame, cols: list[str], *, seed: int) -> dict[str, Any]:
    """Within benign train rows: can features identify the install root? High values = source cues."""
    ben = train[train["label"] == 0].reset_index(drop=True)
    roots = ben["benign_root"].fillna("unknown").astype(str)
    top = roots.value_counts()
    keep = top[top >= 10].index
    ben = ben[roots.isin(keep)].reset_index(drop=True)
    roots = ben["benign_root"].astype(str)
    if roots.nunique() < 2:
        return {"note": "fewer than two benign roots with >=10 rows"}
    sys_like = roots.str.contains(r"\\Windows\\", case=False).astype(int).to_numpy()
    if np.unique(sys_like).size < 2:
        return {"note": "no Windows-vs-third-party contrast"}
    res = group_cv_auc(ben, cols, sys_like, seed=seed)
    res["task"] = "benign: Windows system dir vs third-party root"
    res["n"] = int(len(ben))
    return res


def run(config: str, output: Path, seed: int) -> dict[str, Any]:
    data = load_dev_frames(config)
    train = data["train"]
    fs = data["feature_sets"]
    cols = fs["pe_v3"]
    y = train["label"].to_numpy()

    forbidden = [c for c in fs["pe_v3_ts"] if is_forbidden_predictor(c)]
    sfa = single_feature_auc(train, fs["pe_v3_ts"])
    rng = np.random.default_rng(seed)
    perm = group_cv_auc(train, cols, rng.permutation(y), seed=seed)
    with_ts = group_cv_auc(train, fs["pe_v3_ts"], y, seed=seed)
    without_ts = group_cv_auc(train, cols, y, seed=seed)
    src = source_predictability(train, cols, seed=seed)
    ts_auc = sfa.loc[sfa["feature"] == "pe3_hdr_timestamp", "auc"]

    report = {
        "split_used": "train_only",
        "n_train": int(len(train)),
        "n_predictors_pe_v3": len(cols),
        "forbidden_names_in_predictors": forbidden,
        "suspect_single_features": sfa[sfa["suspect"]]["feature"].tolist(),
        "suspect_auc_threshold": SUSPECT_AUC,
        "top10_single_feature_auc": sfa.head(10).to_dict(orient="records"),
        "label_permutation_sentinel_auc": perm,
        "timestamp_single_feature_auc": float(ts_auc.iloc[0]) if len(ts_auc) else None,
        "timestamp_ablation_group_cv_auc": {"with_timestamp": with_ts, "without_timestamp": without_ts},
        "timestamp_policy": "excluded from primary predictors (source/build-date proxy)",
        "source_predictability_benign_roots": src,
        "interpretation": (
            "Permutation sentinel near 0.5 means the CV pipeline does not leak labels. "
            "High source predictability means benign install roots are distinguishable from PE content; "
            "that is a corpus confound, not proof of leakage, and limits generalization claims."
        ),
    }
    report["pass"] = (
        not forbidden and abs(perm["mean_auc"] - 0.5) < 0.1
    )
    output.mkdir(parents=True, exist_ok=True)
    sfa.to_csv(output / "single_feature_auc_train.csv", index=False)
    (output / "leakage_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--output", type=Path, default=Path("artifacts/v3/leakage"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)
    rep = run(args.config, args.output, args.seed)
    print(json.dumps({k: rep[k] for k in (
        "pass", "suspect_single_features", "label_permutation_sentinel_auc",
        "timestamp_ablation_group_cv_auc", "source_predictability_benign_roots")}, indent=2))
    return 0 if rep["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
