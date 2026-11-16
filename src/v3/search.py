"""Preregistered V3 model search (train group CV) and single validation gate.

Grid, objective and decision rules: docs/v3_preregistration.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier, early_stopping
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
from sklearn.model_selection import GroupKFold, StratifiedGroupKFold
from sklearn.pipeline import Pipeline

from src.metrics import tpr_at_fpr
from src.v3.data import load_dev_frames
from src.v3.stats import paired_group_bootstrap_fixed, rates_at_threshold

DEV_FPR = 0.02
TIE_TOL = 0.005
PRIMARY_SET = "pe_v3"
ABLATION_SETS = ("pe_v1", "pe_v3", "pe_v3_bn")


@dataclass(frozen=True)
class ModelConfig:
    family: str
    params: tuple = field(default_factory=tuple)

    @property
    def name(self) -> str:
        return self.family + "__" + "_".join(f"{k}-{v}" for k, v in self.params)

    def p(self) -> dict[str, Any]:
        return dict(self.params)


def preregistered_grid() -> list[ModelConfig]:
    grid = []
    for nl in (15, 31, 63):
        for mcs in (5, 20):
            for ff in (0.3, 0.7):
                grid.append(ModelConfig("lgbm", (("num_leaves", nl), ("min_child_samples", mcs), ("feature_fraction", ff))))
    for mf in ("sqrt", 0.1, 0.3):
        for msl in (1, 3):
            grid.append(ModelConfig("rf", (("max_features", mf), ("min_samples_leaf", msl))))
    return grid


def _fit_one(cfg: ModelConfig, X_fit, y_fit, X_es, y_es, seed: int):
    p = cfg.p()
    if cfg.family == "lgbm":
        m = LGBMClassifier(
            n_estimators=1000, learning_rate=0.05, num_leaves=p["num_leaves"],
            min_child_samples=p["min_child_samples"], colsample_bytree=p["feature_fraction"],
            class_weight="balanced", random_state=seed, verbosity=-1,
        )
        m.fit(X_fit, y_fit, eval_set=[(X_es, y_es)], callbacks=[early_stopping(50, verbose=False)])
        return m
    m = Pipeline([
        ("imp", SimpleImputer(strategy="median")),
        ("clf", RandomForestClassifier(
            n_estimators=500, max_features=p["max_features"], min_samples_leaf=p["min_samples_leaf"],
            class_weight="balanced_subsample", random_state=seed, n_jobs=-1,
        )),
    ])
    m.fit(X_fit, y_fit)
    return m


def inner_split(df: pd.DataFrame, seed: int) -> tuple[np.ndarray, np.ndarray]:
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    fit_idx, hold_idx = next(sgkf.split(df, df["label"], df["group_id"].astype(str)))
    return fit_idx, hold_idx


def fit_with_inner(df: pd.DataFrame, cols: list[str], cfg: ModelConfig, seed: int) -> dict[str, Any]:
    """Fit on inner 80%; inner 20% gives early stopping and the fixed threshold."""
    fit_idx, hold_idx = inner_split(df, seed)
    X, y = df[cols], df["label"].to_numpy()
    model = _fit_one(cfg, X.iloc[fit_idx], y[fit_idx], X.iloc[hold_idx], y[hold_idx], seed)
    p_hold = model.predict_proba(X.iloc[hold_idx])[:, 1]
    return {"model": model, "p_hold": p_hold, "y_hold": y[hold_idx], "cols": cols}


def threshold_from_holdout(y_hold: np.ndarray, p_hold: np.ndarray, fpr: float = DEV_FPR) -> float:
    return float(tpr_at_fpr(y_hold, p_hold, fpr)["threshold"])


def run_grid(train: pd.DataFrame, cols: list[str], *, seed: int) -> tuple[pd.DataFrame, dict]:
    grid = preregistered_grid()
    groups = train["group_id"].astype(str).to_numpy()
    y = train["label"].to_numpy()
    folds = list(GroupKFold(n_splits=5).split(train, y, groups))
    cache: dict[str, list[dict]] = {}
    rows = []
    for cfg in grid:
        per_fold = []
        for k, (tr, va) in enumerate(folds):
            ftr, fva = train.iloc[tr].reset_index(drop=True), train.iloc[va].reset_index(drop=True)
            fit = fit_with_inner(ftr, cols, cfg, seed + k)
            p_val = fit["model"].predict_proba(fva[cols])[:, 1]
            per_fold.append({"p_hold": fit["p_hold"], "y_hold": fit["y_hold"], "p_val": p_val, "y_val": fva["label"].to_numpy()})
        cache[cfg.name] = per_fold
        rows.append(_score_config(cfg.name, cfg.family, per_fold))
        print(f"  {cfg.name}: tpr={rows[-1]['mean_tpr_fixed']:.3f} auc={rows[-1]['mean_auc']:.3f}", flush=True)

    res = pd.DataFrame(rows)
    best_lgbm = _pick(res[res["family"] == "lgbm"])
    best_rf = _pick(res[res["family"] == "rf"])
    ens_folds = [
        {
            "p_hold": (a["p_hold"] + b["p_hold"]) / 2,
            "y_hold": a["y_hold"],
            "p_val": (a["p_val"] + b["p_val"]) / 2,
            "y_val": a["y_val"],
        }
        for a, b in zip(cache[best_lgbm], cache[best_rf])
    ]
    res = pd.concat([res, pd.DataFrame([_score_config(f"ensemble__{best_lgbm}+{best_rf}", "ensemble", ens_folds)])], ignore_index=True)
    selected = _pick(res)
    return res, {"selected": selected, "best_lgbm": best_lgbm, "best_rf": best_rf}


def _score_config(name: str, family: str, per_fold: list[dict]) -> dict[str, Any]:
    tprs, fprs, aucs = [], [], []
    for f in per_fold:
        thr = threshold_from_holdout(f["y_hold"], f["p_hold"])
        r = rates_at_threshold(f["y_val"], f["p_val"], thr)
        tprs.append(r["tpr"])
        fprs.append(r["fpr"])
        aucs.append(roc_auc_score(f["y_val"], f["p_val"]))
    return {
        "config": name, "family": family,
        "mean_tpr_fixed": float(np.mean(tprs)), "std_tpr_fixed": float(np.std(tprs)),
        "mean_fpr_fixed": float(np.mean(fprs)), "mean_auc": float(np.mean(aucs)),
        "fold_tpr": json.dumps([round(t, 4) for t in tprs]),
    }


def _pick(res: pd.DataFrame) -> str:
    best = res["mean_tpr_fixed"].max()
    tied = res[res["mean_tpr_fixed"] >= best - TIE_TOL]
    return str(tied.sort_values(["mean_auc", "config"], ascending=[False, True]).iloc[0]["config"])


def _cfg_by_name(name: str) -> ModelConfig:
    return {c.name: c for c in preregistered_grid()}[name]


class EnsembleModel:
    def __init__(self, members: list[Any], member_cols: list[list[str]]):
        self.members = members
        self.member_cols = member_cols

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        ps = [m.predict_proba(X[c])[:, 1] for m, c in zip(self.members, self.member_cols)]
        p = np.mean(ps, axis=0)
        return np.column_stack([1 - p, p])


def fit_selected(train: pd.DataFrame, cols: list[str], selection: dict, seed: int) -> dict[str, Any]:
    name = selection["selected"]
    if name.startswith("ensemble__"):
        fits = [fit_with_inner(train, cols, _cfg_by_name(n), seed) for n in (selection["best_lgbm"], selection["best_rf"])]
        model = EnsembleModel([f["model"] for f in fits], [cols, cols])
        p_hold = np.mean([f["p_hold"] for f in fits], axis=0)
        y_hold = fits[0]["y_hold"]
    else:
        fit = fit_with_inner(train, cols, _cfg_by_name(name), seed)
        model, p_hold, y_hold = fit["model"], fit["p_hold"], fit["y_hold"]
    return {"model": model, "threshold": threshold_from_holdout(y_hold, p_hold), "cols": cols, "config": name}


OPERATIONAL_FPR = 0.01


def fit_oof_threshold(train: pd.DataFrame, cols: list[str], cfg_name: str, seed: int, fpr: float = OPERATIONAL_FPR) -> dict[str, Any]:
    """Amendment A1: threshold from pooled group-CV out-of-fold scores; final model refit on all rows."""
    if cfg_name.startswith("ensemble__"):
        raise ValueError("A1 is registered for single-model configurations only")
    cfg = _cfg_by_name(cfg_name)
    y = train["label"].to_numpy()
    groups = train["group_id"].astype(str).to_numpy()
    oof = np.full(len(train), np.nan)
    iters = []
    for k, (tr, va) in enumerate(GroupKFold(n_splits=5).split(train, y, groups)):
        fit = fit_with_inner(train.iloc[tr].reset_index(drop=True), cols, cfg, seed + k)
        oof[va] = fit["model"].predict_proba(train.iloc[va][cols])[:, 1]
        if cfg.family == "lgbm":
            iters.append(int(fit["model"].best_iteration_ or fit["model"].n_estimators))
    threshold = float(tpr_at_fpr(y, oof, fpr)["threshold"])
    if cfg.family == "lgbm":
        p = cfg.p()
        n_est = int(np.median(iters))
        model = LGBMClassifier(
            n_estimators=n_est, learning_rate=0.05, num_leaves=p["num_leaves"],
            min_child_samples=p["min_child_samples"], colsample_bytree=p["feature_fraction"],
            class_weight="balanced", random_state=seed, verbosity=-1,
        )
        model.fit(train[cols], y)
    else:
        n_est = None
        model = _fit_one(cfg, train[cols], y, None, None, seed)
    return {
        "model": model, "threshold": threshold, "cols": cols, "config": cfg_name,
        "rule": "A1", "target_fpr": fpr, "n_estimators": n_est, "oof_iterations": iters,
        "oof_rates": rates_at_threshold(y, oof, threshold),
        "oof_scores": oof,
    }


def amendment_a1_on_val(train: pd.DataFrame, val: pd.DataFrame, fs: dict[str, list[str]], cfg_name: str, seed: int) -> dict[str, Any]:
    fitted, scores, out = {}, {}, {}
    y = val["label"].to_numpy()
    for name in ABLATION_SETS:
        f = fit_oof_threshold(train, fs[name], cfg_name, seed)
        p = f["model"].predict_proba(val[f["cols"]])[:, 1]
        fitted[name], scores[name] = f, p
        out[name] = {
            "n_features": len(f["cols"]), "threshold": f["threshold"], "n_estimators": f["n_estimators"],
            "train_oof": f["oof_rates"],
            "fixed": rates_at_threshold(y, p, f["threshold"]),
            "roc_auc": float(roc_auc_score(y, p)),
        }
    groups = val["group_id"].astype(str).to_numpy()
    for name in ("pe_v3", "pe_v3_bn"):
        out[f"paired_{name}_vs_pe_v1"] = paired_group_bootstrap_fixed(
            y, scores["pe_v1"], fitted["pe_v1"]["threshold"], scores[name], fitted[name]["threshold"], groups, seed=seed
        )
    out["note"] = "Descriptive only: A1 was registered after the validation gate."
    return {"results": out, "fitted": fitted}


def validation_gate(train: pd.DataFrame, val: pd.DataFrame, fs: dict[str, list[str]], selection: dict, seed: int) -> dict[str, Any]:
    fitted, scores, out = {}, {}, {}
    y = val["label"].to_numpy()
    for name in ABLATION_SETS:
        f = fit_selected(train, fs[name], selection, seed)
        p = f["model"].predict_proba(val[f["cols"]])[:, 1]
        fitted[name], scores[name] = f, p
        out[name] = {
            "n_features": len(f["cols"]),
            "threshold": f["threshold"],
            "fixed": rates_at_threshold(y, p, f["threshold"]),
            "oracle_tpr_at_1pct_fpr": float(tpr_at_fpr(y, p, 0.01)["tpr"]),
            "roc_auc": float(roc_auc_score(y, p)),
            "pr_auc": float(average_precision_score(y, p)),
            "brier": float(brier_score_loss(y, p)),
        }
    groups = val["group_id"].astype(str).to_numpy()
    for name in ("pe_v3", "pe_v3_bn"):
        out[f"paired_{name}_vs_pe_v1"] = paired_group_bootstrap_fixed(
            y, scores["pe_v1"], fitted["pe_v1"]["threshold"], scores[name], fitted[name]["threshold"], groups, seed=seed
        )
    a, b = out["pe_v1"]["fixed"], out["pe_v3"]["fixed"]
    carry = "pe_v3" if (b["tpr"] > a["tpr"] and b["fpr"] <= a["fpr"]) else "pe_v1"
    out["carried_forward_feature_set"] = carry
    out["decision_rule"] = "pe_v3 if val fixed-threshold TPR > pe_v1 with FPR no higher, else pe_v1"
    return {"results": out, "fitted": fitted}


def run(config: str, output: Path, seed: int) -> dict[str, Any]:
    data = load_dev_frames(config)
    train, val, fs = data["train"], data["val"], data["feature_sets"]
    prereg = Path("docs/v3_preregistration.md")
    output.mkdir(parents=True, exist_ok=True)

    print(f"Grid search on {PRIMARY_SET} ({len(fs[PRIMARY_SET])} features, n_train={len(train)})")
    grid_res, selection = run_grid(train, fs[PRIMARY_SET], seed=seed)
    grid_res.to_csv(output / "grid_results_train_cv.csv", index=False)

    gate = validation_gate(train, val, fs, selection, seed)
    models_dir = output.parent / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    for name, f in gate["fitted"].items():
        with (models_dir / f"{name}__selected.pkl").open("wb") as fh:
            pickle.dump(f, fh)

    summary = {
        "preregistration_sha256": hashlib.sha256(prereg.read_bytes()).hexdigest() if prereg.is_file() else None,
        "seed": seed,
        "n_train": int(len(train)), "n_val": int(len(val)),
        "selection": selection,
        "grid_size_scored": int(len(grid_res)),
        "validation_gate": gate["results"],
        "test_split_used": False,
        "confirmatory": False,
        "sota_claim_supported": False,
    }
    (output / "search_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def run_a1(config: str, output: Path, seed: int) -> int:
    summary = json.loads((output / "search_summary.json").read_text(encoding="utf-8"))
    cfg_name = summary["selection"]["selected"]
    data = load_dev_frames(config)
    res = amendment_a1_on_val(data["train"], data["val"], data["feature_sets"], cfg_name, seed)
    models_dir = output.parent / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    for name, f in res["fitted"].items():
        with (models_dir / f"{name}__a1.pkl").open("wb") as fh:
            pickle.dump(f, fh)
    out = {"config": cfg_name, "seed": seed, "test_split_used": False, "confirmatory": False, **res["results"]}
    (output / "a1_val_summary.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps({k: {"val_tpr": out[k]["fixed"]["tpr"], "val_fpr": out[k]["fixed"]["fpr"],
                          "oof_tpr": out[k]["train_oof"]["tpr"], "oof_fpr": out[k]["train_oof"]["fpr"], "auc": out[k]["roc_auc"]}
                      for k in ABLATION_SETS} | {"paired_pe_v3_vs_pe_v1": out["paired_pe_v3_vs_pe_v1"]}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--output", type=Path, default=Path("artifacts/v3/development"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--a1", action="store_true", help="Run Amendment A1 using the already-selected configuration")
    args = ap.parse_args(argv)
    if args.a1:
        return run_a1(args.config, args.output, args.seed)
    s = run(args.config, args.output, args.seed)
    g = s["validation_gate"]
    print(json.dumps({
        "selected": s["selection"]["selected"],
        **{k: {"tpr": g[k]["fixed"]["tpr"], "fpr": g[k]["fixed"]["fpr"], "oracle": g[k]["oracle_tpr_at_1pct_fpr"], "auc": g[k]["roc_auc"]}
           for k in ABLATION_SETS},
        "paired_pe_v3_vs_pe_v1": g["paired_pe_v3_vs_pe_v1"],
        "carried_forward": g["carried_forward_feature_set"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
