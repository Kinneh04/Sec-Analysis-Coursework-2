"""Retrain frozen V3 configuration on expanding training pools.

  python -m src.v3.retrain --cohort-tag v3.2
"""

from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold

from src.metrics import tpr_at_fpr
from src.v3.cohorts import train_cohorts_for_tag
from src.v3.data import load_pool
from src.v3.fit import fit_oof_calibrated
from src.v3.pe_features_v3 import v3_predictor_columns
from src.v3.pe_v1_stable import v1s_predictor_columns
from src.v3.search import OPERATIONAL_FPR, _cfg_by_name, fit_oof_threshold, fit_with_inner

FRACTIONS = (0.25, 0.5, 0.75, 1.0)
CANDIDATE, BASELINE = "pe_v3", "pe_v1s"


def blind_feature_sets(df: pd.DataFrame) -> dict[str, list[str]]:
    return {CANDIDATE: v3_predictor_columns(df), BASELINE: v1s_predictor_columns(df)}


def learning_curve(pool: pd.DataFrame, fs: dict[str, list[str]], cfg_name: str, seed: int) -> pd.DataFrame:
    cfg = _cfg_by_name(cfg_name)
    y = pool["label"].to_numpy()
    groups = pool["group_id"].astype(str).to_numpy()
    folds = list(GroupKFold(n_splits=5).split(pool, y, groups))
    rng = np.random.default_rng(seed)
    rows = []
    for frac in FRACTIONS:
        for name, cols in fs.items():
            oof = np.full(len(pool), np.nan)
            n_train = []
            for k, (tr, va) in enumerate(folds):
                tr_groups = np.unique(groups[tr])
                keep = set(rng.permutation(tr_groups)[: max(10, int(round(frac * len(tr_groups))))])
                sub = pool.iloc[tr][np.isin(groups[tr], list(keep))].reset_index(drop=True)
                n_train.append(len(sub))
                fit = fit_with_inner(sub, cols, cfg, seed + k)
                oof[va] = fit["model"].predict_proba(pool.iloc[va][cols])[:, 1]
            rows.append({
                "fraction": frac, "feature_set": name, "mean_fold_train_rows": float(np.mean(n_train)),
                "oof_roc_auc": float(roc_auc_score(y, oof)),
                "oof_oracle_tpr_at_1pct": float(tpr_at_fpr(y, oof, 0.01)["tpr"]),
                "oof_oracle_tpr_at_2pct": float(tpr_at_fpr(y, oof, 0.02)["tpr"]),
            })
    return pd.DataFrame(rows)


def _fit_params_for_tag(tag: str, tag_dir: Path) -> dict:
    if tag == "v3.1":
        return {"target_fpr": 0.005, "calibrate": True, "use_weights": True, "threshold_mode": "pooled", "rule": "V3.1"}
    if tag == "v3.2":
        sel = json.loads((tag_dir / "retrain" / "tuning_selected.json").read_text(encoding="utf-8"))["selected"]
        return {
            "target_fpr": float(sel["target_fpr"]),
            "calibrate": False,
            "use_weights": bool(sel["use_weights"]),
            "threshold_mode": str(sel["threshold_mode"]),
            "rule": "V3.2",
        }
    return {}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--dev-dir", type=Path, default=Path("artifacts/v3/development"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--cohort-tag", default="v3")
    ap.add_argument("--target-fpr", type=float, default=None)
    args = ap.parse_args(argv)

    tag = args.cohort_tag
    tag_dir = Path(f"artifacts/{tag}")
    cfg_name = json.loads((args.dev_dir / "search_summary.json").read_text(encoding="utf-8"))["selection"]["selected"]
    train_cohorts = train_cohorts_for_tag(tag) if tag in ("v3", "v3.1", "v3.2") else [("v3", ("new_train",))]
    pool = load_pool(args.config, include_v1_train=True, cohorts=train_cohorts)
    assert not pool["origin"].str.contains("_blind").any()
    fs = blind_feature_sets(pool)
    extra = _fit_params_for_tag(tag, tag_dir)
    target_fpr = args.target_fpr if args.target_fpr is not None else extra.get("target_fpr", OPERATIONAL_FPR)
    print(f"Training pool: {len(pool)} rows ({pool['label'].value_counts().to_dict()}), "
          f"groups={pool['group_id'].nunique()}, tag={tag}, fit={extra or 'A1'}")

    out_dir = tag_dir / "retrain"
    out_dir.mkdir(parents=True, exist_ok=True)
    if tag == "v3":
        learning_curve(pool, fs, cfg_name, args.seed).to_csv(out_dir / "learning_curve.csv", index=False)

    models_dir = tag_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    final = {}
    for name, cols in fs.items():
        if tag in ("v3.1", "v3.2"):
            kw = {k: v for k, v in extra.items() if k not in ("rule", "target_fpr")}
            f = fit_oof_calibrated(
                pool, cols, cfg_name, args.seed, target_fpr=target_fpr, rule=extra.get("rule", "V3.1"), **kw,
            )
        else:
            f = fit_oof_threshold(pool, cols, cfg_name, args.seed, target_fpr)
        f["feature_set"] = name
        f["training_pool_sha256"] = sorted(pool["sha256"])
        with (models_dir / f"final_{name}.pkl").open("wb") as fh:
            pickle.dump(f, fh)
        final[name] = {
            "threshold": f["threshold"], "n_estimators": f["n_estimators"], "n_features": len(cols),
            "train_oof": f["oof_rates"], "calibrate": f.get("calibrate"), "use_weights": f.get("use_weights"),
            "threshold_mode": f.get("threshold_mode"),
        }
    rule = extra.get("rule", "A1")
    summary = {
        "config": cfg_name, "rule": rule, "target_fpr": target_fpr, "seed": args.seed, "cohort_tag": tag,
        "fit_params": extra,
        "n_pool": int(len(pool)), "pool_by_origin": pool.groupby(["origin", "label"]).size().unstack(fill_value=0).to_dict("index"),
        "n_groups": int(pool["group_id"].nunique()), "final": final, "blind_rows_loaded": False,
        "preregistration": f"docs/{tag}_preregistration.md" if tag != "v3" else "docs/v3_preregistration.md",
    }
    (out_dir / "retrain_summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(json.dumps(final, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
