"""Development only: residual boosting from the EMBER2024 logit with Binary Ninja features.

Uses the already-consumed V4 blind cohort as a development set. Any design chosen here must be
confirmed on a new frozen blind cohort before any claim is made.
"""

from __future__ import annotations

import json

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold

from src.metrics import tpr_at_fpr
from src.v3.stats import rates_at_threshold
from src.v4.bn_features import USABLE, bn4_columns, build
from src.v4.ember import ember_columns, pretrained_model
from src.v4.experiment import ROOT, _logit, training_frames

PARAMS = {"objective": "binary", "learning_rate": 0.02, "num_leaves": 7, "min_data_in_leaf": 40,
          "feature_fraction": 0.5, "lambda_l2": 10.0, "verbose": -1, "seed": 42, "num_threads": 8}


def _fit(X, y, init, rounds):
    return lgb.train(PARAMS, lgb.Dataset(X, y, init_score=init), num_boost_round=rounds)


def main() -> int:
    fr = training_frames()
    pool = fr["pool"][fr["bn_mask"]].reset_index(drop=True)
    cols = bn4_columns(pool)
    X, y, init = pool[cols].to_numpy(), pool["label"].to_numpy(), pool["r1_logit"].to_numpy()
    groups = pool["group_id"].astype(str).to_numpy()
    out = {}
    for rounds in (0, 25, 50, 100, 200):
        oof = np.full(len(pool), np.nan)
        for tr, va in GroupKFold(n_splits=5).split(X, y, groups):
            if rounds == 0:
                oof[va] = init[va]
            else:
                b = _fit(X[tr], y[tr], init[tr], rounds)
                oof[va] = init[va] + b.predict(X[va], raw_score=True)
        thr = float(tpr_at_fpr(y, oof, 0.01)["threshold"])
        full = _fit(X, y, init, rounds) if rounds else None

        split = pd.read_parquet(ROOT / "manifests" / "new_split_assignments.parquet")
        b_ = split[split["split"] == "blind"].copy()
        b_["label"] = b_["label"].map({"benign": 0, "malicious": 1}).astype(int)
        b_ = b_.merge(pd.read_parquet(ROOT / "features" / "ember_v3.parquet"), on="sha256").merge(build(list(b_["sha256"])), on="sha256")
        for c in cols:
            if c not in b_.columns:
                b_[c] = np.nan
        bl = _logit(pretrained_model("PE").predict(b_[ember_columns()].to_numpy()))
        s = bl + (full.predict(b_[cols].to_numpy(), raw_score=True) if full else 0.0)
        yb = b_["label"].to_numpy()
        r = rates_at_threshold(yb, s, thr)
        out[rounds] = {"train_oof_tpr": rates_at_threshold(y, oof, thr)["tpr"], "train_oof_auc": float(roc_auc_score(y, oof)),
                       "dev_tpr": r["tpr"], "dev_fpr": r["fpr"], "dev_auc": float(roc_auc_score(yb, s)),
                       "dev_matched_tpr_1pct": float(tpr_at_fpr(yb, s, 0.01)["tpr"])}
        print(rounds, {k: round(v, 4) for k, v in out[rounds].items()}, flush=True)
    (ROOT / "development" / "residual_dev.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
