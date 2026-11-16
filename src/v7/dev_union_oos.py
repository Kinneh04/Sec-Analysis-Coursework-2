"""Out-of-sample checks of the guarded union (development only).

1. Pool, nested: rescue threshold set on half of the groups (max benign OOF score not already flagged
   by R1), evaluated on the other half.
2. V7 blind cohort (already consumed by the V7 one-shot evaluation, so descriptive only): rescue model
   fit on the full training pool, threshold from pooled OOF scores, applied once.

  python -m src.v7.dev_union_oos
"""

from __future__ import annotations

import json

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from src.metrics import tpr_at_fpr
from src.v4.ember import ember_columns, pretrained_model
from src.v4.experiment import TARGET_FPR, _logit
from src.v7.experiment import ROOT, USABLE, _bn, candidate_columns, training_frames

PARAMS = dict(n_estimators=300, num_leaves=15, min_child_samples=20, feature_fraction=0.7, learning_rate=0.05, verbose=-1)


def _oof(X: np.ndarray, y: np.ndarray, groups: pd.Series, seed: int) -> np.ndarray:
    oof = np.zeros(len(y))
    for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed).split(X, y, groups):
        m = lgb.LGBMClassifier(random_state=seed, **PARAMS)
        m.fit(X[tr], y[tr])
        oof[te] = m.predict_proba(X[te])[:, 1]
    return oof


def main() -> int:
    fr = training_frames()
    pool, mask = fr["pool"], fr["bn_mask"]
    thr_r1 = float(tpr_at_fpr(pool["label"].to_numpy(), pool["r1_score"].to_numpy(), TARGET_FPR)["threshold"])
    sub = pool[mask].reset_index(drop=True)
    cols = candidate_columns(sub)["C7a"]
    X, y = sub[cols].to_numpy(dtype=float), sub["label"].to_numpy()
    r1_pos = sub["r1_score"].to_numpy() >= thr_r1
    nested = []
    for seed in range(10):
        oof = _oof(X, y, sub["group_id"], seed)
        g = sub["group_id"].astype(str).unique()
        rng = np.random.default_rng(seed)
        half = set(rng.choice(g, len(g) // 2, replace=False))
        a = sub["group_id"].astype(str).isin(half).to_numpy()
        for cal, ev in ((a, ~a), (~a, a)):
            ben = oof[cal & (y == 0) & ~r1_pos]
            t = float(np.nextafter(ben.max(), np.inf))
            rescue = (oof >= t) & ~r1_pos & ev
            nested.append({"extra_tp": int((rescue & (y == 1)).sum()), "extra_fp": int((rescue & (y == 0)).sum()),
                           "eval_mal": int((ev & (y == 1)).sum()), "eval_ben": int((ev & (y == 0)).sum())})
    res = {"nested": nested,
           "nested_extra_fp_total": int(sum(n["extra_fp"] for n in nested)),
           "nested_eval_ben_total": int(sum(n["eval_ben"] for n in nested)),
           "nested_median_extra_tp": float(np.median([n["extra_tp"] for n in nested])),
           "nested_runs_with_fp": int(sum(n["extra_fp"] > 0 for n in nested))}

    oof = _oof(X, y, sub["group_id"], 0)
    t = float(np.nextafter(oof[(y == 0) & ~r1_pos].max(), np.inf))
    model = lgb.LGBMClassifier(random_state=0, **PARAMS).fit(X, y)
    b = pd.read_parquet(ROOT / "blind" / "blind_scores.parquet")[["sha256", "label", "score_R1"]]
    em = pd.read_parquet(ROOT / "features" / "ember_v3.parquet")
    b = b.merge(em[["sha256", *ember_columns()]], on="sha256").merge(_bn(list(b["sha256"])), on="sha256")
    b["r1_logit"] = _logit(pretrained_model("PE").predict(b[ember_columns()].to_numpy()))
    cov = b["cap6_status"].isin(USABLE).to_numpy()
    s = model.predict_proba(b[cols].to_numpy(dtype=float))[:, 1]
    yb = b["label"].to_numpy()
    r1b = b["score_R1"].to_numpy() >= thr_r1
    rescue = (s >= t) & ~r1b & cov
    res["v7_blind_descriptive"] = {"threshold": t, "r1_tp": int((r1b & (yb == 1)).sum()), "r1_fp": int((r1b & (yb == 0)).sum()),
                                   "extra_tp": int((rescue & (yb == 1)).sum()), "extra_fp": int((rescue & (yb == 0)).sum()),
                                   "n_mal": int(yb.sum()), "n_ben": int((yb == 0).sum())}
    (ROOT / "development" / "dev_union_oos.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k != "nested"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
