"""Development check: gentle blend score = logit(R1) + w * logit(BN model), threshold at 1% FPR.

Training pool (rows with Binary Ninja features): the BN model is scored out of fold; thresholds are set
on one half of the groups and evaluated on the other half, for R1 alone (w = 0) and each w.
V7 blind (consumed, descriptive only): BN model fit on all training BN rows; thresholds from training
out-of-fold scores.

  python -m src.v7.dev_blend
"""

from __future__ import annotations

import json

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from src.v4.ember import ember_columns, pretrained_model
from src.v4.experiment import TARGET_FPR, _logit
from src.v7.dev_union_oos import PARAMS
from src.v7.experiment import ROOT, USABLE, _bn, candidate_columns, training_frames

BN_ONLY = True
WEIGHTS = (0.0, 0.05, 0.1, 0.2, 0.3, 0.5)


def _thr(benign: np.ndarray, fpr: float = TARGET_FPR) -> float:
    s = np.sort(benign)[::-1]
    k = int(np.floor(fpr * len(s)))
    return float(np.nextafter(s[k], np.inf)) if k < len(s) else float(s[-1])


def main() -> int:
    fr = training_frames()
    sub = fr["pool"][fr["bn_mask"]].reset_index(drop=True)
    cols = [c for c in candidate_columns(sub)["C7a"] if c != "r1_logit"] if BN_ONLY else candidate_columns(sub)["C7a"]
    X, y = sub[cols].to_numpy(dtype=float), sub["label"].to_numpy()
    r1l = sub["r1_logit"].to_numpy()
    res: dict = {"n": int(len(sub)), "features": "bn_only" if BN_ONLY else "r1_plus_bn", "pool_nested": {}}
    gains = {w: [] for w in WEIGHTS}
    fps = {w: [] for w in WEIGHTS}
    for seed in range(10):
        oof = np.zeros(len(sub))
        for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed).split(X, y, sub["group_id"]):
            oof[te] = lgb.LGBMClassifier(random_state=seed, **PARAMS).fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
        bl = _logit(oof)
        g = sub["group_id"].astype(str).unique()
        half = set(np.random.default_rng(seed).choice(g, len(g) // 2, replace=False))
        a = sub["group_id"].astype(str).isin(half).to_numpy()
        for cal, ev in ((a, ~a), (~a, a)):
            base = None
            for w in WEIGHTS:
                s = r1l + w * bl
                t = _thr(s[cal & (y == 0)])
                tp = int(((s >= t) & ev & (y == 1)).sum())
                fp = int(((s >= t) & ev & (y == 0)).sum())
                if w == 0.0:
                    base = (tp, fp)
                gains[w].append(tp - base[0])
                fps[w].append(fp - base[1])
    for w in WEIGHTS:
        res["pool_nested"][str(w)] = {"median_extra_tp": float(np.median(gains[w])), "mean_extra_tp": float(np.mean(gains[w])),
                                      "mean_extra_fp": float(np.mean(fps[w])), "runs_tp_gain_and_fp_not_higher":
                                      int(sum(gt > 0 and ft <= 0 for gt, ft in zip(gains[w], fps[w]))), "n_runs": len(gains[w])}

    oof = np.zeros(len(sub))
    for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=0).split(X, y, sub["group_id"]):
        oof[te] = lgb.LGBMClassifier(random_state=0, **PARAMS).fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
    model = lgb.LGBMClassifier(random_state=0, **PARAMS).fit(X, y)
    b = pd.read_parquet(ROOT / "blind" / "blind_scores.parquet")[["sha256", "label"]]
    em = pd.read_parquet(ROOT / "features" / "ember_v3.parquet")
    b = b.merge(em[["sha256", *ember_columns()]], on="sha256").merge(_bn(list(b["sha256"])), on="sha256")
    b["r1_logit"] = _logit(pretrained_model("PE").predict(b[ember_columns()].to_numpy()))
    cov = b["cap6_status"].isin(USABLE).to_numpy()
    yb = b["label"].to_numpy()
    blb = _logit(model.predict_proba(b[cols].to_numpy(dtype=float))[:, 1])
    res["v7_blind_descriptive_bn_rows"] = {}
    for w in WEIGHTS:
        t = _thr((r1l + w * _logit(oof))[y == 0])
        s = b["r1_logit"].to_numpy() + w * blb
        m = cov
        res["v7_blind_descriptive_bn_rows"][str(w)] = {"tp": int(((s >= t) & m & (yb == 1)).sum()), "fp": int(((s >= t) & m & (yb == 0)).sum()),
                                                       "n_mal": int((m & (yb == 1)).sum()), "n_ben": int((m & (yb == 0)).sum())}
    (ROOT / "development" / "dev_blend.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
