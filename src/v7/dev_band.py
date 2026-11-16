"""Development check (training pool only): Binary Ninja rescue restricted to an R1 score band.

Decision rule: positive if R1 >= thr_R1; for R1 in [band_low, thr_R1), positive only if the out-of-fold
Binary Ninja model score >= t_band; otherwise negative. band_low is the R1 threshold at a looser
training FPR (2%, 3% or 5%). t_band is chosen on one half of the groups (no extra benign in band)
and evaluated on the other half.

  python -m src.v7.dev_band
"""

from __future__ import annotations

import json

import lightgbm as lgb
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from src.metrics import tpr_at_fpr
from src.v4.experiment import TARGET_FPR
from src.v7.experiment import ROOT, candidate_columns, training_frames

PARAMS = dict(n_estimators=300, num_leaves=15, min_child_samples=20, feature_fraction=0.7, learning_rate=0.05, verbose=-1)


def main() -> int:
    fr = training_frames()
    pool, mask = fr["pool"], fr["bn_mask"]
    y_all, r_all = pool["label"].to_numpy(), pool["r1_score"].to_numpy()
    thr = float(tpr_at_fpr(y_all, r_all, TARGET_FPR)["threshold"])
    sub = pool[mask].reset_index(drop=True)
    cols = candidate_columns(sub)["C7a"]
    X, y, r1 = sub[cols].to_numpy(dtype=float), sub["label"].to_numpy(), sub["r1_score"].to_numpy()
    res: dict = {"thr_r1": thr, "bands": {}}
    oofs = []
    for seed in range(10):
        oof = np.zeros(len(sub))
        for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed).split(X, y, sub["group_id"]):
            m = lgb.LGBMClassifier(random_state=seed, **PARAMS).fit(X[tr], y[tr])
            oof[te] = m.predict_proba(X[te])[:, 1]
        oofs.append(oof)
    for fpr in (0.02, 0.03, 0.05):
        low = float(tpr_at_fpr(y_all, r_all, fpr)["threshold"])
        band = (r1 >= low) & (r1 < thr)
        runs = []
        for seed, oof in enumerate(oofs):
            g = sub["group_id"].astype(str).unique()
            half = set(np.random.default_rng(seed).choice(g, len(g) // 2, replace=False))
            a = sub["group_id"].astype(str).isin(half).to_numpy()
            for cal, ev in ((a, ~a), (~a, a)):
                ben = oof[cal & band & (y == 0)]
                t = float(np.nextafter(ben.max(), np.inf)) if len(ben) else 0.5
                add = band & ev & (oof >= t)
                runs.append({"extra_tp": int((add & (y == 1)).sum()), "extra_fp": int((add & (y == 0)).sum())})
        res["bands"][str(fpr)] = {"band_low": low, "band_mal": int((band & (y == 1)).sum()), "band_ben": int((band & (y == 0)).sum()),
                                  "median_extra_tp": float(np.median([x["extra_tp"] for x in runs])),
                                  "total_extra_tp": int(sum(x["extra_tp"] for x in runs)),
                                  "total_extra_fp": int(sum(x["extra_fp"] for x in runs)),
                                  "runs_with_fp": int(sum(x["extra_fp"] > 0 for x in runs)), "n_runs": len(runs)}
    (ROOT / "development" / "dev_band.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
