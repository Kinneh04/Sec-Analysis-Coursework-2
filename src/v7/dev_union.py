"""Development check (training pool only): guarded union "R1 positive OR rescue model positive".

The rescue model (LightGBM over r1_logit + cap6_* + hl6_*) is scored out of fold on rows with Binary
Ninja features. Its threshold is the lowest value that adds no out-of-fold benign false positive
beyond those R1 already makes, with an optional margin of extra benign headroom.

  python -m src.v7.dev_union
"""

from __future__ import annotations

import json

import lightgbm as lgb
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from src.metrics import tpr_at_fpr
from src.v4.experiment import TARGET_FPR
from src.v7.experiment import ROOT, candidate_columns, training_frames


def main() -> int:
    fr = training_frames()
    pool, mask = fr["pool"], fr["bn_mask"]
    y_all = pool["label"].to_numpy()
    thr_r1 = float(tpr_at_fpr(y_all, pool["r1_score"].to_numpy(), TARGET_FPR)["threshold"])
    sub = pool[mask].reset_index(drop=True)
    cols = candidate_columns(sub)["C7a"]
    X, y = sub[cols].to_numpy(dtype=float), sub["label"].to_numpy()
    r1_pos = sub["r1_score"].to_numpy() >= thr_r1
    out = {"n_bn_rows": int(len(sub)), "n_mal": int(y.sum()), "n_ben": int((y == 0).sum()),
           "r1_tp": int((r1_pos & (y == 1)).sum()), "r1_fp": int((r1_pos & (y == 0)).sum()), "per_seed": []}
    for seed in range(10):
        oof = np.zeros(len(sub))
        for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed).split(X, y, sub["group_id"]):
            m = lgb.LGBMClassifier(n_estimators=300, num_leaves=15, min_child_samples=20, feature_fraction=0.7,
                                   learning_rate=0.05, verbose=-1, random_state=seed)
            m.fit(X[tr], y[tr])
            oof[te] = m.predict_proba(X[te])[:, 1]
        ben_new = oof[(y == 0) & ~r1_pos]
        t = float(np.nextafter(ben_new.max(), np.inf)) if len(ben_new) else 0.5
        rescue = (oof >= t) & ~r1_pos
        out["per_seed"].append({"threshold": t, "extra_tp": int((rescue & (y == 1)).sum()), "extra_fp": int((rescue & (y == 0)).sum()),
                                "r1_missed_mal": int((~r1_pos & (y == 1)).sum())})
    ex = [s["extra_tp"] for s in out["per_seed"]]
    out["median_extra_tp"] = float(np.median(ex))
    (ROOT / "development").mkdir(parents=True, exist_ok=True)
    (ROOT / "development" / "dev_union.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
