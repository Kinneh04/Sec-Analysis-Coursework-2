"""Gate B ablation over feature subsets and seeds (development data only).

  python -m src.v6.dev_ablation
"""

from __future__ import annotations

import json

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from src.v6.bn_capabilities import build, cap6_columns
from src.v6.dev_gate import OUT, QUEUE, _thr_at_fpr

GENERIC = ("cap6_n_functions", "cap6_n_imports", "cap6_n_insn", "cap6_frac_disassembled", "cap6_imported_unused_frac",
           "cap6_frac_call_import", "cap6_frac_call_func", "cap6_frac_call_reg_unresolved", "cap6_frac_call_mem_indirect")


def main() -> int:
    q = pd.read_csv(QUEUE)
    df = q.merge(build(q.sha256.tolist()), on="sha256")
    cols = cap6_columns(df)
    df.loc[~df.cap6_status.isin(["ok", "partial"]), cols] = np.nan
    r1 = np.clip(df.r1_score.to_numpy(), 1e-6, 1 - 1e-6)
    logit = np.log(r1 / (1 - r1))
    y = df.label.to_numpy()
    subsets = {"all_cap6": cols, "generic_only": [c for c in cols if c in GENERIC],
               "evasion_capability_only": [c for c in cols if c not in GENERIC]}
    r1_t = _thr_at_fpr(r1[y == 0])
    r1_tp = int(((r1 >= r1_t) & (y == 1)).sum())
    res = {"R1": {"tp": r1_tp, "fp": int(((r1 >= r1_t) & (y == 0)).sum())}}
    for name, sub in subsets.items():
        X = np.column_stack([logit, df[sub].to_numpy(dtype=float)])
        extra = []
        for seed in range(10):
            oof = np.zeros(len(df))
            for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed).split(X, y, df.group_id):
                m = lgb.LGBMClassifier(n_estimators=200, num_leaves=7, min_child_samples=10, learning_rate=0.05,
                                       feature_fraction=0.7, verbose=-1, random_state=seed)
                m.fit(X[tr], y[tr])
                oof[te] = m.predict_proba(X[te])[:, 1]
            t = _thr_at_fpr(oof[y == 0])
            extra.append(int(((oof >= t) & (y == 1)).sum()) - r1_tp)
        res[name] = {"n_features": len(sub), "extra_tp_per_seed": extra, "median_extra_tp": float(np.median(extra)),
                     "seeds_with_gain_ge5": int(sum(e >= 5 for e in extra))}
    (OUT / "dev_ablation.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
