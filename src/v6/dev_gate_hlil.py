"""V6b development gate for full-analysis HLIL features (development data only).

  python -m src.v6.dev_gate_hlil
"""

from __future__ import annotations

import json

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from src.v6 import bn_capabilities, bn_hlil
from src.v6.dev_gate import OUT, QUEUE, _thr_at_fpr

STRONG = ("hl6_n_resolved_sensitive", "hl6_stack_api_names", "hl6_stack_dll_names")


def main() -> int:
    q = pd.read_csv(QUEUE)
    h = bn_hlil.build(q.sha256.tolist())
    c = bn_capabilities.build(q.sha256.tolist())
    df = q.merge(h, on="sha256").merge(c, on="sha256")
    df = df[df.hl6_status.isin(["ok", "partial"])].reset_index(drop=True)
    hcols = bn_hlil.hl6_columns(df)
    ccols = bn_capabilities.cap6_columns(df)
    df.loc[~df.cap6_status.isin(["ok", "partial"]), ccols] = np.nan
    groups = {"missed_mal": df.r1_missed, "detected_mal": (df.label == 1) & ~df.r1_missed, "benign": df.label == 0}
    rules = [x for x in hcols if x.startswith("hl6_r_")]
    df["strong"] = (df[list(STRONG)] > 0).any(axis=1)
    df["strong_or_rule"] = df.strong | (df[rules] > 0).any(axis=1)
    res: dict = {"n": int(len(df)), "group_sizes": {g: int(m.sum()) for g, m in groups.items()}}
    res["strong_rate"] = {g: round(float(df.loc[m, "strong"].mean()), 3) for g, m in groups.items()}
    res["strong_or_rule_rate"] = {g: round(float(df.loc[m, "strong_or_rule"].mean()), 3) for g, m in groups.items()}
    res["gate_a_pass"] = bool(res["strong_or_rule_rate"]["missed_mal"] >= 0.30 and res["strong_or_rule_rate"]["benign"] <= 0.03)
    res["indicator_rates"] = {k: {g: round(float((df.loc[m, k] > 0).mean()), 3) for g, m in groups.items()} for k in hcols}
    y = df.label.to_numpy()
    r1 = np.clip(df.r1_score.to_numpy(), 1e-6, 1 - 1e-6)
    logit = np.log(r1 / (1 - r1))
    r1_tp = int(((r1 >= _thr_at_fpr(r1[y == 0])) & (y == 1)).sum())
    res["R1_tp"] = r1_tp
    for name, cols in (("hl6", hcols), ("hl6_plus_cap6", hcols + ccols)):
        X = np.column_stack([logit, df[cols].to_numpy(dtype=float)])
        extra = []
        for seed in range(10):
            oof = np.zeros(len(df))
            for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed).split(X, y, df.group_id):
                m = lgb.LGBMClassifier(n_estimators=200, num_leaves=7, min_child_samples=10, learning_rate=0.05,
                                       feature_fraction=0.7, verbose=-1, random_state=seed)
                m.fit(X[tr], y[tr])
                oof[te] = m.predict_proba(X[te])[:, 1]
            extra.append(int(((oof >= _thr_at_fpr(oof[y == 0])) & (y == 1)).sum()) - r1_tp)
        res[f"stacker_{name}"] = {"extra_tp_per_seed": extra, "median": float(np.median(extra)),
                                  "seeds_ge5": int(sum(e >= 5 for e in extra)), "seeds_negative": int(sum(e < 0 for e in extra))}
    res["gate_b_pass"] = bool(res["stacker_hl6"]["seeds_ge5"] == 10)
    (OUT / "dev_gate_hlil.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k != "indicator_rates"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
