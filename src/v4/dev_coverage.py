"""Development only: do Binary Ninja designs improve as training coverage grows?

Uses every cached Binary Ninja result for training-pool rows, and evaluates on the consumed V4
blind cohort (development set). Appends one row per run to artifacts/v4/development/coverage_curve.csv.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from src.metrics import tpr_at_fpr
from src.v3.cohorts import train_cohorts_for_tag
from src.v3.data import load_pool
from src.v3.search import fit_oof_threshold
from src.v4.bn_features import USABLE, bn4_columns, build
from src.v4.dev_union import dev_frame
from src.v4.ember import ember_columns, pretrained_model
from src.v4.experiment import CFG_NAME, CONFIG, ROOT, SEED, _logit


def pool_with_bn() -> tuple[pd.DataFrame, np.ndarray]:
    pool = load_pool(CONFIG, include_v1_train=True, cohorts=train_cohorts_for_tag("v3.2"))[["sha256", "label", "group_id"]]
    pool = pool.merge(pd.read_parquet(ROOT / "features" / "ember_v3.parquet"), on="sha256")
    pool = pool[pool["em_status"] == "ok"].reset_index(drop=True)
    pool["r1_score"] = pretrained_model("PE").predict(pool[ember_columns()].to_numpy())
    pool["r1_logit"] = _logit(pool["r1_score"].to_numpy())
    pool = pool.merge(build(list(pool["sha256"])), on="sha256", how="left")
    mask = pool["bn4_status"].isin(USABLE).to_numpy()
    pool.loc[~mask, bn4_columns(pool)] = np.nan
    return pool, mask


def main() -> int:
    pool, mask = pool_with_bn()
    bn = bn4_columns(pool)
    dev = dev_frame(ember_columns() + bn)
    dev["r1_logit"] = _logit(dev["r1_score"].to_numpy())
    y = dev["label"].to_numpy()
    r1_thr = json.loads((ROOT / "freeze" / "freeze_manifest.json").read_text())["thresholds"]["R1"]
    r1 = dev["r1_score"].to_numpy()
    row = {"at": datetime.now(timezone.utc).isoformat(), "bn_rows": int(mask.sum()),
           "R1_auc": roc_auc_score(y, r1), "R1_m1": tpr_at_fpr(y, r1, 0.01)["tpr"],
           "R1_tp": int(((r1 >= r1_thr) & (y == 1)).sum()), "R1_fp": int(((r1 >= r1_thr) & (y == 0)).sum())}
    for name, cols in {"C2": ["r1_logit"] + bn, "C1": ember_columns() + bn}.items():
        f = fit_oof_threshold(pool, cols, CFG_NAME, SEED, 0.01)
        s = f["model"].predict_proba(dev[cols])[:, 1]
        row[f"{name}_auc"] = roc_auc_score(y, s)
        row[f"{name}_m1"] = tpr_at_fpr(y, s, 0.01)["tpr"]
        row[f"{name}_tp"] = int(((s >= f["threshold"]) & (y == 1)).sum())
        row[f"{name}_fp"] = int(((s >= f["threshold"]) & (y == 0)).sum())
        if name == "C1":
            ytr = pool["label"].to_numpy()
            for t in (0.0025, 0.005):
                thr = float(tpr_at_fpr(ytr, f["oof_scores"], t)["threshold"])
                extra = (s >= thr) & (r1 < r1_thr)
                row[f"U{t}_extra_tp"] = int((extra & (y == 1)).sum())
                row[f"U{t}_extra_fp"] = int((extra & (y == 0)).sum())
    print({k: (round(v, 4) if isinstance(v, float) else v) for k, v in row.items()}, flush=True)
    out = ROOT / "development" / "coverage_curve.csv"
    pd.DataFrame([row]).to_csv(out, mode="a", header=not out.exists(), index=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
