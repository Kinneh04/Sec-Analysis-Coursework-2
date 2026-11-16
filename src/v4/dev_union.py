"""Development only: union of EMBER2024 (R1) with a strict Binary Ninja detector.

Flags a file if R1 >= its frozen threshold OR the Binary Ninja model >= a strict training-derived
threshold. Uses the consumed V4 blind cohort as a development set; any chosen design must be
confirmed on a new frozen blind cohort.
"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd

from src.metrics import tpr_at_fpr
from src.v3.search import fit_oof_threshold
from src.v3.stats import rates_at_threshold
from src.v4.bn_features import bn4_columns, build
from src.v4.ember import ember_columns, pretrained_model
from src.v4.experiment import CFG_NAME, ROOT, SEED, training_frames

STRICT_FPRS = (0.001, 0.0025, 0.005)


def dev_frame(cols: list[str]) -> pd.DataFrame:
    split = pd.read_parquet(ROOT / "manifests" / "new_split_assignments.parquet")
    b = split[split["split"] == "blind"].copy()
    b["label"] = b["label"].map({"benign": 0, "malicious": 1}).astype(int)
    b = b.merge(pd.read_parquet(ROOT / "features" / "ember_v3.parquet"), on="sha256").merge(build(list(b["sha256"])), on="sha256")
    for c in cols:
        if c not in b.columns:
            b[c] = np.nan
    b["r1_score"] = pretrained_model("PE").predict(b[ember_columns()].to_numpy())
    return b


def main() -> int:
    fr = training_frames()
    pool, mask = fr["pool"], fr["bn_mask"]
    bn_cols = bn4_columns(pool)
    designs = {
        "U_bn_only": (pool[mask].reset_index(drop=True), bn_cols),
        "U_ember_bn": (pool, ember_columns() + bn_cols),
    }
    r1_thr = json.loads((ROOT / "freeze" / "freeze_manifest.json").read_text())["thresholds"]["R1"]
    dev = dev_frame(ember_columns() + bn_cols)
    y = dev["label"].to_numpy()
    r1_flag = dev["r1_score"].to_numpy() >= r1_thr
    base = rates_at_threshold(y, dev["r1_score"].to_numpy(), r1_thr)
    out = {"R1": {"tpr": base["tpr"], "fpr": base["fpr"], "fp": base["fp"]}}
    print("R1", out["R1"], flush=True)
    for name, (train, cols) in designs.items():
        f = fit_oof_threshold(train, cols, CFG_NAME, SEED, 0.01)
        ytr = train["label"].to_numpy()
        s = f["model"].predict_proba(dev[cols])[:, 1]
        for t_fpr in STRICT_FPRS:
            thr = float(tpr_at_fpr(ytr, f["oof_scores"], t_fpr)["threshold"])
            flag = r1_flag | (s >= thr)
            tp = int((flag & (y == 1)).sum())
            fp = int((flag & (y == 0)).sum())
            extra = flag & ~r1_flag
            out[f"{name}@{t_fpr}"] = {
                "threshold": thr, "union_tpr": tp / int((y == 1).sum()), "union_fp": fp,
                "extra_tp": int((extra & (y == 1)).sum()), "extra_fp": int((extra & (y == 0)).sum()),
                "extra_tp_groups": int(dev.loc[extra & (y == 1), "group_id"].nunique()),
            }
            print(name, t_fpr, out[f"{name}@{t_fpr}"], flush=True)
    (ROOT / "development" / "union_dev.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
