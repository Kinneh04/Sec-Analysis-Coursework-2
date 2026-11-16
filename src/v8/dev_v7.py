"""Development check of the V8 blend candidate: fit on the V7 training pool, applied to the consumed V7
blind cohort (descriptive only; the V7 cohort cannot confirm anything).

  python -m src.v8.dev_v7
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from src.v3.stats import paired_group_bootstrap_fixed, rates_at_threshold
from src.v4.ember import ember_columns, pretrained_model
from src.v4.experiment import _logit
from src.v7.experiment import USABLE, _bn, training_frames
from src.v8 import blend

OUT = Path("artifacts/v8/development")


def main() -> int:
    fr = training_frames()
    bundle = blend.fit(fr["pool"], fr["bn_mask"])
    b = pd.read_parquet("artifacts/v7/blind/blind_scores.parquet")[["sha256", "label", "group_id"]]
    em = pd.read_parquet("artifacts/v7/features/ember_v3.parquet")
    b = b.merge(em[["sha256", *ember_columns()]], on="sha256").merge(_bn(list(b["sha256"])), on="sha256")
    b["r1_score"] = pretrained_model("PE").predict(b[ember_columns()].to_numpy())
    b["r1_logit"] = _logit(b["r1_score"].to_numpy())
    cov = b["cap6_status"].isin(USABLE).to_numpy() & b["hl6_status"].isin(USABLE).to_numpy()
    dec, score = blend.decide(bundle, b, cov)
    y = b["label"].to_numpy()
    r1dec = b["r1_score"].to_numpy() >= bundle["thr_r1"]
    res = {
        "w": bundle["w"], "weight_table": bundle["weight_table"], "t_blend": bundle["t_blend"], "thr_r1": bundle["thr_r1"],
        "train": {k: bundle[k] for k in ("train_bn_rows", "train_r1_flagged_benign_bn_rows", "train_blend_flagged_benign_bn_rows")},
        "v7_blind": {
            "candidate": rates_at_threshold(y, score, 0.0),
            "R1": rates_at_threshold(y, b["r1_score"].to_numpy(), bundle["thr_r1"]),
            "gains_vs_r1": int((dec & ~r1dec & (y == 1)).sum()), "losses_vs_r1": int((~dec & r1dec & (y == 1)).sum()),
            "new_fp_vs_r1": int((dec & ~r1dec & (y == 0)).sum()), "removed_fp_vs_r1": int((~dec & r1dec & (y == 0)).sum()),
            "paired": paired_group_bootstrap_fixed(y, b["r1_score"].to_numpy(), bundle["thr_r1"], score, 0.0,
                                                   b["group_id"].astype(str).to_numpy(), seed=42),
        },
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "dev_v7_blend.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print(json.dumps(res, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
