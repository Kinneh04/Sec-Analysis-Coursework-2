"""Development gate for instruction-level Binary Ninja features (V4 blind cohort used as development set).

Passes only if a design detects >= 5 more development malware files than R1 at frozen thresholds with
no added false positives. A pass justifies a new preregistration and a fresh blind cohort; it is not
itself a result.
"""

from __future__ import annotations

import json

import numpy as np
from sklearn.metrics import roc_auc_score

from src.metrics import tpr_at_fpr
from src.v3.search import fit_oof_threshold
from src.v4.bn_features import bn4_columns
from src.v4.dev_coverage import pool_with_bn
from src.v4.dev_union import dev_frame
from src.v4.ember import ember_columns
from src.v4.experiment import CFG_NAME, ROOT, SEED, _logit
from src.v5.bn_insn import build, in5_columns

MIN_EXTRA_TP = 5


def main() -> int:
    pool, _ = pool_with_bn()
    pool = pool.merge(build(list(pool["sha256"])), on="sha256", how="left")
    ins = in5_columns(pool)
    in_mask = pool["in5_status"].isin(("ok", "partial")).to_numpy()
    bn = bn4_columns(pool)
    dev = dev_frame(ember_columns() + bn)
    dev = dev.merge(build(list(dev["sha256"])), on="sha256", how="left")
    for c in ins:
        if c not in dev.columns:
            dev[c] = np.nan
    dev["r1_logit"] = _logit(dev["r1_score"].to_numpy())
    y = dev["label"].to_numpy()
    r1 = dev["r1_score"].to_numpy()
    r1_thr = json.loads((ROOT / "freeze" / "freeze_manifest.json").read_text())["thresholds"]["R1"]
    r1_tp, r1_fp = int(((r1 >= r1_thr) & (y == 1)).sum()), int(((r1 >= r1_thr) & (y == 0)).sum())
    out = {"train_insn_rows": int(in_mask.sum()), "dev_insn_coverage": float(dev["in5_status"].isin(("ok", "partial")).mean()),
           "R1": {"tp": r1_tp, "fp": r1_fp, "auc": roc_auc_score(y, r1), "m1": tpr_at_fpr(y, r1, 0.01)["tpr"]}}
    designs = {"C2_bn4": ["r1_logit"] + bn, "C2_insn": ["r1_logit"] + ins, "C2_bn4_insn": ["r1_logit"] + bn + ins}
    for name, cols in designs.items():
        f = fit_oof_threshold(pool, cols, CFG_NAME, SEED, 0.01)
        s = f["model"].predict_proba(dev[cols])[:, 1]
        tp, fp = int(((s >= f["threshold"]) & (y == 1)).sum()), int(((s >= f["threshold"]) & (y == 0)).sum())
        out[name] = {"tp": tp, "fp": fp, "extra_tp": tp - r1_tp, "auc": roc_auc_score(y, s), "m1": tpr_at_fpr(y, s, 0.01)["tpr"],
                     "gate_pass": (tp - r1_tp) >= MIN_EXTRA_TP and fp <= r1_fp}
        print(name, out[name], flush=True)
    out["gate_pass_any"] = any(v.get("gate_pass") for k, v in out.items() if isinstance(v, dict) and k.startswith("C2"))
    (ROOT.parent / "v5").mkdir(parents=True, exist_ok=True)
    (ROOT.parent / "v5" / "dev_gate.json").write_text(json.dumps(out, indent=2, default=float), encoding="utf-8")
    print(json.dumps({"R1": out["R1"], "gate_pass_any": out["gate_pass_any"]}, default=float))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
