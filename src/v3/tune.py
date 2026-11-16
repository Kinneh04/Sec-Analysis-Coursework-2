"""Closed OOF grid for V3.2 (train only); writes tuning_selected.json before blind."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from src.v3.cohorts import train_cohorts_for_tag
from src.v3.data import load_pool
from src.v3.fit import fit_oof_calibrated
from src.v3.retrain import blind_feature_sets

GRID = [
    {"target_fpr": 0.008, "threshold_mode": "median_fold", "use_weights": True},
    {"target_fpr": 0.010, "threshold_mode": "median_fold", "use_weights": True},
    {"target_fpr": 0.010, "threshold_mode": "pooled", "use_weights": True},
    {"target_fpr": 0.012, "threshold_mode": "median_fold", "use_weights": True},
    {"target_fpr": 0.010, "threshold_mode": "median_fold", "use_weights": False},
]
FPR_SLACK = 0.002


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--dev-dir", type=Path, default=Path("artifacts/v3/development"))
    ap.add_argument("--cohort-tag", default="v3.2", help="Tag whose new_train is included (plus all prior waves)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--output", type=Path, default=Path("artifacts/v3.2/retrain/tuning_selected.json"))
    args = ap.parse_args(argv)

    cfg_name = json.loads((args.dev_dir / "search_summary.json").read_text(encoding="utf-8"))["selection"]["selected"]
    pool = load_pool(args.config, include_v1_train=True, cohorts=train_cohorts_for_tag(args.cohort_tag))
    fs = blind_feature_sets(pool)
    rows = []
    for g in GRID:
        fv = fit_oof_calibrated(
            pool, fs["pe_v3"], cfg_name, args.seed, calibrate=False, rule="tune", **g,
        )
        fb = fit_oof_calibrated(
            pool, fs["pe_v1s"], cfg_name, args.seed, calibrate=False, rule="tune", **g,
        )
        rv, rb = fv["oof_rates"], fb["oof_rates"]
        ok = rv["fpr"] <= g["target_fpr"] + FPR_SLACK
        rows.append({
            **g,
            "pe_v3_oof_tpr": rv["tpr"],
            "pe_v3_oof_fpr": rv["fpr"],
            "pe_v1s_oof_tpr": rb["tpr"],
            "pe_v1s_oof_fpr": rb["fpr"],
            "delta_tpr": rv["tpr"] - rb["tpr"],
            "fpr_ok": ok,
        })
        print(f"  {g} delta_tpr={rows[-1]['delta_tpr']:.3f} v3_fpr={rv['fpr']:.4f} ok={ok}", flush=True)

    df = pd.DataFrame(rows)
    eligible = df[df["fpr_ok"]].sort_values(["delta_tpr", "pe_v3_oof_tpr"], ascending=[False, False])
    if eligible.empty:
        eligible = df.sort_values(["pe_v3_oof_fpr", "delta_tpr"], ascending=[True, False])
    pick = eligible.iloc[0].to_dict()
    out = {
        "config": cfg_name,
        "seed": args.seed,
        "n_pool": int(len(pool)),
        "grid_results": rows,
        "selected": {k: pick[k] for k in GRID[0].keys()},
        "selected_metrics": {
            "delta_tpr_oof": pick["delta_tpr"],
            "pe_v3_oof_tpr": pick["pe_v3_oof_tpr"],
            "pe_v3_oof_fpr": pick["pe_v3_oof_fpr"],
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2), encoding="utf-8")
    pd.DataFrame(rows).to_csv(args.output.with_suffix(".csv"), index=False)
    print(json.dumps(out["selected"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
