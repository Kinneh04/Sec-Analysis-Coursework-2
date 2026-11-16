"""Development-only replay on an existing blind cohort (not confirmatory; does not touch freeze locks)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.metrics import tpr_at_fpr
from src.v3.data import load_pool
from src.v3.fit import fit_oof_calibrated
from src.v3.retrain import blind_feature_sets
from src.v3.stats import rates_at_threshold


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--dev-dir", type=Path, default=Path("artifacts/v3/development"))
    ap.add_argument("--train-cohorts", default="v3,v3.1")
    ap.add_argument("--blind-cohort", default="v3.1")
    ap.add_argument("--target-fpr", type=float, default=0.01)
    ap.add_argument("--no-calibrate", action="store_true")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--output", type=Path, default=Path("artifacts/v3.1/development/dev_replay.json"))
    args = ap.parse_args(argv)

    cfg_name = json.loads((args.dev_dir / "search_summary.json").read_text(encoding="utf-8"))["selection"]["selected"]
    train_spec = [(t.strip(), ("new_train",)) for t in args.train_cohorts.split(",") if t.strip()]
    pool = load_pool(args.config, include_v1_train=True, cohorts=train_spec)
    blind = load_pool(args.config, include_v1_train=False, cohorts=[(args.blind_cohort, ("blind",))])
    fs = blind_feature_sets(pool)
    yb = blind["label"].to_numpy()
    scores: dict[str, list[float]] = {}
    out: dict = {
        "confirmatory": False,
        "note": "Descriptive replay; blind cohort was used for threshold method comparison only.",
        "config": cfg_name,
        "target_fpr": args.target_fpr,
        "calibrate": not args.no_calibrate,
        "n_train": len(pool),
        "n_blind": len(blind),
        "n_blind_benign": int((yb == 0).sum()),
    }
    for name, cols in fs.items():
        f = fit_oof_calibrated(
            pool, cols, cfg_name, args.seed, target_fpr=args.target_fpr, calibrate=not args.no_calibrate,
        )
        p = f["model"].predict_proba(blind[cols])[:, 1]
        scores[name] = p
        out[name] = {"train_oof": f["oof_rates"], "blind_fixed": rates_at_threshold(yb, p, f["threshold"]), "threshold": f["threshold"]}
    pc, pb = out["pe_v3"]["blind_fixed"], out["pe_v1s"]["blind_fixed"]
    out["fixed_threshold_comparison"] = {
        "delta_tpr": pc["tpr"] - pb["tpr"],
        "delta_fpr": pc["fpr"] - pb["fpr"],
        "fpr_ok_vs_baseline": pc["fpr"] <= pb["fpr"],
    }
    matched = {}
    for fpr in (0.005, 0.01):
        ba = tpr_at_fpr(yb, scores["pe_v1s"], fpr)
        ca = tpr_at_fpr(yb, scores["pe_v3"], fpr)
        matched[str(fpr)] = {"baseline_tpr": ba["tpr"], "candidate_tpr": ca["tpr"], "delta": ca["tpr"] - ba["tpr"]}
    out["matched_fpr_on_blind"] = matched
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
