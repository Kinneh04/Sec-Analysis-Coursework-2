"""Paired PE vs PE+BN comparison with bootstrap uncertainty (identical test rows)."""

from __future__ import annotations

import argparse
import json
import pickle

import numpy as np
import pandas as pd

from src.common.config import artifacts, load_config
from src.metrics import bootstrap_tpr_at_fpr, paired_bootstrap_metric_diff


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--split-prefix", default="")
    ap.add_argument("--suffix", default="_v2")
    ap.add_argument("--model-a", default="random_forest__pe")
    ap.add_argument("--model-b", default="random_forest__pe_bn")
    ap.add_argument("--n-boot", type=int, default=2000)
    args = ap.parse_args()
    cfg = load_config(args.config)
    art = artifacts(cfg)
    test = pd.read_parquet(art / "splits" / f"{args.split_prefix}test.parquet")
    y = test["label"].map({"benign": 0, "malicious": 1}).to_numpy()
    fpr = float(cfg["evaluation"]["primary_fpr"])

    def scores(run_id: str) -> np.ndarray:
        path = art / "models" / f"{run_id}{args.suffix}.pkl"
        bundle = pickle.loads(path.read_bytes())
        return bundle["pipeline"].predict_proba(test[bundle["features"]])[:, 1]

    sa = scores(args.model_a)
    sb = scores(args.model_b)
    out = {
        "test_n": int(len(test)),
        "fpr_target": fpr,
        "model_a": args.model_a + args.suffix,
        "model_b": args.model_b + args.suffix,
        "bootstrap_a": bootstrap_tpr_at_fpr(y, sa, fpr, n_boot=args.n_boot),
        "bootstrap_b": bootstrap_tpr_at_fpr(y, sb, fpr, n_boot=args.n_boot),
        "paired_delta_b_minus_a": paired_bootstrap_metric_diff(y, sa, sb, fpr, n_boot=args.n_boot),
        "interpretation": (
            "Positive delta means B (typically PE+BN) exceeds A (PE-only) on TPR@FPR. "
            "Use group-aware bootstrap when test groups are small or related."
        ),
    }
    path = art / "evaluations" / f"paired_pe_vs_pebn{args.suffix}.json"
    path.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(json.dumps(out["paired_delta_b_minus_a"], indent=2))
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
