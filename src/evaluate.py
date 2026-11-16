from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

from src.common.config import artifacts, load_config
from src.metrics import classification_metrics, tpr_at_fpr

# Published EMBER2024-style reference (LightGBM on full EMBER PE features, test split).
# Not directly comparable — different corpus, labels, and time window.
EMBER2024_REFERENCE = {
    "source": "EMBER2024 paper / Endgame feature set (indicative literature values)",
    "roc_auc": 0.999,
    "tpr_at_1pct_fpr": 0.98,
    "note": "Reference only; not reproduced on this MalwareBazaar + System32 cohort.",
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--split-prefix", default="")
    ap.add_argument("--output-suffix", default="")
    ap.add_argument("--results-name", default="test_results.csv")
    args = ap.parse_args()
    cfg = load_config(args.config)
    art = artifacts(cfg)
    test = pd.read_parquet(art / "splits" / f"{args.split_prefix}test.parquet")
    y_test = test["label"].map({"benign": 0, "malicious": 1}).to_numpy()

    models_dir = art / "models"
    manifest_name = f"train_manifest{args.output_suffix}.json" if args.output_suffix else "train_manifest.json"
    manifest = json.loads((models_dir / manifest_name).read_text(encoding="utf-8"))
    results = []

    for entry in manifest:
        run_id = entry["run_id"]
        model_name = entry["run_id"]
        if args.output_suffix and not model_name.endswith(args.output_suffix):
            continue
        if not args.output_suffix and any(
            model_name.endswith(s) for s in ("_full", "_challenge")
        ):
            continue
        with (models_dir / f"{model_name}.pkl").open("rb") as f:
            bundle = pickle.load(f)
        cols = bundle["features"]
        pipe = bundle["pipeline"]
        threshold = bundle["threshold"]
        scores = pipe.predict_proba(test[cols])[:, 1]
        primary_fpr = float(cfg["evaluation"]["primary_fpr"])
        tpr1 = tpr_at_fpr(y_test, scores, primary_fpr)
        metrics = classification_metrics(y_test, scores, threshold)
        results.append(
            {
                "run_id": run_id,
                "algorithm": entry["algorithm"],
                "feature_set": entry["feature_set"],
                "test_tpr_at_1pct_fpr": tpr1["tpr"],
                "test_fpr_at_threshold": tpr1["fpr"],
                "threshold_from_val": threshold,
                **metrics,
            }
        )
        print(run_id, "TPR@1%FPR=", round(tpr1["tpr"], 4), "ROC-AUC=", round(metrics["roc_auc"], 4))

    df = pd.DataFrame(results)
    eval_dir = art / "evaluations"
    eval_dir.mkdir(parents=True, exist_ok=True)
    out_csv = eval_dir / args.results_name
    df.to_csv(out_csv, index=False)

    # Internal SOTA-style comparison: LightGBM PE vs PE+BN
    lgb_pe = df[(df["algorithm"] == "lightgbm") & (df["feature_set"] == "pe")]
    lgb_pebn = df[(df["algorithm"] == "lightgbm") & (df["feature_set"] == "pe_bn")]
    comparison = {
        "cohort_test_size": int(len(test)),
        "ember2024_reference": EMBER2024_REFERENCE,
        "lightgbm_pe_only": lgb_pe.to_dict(orient="records")[0] if len(lgb_pe) else None,
        "lightgbm_pe_bn": lgb_pebn.to_dict(orient="records")[0] if len(lgb_pebn) else None,
    }
    if len(lgb_pe) and len(lgb_pebn):
        pe_row = lgb_pe.iloc[0]
        pebn_row = lgb_pebn.iloc[0]
        comparison["delta_tpr_at_1pct_fpr"] = float(pebn_row["test_tpr_at_1pct_fpr"] - pe_row["test_tpr_at_1pct_fpr"])
        comparison["delta_roc_auc"] = float(pebn_row["roc_auc"] - pe_row["roc_auc"])
        comparison["bn_beats_pe_on_tpr"] = comparison["delta_tpr_at_1pct_fpr"] > 0
        comparison["claims_sota_over_ember"] = False
        comparison["interpretation"] = (
            "Compare PE vs PE+BN on the same held-out test set. "
            "EMBER2024 numbers are reference-only unless reproduced on matched binaries."
        )

    summary_name = "sota_comparison_full.json" if args.output_suffix == "_full" else "sota_comparison.json"
    if args.output_suffix == "_v2":
        summary_name = "sota_comparison_v2.json"
    summary_path = eval_dir / summary_name
    summary_path.write_text(json.dumps(comparison, indent=2, default=str), encoding="utf-8")

    if args.output_suffix == "_v2":
        ablation = {
            "cohort": "bn_v2_matched",
            "test_size": int(len(test)),
            "results": df.to_dict(orient="records"),
            "lightgbm_delta_pe_vs_pebn": comparison.get("delta_tpr_at_1pct_fpr"),
            "claims_sota": False,
        }
        (eval_dir / "ablation_v2.json").write_text(json.dumps(ablation, indent=2, default=str), encoding="utf-8")

    print(f"Wrote {out_csv} and {summary_path}")


if __name__ == "__main__":
    main()
