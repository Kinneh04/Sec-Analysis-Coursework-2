"""Orchestrate read-only feature audit."""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from src.audit.contribution import run_validation_ablation
from src.audit.diagnostics import (
    bn_missingness_by_class,
    coverage_tables,
    feature_quality_table,
    redundancy_groups,
)
from src.audit.inputs import build_model_tables, load_audit_inputs, verify_split_integrity
from src.audit.leakage import schema_report, source_label_confounding
from src.audit.report import build_audit_summary, render_markdown, write_json


def _git_commit() -> str | None:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True)
        return out.strip()
    except Exception:
        return None


def _verify_frozen_sha_files(data: dict) -> list[str]:
    issues = []
    art = data["art"]
    assign = data["assignments"]
    for split in ("train", "val", "test"):
        p = art / "manifests" / f"frozen_{split}_sha256.txt"
        if not p.is_file():
            issues.append(f"missing_frozen_{split}_sha256.txt")
            continue
        sha_set = {ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")}
        assign_set = set(assign[assign["split"] == split]["sha256"])
        if sha_set != assign_set:
            issues.append(f"frozen_sha_mismatch_{split}")
    return issues


def run_audit(
    config: str,
    output: Path,
    *,
    seed: int,
    strict: bool,
    dry_run: bool,
) -> int:
    data = load_audit_inputs(config)
    split_report = verify_split_integrity(data)
    frozen_issues = _verify_frozen_sha_files(data)
    split_report["issues"].extend(frozen_issues)
    split_report["pass"] = split_report["pass"] and not frozen_issues

    schema = schema_report(data["train"], data["val"], strict=strict)
    tables = build_model_tables(data)
    train, val = tables["train"], tables["val"]

    output.mkdir(parents=True, exist_ok=True)
    try:
        import lightgbm
        import sklearn

        dep_versions = {
            "pandas": pd.__version__,
            "sklearn": sklearn.__version__,
            "lightgbm": lightgbm.__version__,
        }
    except Exception:
        dep_versions = {"pandas": pd.__version__}

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "config": config,
        "python": sys.version,
        "platform": platform.platform(),
        "git_commit": _git_commit(),
        "dependencies": dep_versions,
        "provenance": data["provenance"],
        "dry_run": dry_run,
    }
    write_json(output / "run_manifest.json", manifest)
    write_json(output / "split_integrity.json", split_report)
    write_json(output / "schema_report.json", schema)

    if not split_report["pass"]:
        write_json(
            output / "audit_summary.json",
            build_audit_summary({"input_integrity": "fail", "conclusion": "inconclusive"}),
        )
        (output / "audit_report.md").write_text(
            "# Audit stopped at Gate A\n\nSplit integrity failed. See split_integrity.json.\n",
            encoding="utf-8",
        )
        return 1

    cov_df, cov_summary = coverage_tables(train, val, data["inventory"])
    cov_df.to_csv(output / "coverage_by_class_source.csv", index=False)
    write_json(output / "coverage_summary.json", cov_summary)

    fq = feature_quality_table(train)
    fq.to_csv(output / "feature_quality.csv", index=False)
    red = redundancy_groups(train)
    red.to_csv(output / "redundancy_groups.csv", index=False)
    write_json(output / "source_label_confounding.json", source_label_confounding(train, val))

    leakage_risk = "none_detected"
    forbidden_in_schema = schema.get("constant_on_train", [])
    if schema.get("pe_bn_name_overlap"):
        leakage_risk = "suspected"

    if dry_run:
        write_json(
            output / "audit_summary.json",
            build_audit_summary(
                {
                    "input_integrity": "pass",
                    "leakage_risk": leakage_risk,
                    "candidate_arms": list(
                        ["P0_pe_baseline", "P1_pe_plus_bn_all", "P2_pe_plus_bn_filtered", "P3_pe_plus_bn_reduced", "P4_bn_only"]
                    ),
                    "conclusion": "inconclusive",
                }
            ),
        )
        (output / "audit_report.md").write_text("# Dry run complete\n\nGate A passed; models not fit.\n", encoding="utf-8")
        return 0

    cfg = data["cfg"]
    fpr_target = float(cfg.get("experiment", {}).get("primary_fpr", 0.01))

    ablation_df, paired, resolution = run_validation_ablation(
        train,
        val,
        seed=seed,
        fpr_target=fpr_target,
        pairs_redundancy=red,
    )
    ablation_df.to_csv(output / "validation_ablation.csv", index=False)
    write_json(output / "validation_ci.json", {"paired": paired, "resolution": resolution})

    from src.audit.contribution import permutation_family_importance

    fam_imp = permutation_family_importance(train, val, seed=seed)
    fam_imp.to_csv(output / "validation_family_importance.csv", index=False)

    rf_p0 = ablation_df[(ablation_df["model"] == "random_forest") & (ablation_df["arm"] == "P0_pe_baseline")]
    if len(rf_p0):
        from src.audit.contribution import _feature_cols_for_arm, _threshold_from_calibration, _train_cal_indices
        from src.train import _make_model
        from src.audit.schema import bn_predictor_columns, pe_predictor_columns
        from src.audit.diagnostics import train_filter_bn_cols, train_drop_redundant_bn

        bn_all = bn_predictor_columns(train)
        bn_f = train_filter_bn_cols(train, bn_all)
        bn_r = train_drop_redundant_bn(train, bn_f, red)
        cols = _feature_cols_for_arm("pe", train, bn_all=bn_all, bn_filtered=bn_f, bn_reduced=bn_r)
        y_train = train["label"].astype(int).values
        y_val = val["label"].astype(int).values
        fit_idx, cal_idx = _train_cal_indices(len(y_train), cal_fraction=0.25, seed=seed)
        pipe = _make_model("random_forest", seed)
        pipe.fit(train[cols].iloc[fit_idx], y_train[fit_idx])
        thr = _threshold_from_calibration(y_train[cal_idx], pipe.predict_proba(train[cols].iloc[cal_idx])[:, 1], fpr_target)[
            "threshold"
        ]
        scores = pipe.predict_proba(val[cols])[:, 1]
        err = val[["sha256", "label", "bn_extraction_status", "file_size"]].copy()
        err["score"] = scores
        err["pred"] = (scores >= thr).astype(int)
        err["error_type"] = "tn"
        err.loc[(err["label"] == 1) & (err["pred"] == 0), "error_type"] = "fn"
        err.loc[(err["label"] == 0) & (err["pred"] == 1), "error_type"] = "fp"
        err.loc[(err["label"] == 1) & (err["pred"] == 1), "error_type"] = "tp"
        err.to_csv(output / "error_analysis_validation.csv", index=False)

    conclusion = "inconclusive"
    rf_pair = paired.get("random_forest", {})
    if rf_pair.get("note") == "insufficient_resolution":
        conclusion = "inconclusive"
    elif "delta_b_minus_a" in rf_pair:
        d = rf_pair["delta_b_minus_a"]
        lo, hi = rf_pair.get("ci_low"), rf_pair.get("ci_high")
        if lo is not None and hi is not None:
            if lo > 0.02:
                conclusion = "incremental_value_supported"
            elif hi < -0.02:
                conclusion = "not_supported"
            elif d < -0.02:
                conclusion = "not_supported"

    ctx = {
        "generated_at": manifest["generated_at"],
        "input_integrity": "pass",
        "leakage_risk": leakage_risk,
        "pe_predictor_count": schema["pe_predictor_count"],
        "bn_predictor_count": schema["bn_predictor_count"],
        "bn_missingness_by_class": bn_missingness_by_class(train, val),
        "high_redundancy_features": sorted(set(red["feature_b"].tolist())) if len(red) else [],
        "ablation_highlights": ablation_df.to_dict(orient="records") if len(ablation_df) else [],
        "candidate_arms": list(ablation_df["arm"].unique()) if len(ablation_df) else [],
        "fpr_target": fpr_target,
        "benign_validation_n": resolution.get("benign_validation_n"),
        "min_attainable_fpr_validation": resolution.get("min_attainable_fpr_validation"),
        "paired_random_forest": rf_pair,
        "conclusion": conclusion,
    }
    write_json(output / "audit_summary.json", build_audit_summary(ctx))
    (output / "audit_report.md").write_text(render_markdown(ctx), encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="SA2 read-only feature audit")
    p.add_argument("--config", default="configs/local.yaml")
    p.add_argument("--output", type=Path, default=Path("artifacts/feature_audit"))
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--strict", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    return run_audit(args.config, args.output, seed=args.seed, strict=args.strict, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
