"""V2 CLI: inspect (Week 1), develop/freeze/blind (gated)."""

from __future__ import annotations

import argparse
import json
import pickle
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from src.train import _cols
from src.v2.baseline import load_v1_comparator_manifest
from src.v2.calibration import brier_score
from src.v2.config import load_v2_config
from src.v2.inputs import build_development_frame, load_v2_inputs, run_input_audit
from src.v2.quality import coverage_by_source_size, quality_feature_table, summarize_coverage_by_class
from src.v2.reports import try_coverage_plots, write_csv, write_json
from src.v2.v1_guard import assert_v2_write_allowed


def _git_commit() -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return None


def _out_dirs(cfg: dict) -> dict[str, Path]:
    root = cfg["_v2_artifacts"]
    return {
        "root": root,
        "development": root / "development",
        "models": root / "models",
        "blind": root / "blind",
        "reports": root / "reports",
    }


def cmd_inspect(config: str) -> int:
    cfg = load_v2_config(config)
    dirs = _out_dirs(cfg)
    v1_art = cfg["_v1_artifacts"]
    data = load_v2_inputs(config)
    audit = run_input_audit(data)
    dev = build_development_frame(data)
    assign = data["assignments"]
    dev = dev.merge(assign[["sha256", "split"]], on="sha256", how="left")

    cov_class = summarize_coverage_by_class(dev, split_col="split")
    by_source, by_size = coverage_by_source_size(dev)
    qtab = quality_feature_table(dev)
    v1_manifest = load_v1_comparator_manifest(v1_art)

    cal_diag = _validation_calibration_diagnostics(data, v1_art, cfg["v2"]["seed"])

    write_json(dirs["development"] / "input_audit.json", audit, v1_art=v1_art)
    write_json(dirs["development"] / "v1_comparator_manifest.json", v1_manifest, v1_art=v1_art)
    write_json(dirs["development"] / "calibration_diagnostics_val.json", cal_diag, v1_art=v1_art)
    write_csv(dirs["development"] / "coverage_by_class.csv", cov_class, v1_art=v1_art)
    write_csv(dirs["development"] / "coverage_by_source.csv", by_source, v1_art=v1_art)
    write_csv(dirs["development"] / "coverage_by_size_band.csv", by_size, v1_art=v1_art)
    write_csv(dirs["development"] / "quality_by_class.csv", qtab, v1_art=v1_art)
    plots = try_coverage_plots(dirs["development"] / "plots", cov_class, by_size, v1_art=v1_art)

    gate_pass = (
        audit["split_integrity"]["pass"]
        and not audit["schema_lock"]["forbidden_in_predictors"]
        and v1_manifest["reproduction"]["pass"]
    )
    week1 = {
        "gate": "week1",
        "pass": gate_pass,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "blockers": [] if gate_pass else ["see split_integrity or v1 reproduction or forbidden predictors"],
        "split_integrity_pass": audit["split_integrity"]["pass"],
        "v1_baseline_reproduced": v1_manifest["reproduction"]["pass"],
        "predictor_forbidden_count": len(audit["schema_lock"]["forbidden_in_predictors"]),
        "input_hashes": audit["input_hashes"],
        "plots": plots,
        "next_permitted_action": "week2_develop" if gate_pass else "fix_integrity_then_reinspect",
        "claims": {
            "sota_claim_supported": False,
            "v2_improvement_confirmed": False,
            "mode": cfg["v2"].get("mode", "developmental"),
        },
    }
    write_json(dirs["development"] / "week1_gate.json", week1, v1_art=v1_art)

    manifest = {
        "generated_at": week1["generated_at"],
        "seed": cfg["v2"]["seed"],
        "config": config,
        "python": sys.version,
        "platform": platform.platform(),
        "git_commit": _git_commit(),
        "v2_version": __import__("src.v2", fromlist=["__version__"]).__version__,
    }
    write_json(dirs["root"] / "run_manifest.json", manifest, v1_art=v1_art)

    print(json_dumps({"week1_gate_pass": gate_pass, "artifacts": str(dirs["development"])}))
    return 0 if gate_pass else 1


def _validation_calibration_diagnostics(data: dict, v1_art: Path, seed: int) -> dict:
    """Descriptive Brier on validation only using frozen V1 PE models (no test access)."""
    val = data["val"]
    y = val["label"].map({"benign": 0, "malicious": 1}).to_numpy()
    if y.dtype == object:
        y = val["label"].astype(int).to_numpy()
    out = {"note": "validation_only_descriptive", "models": {}}
    for algo in ("random_forest", "lightgbm", "logistic_regression"):
        pkl = v1_art / "models" / f"{algo}__pe_v2.pkl"
        if not pkl.is_file():
            continue
        with pkl.open("rb") as f:
            bundle = pickle.load(f)
        if isinstance(bundle, dict) and "pipeline" in bundle:
            pipe = bundle["pipeline"]
            pe_cols = bundle.get("features") or _cols(("pe_",), val)
        else:
            pipe = bundle
            pe_cols = _cols(("pe_",), val)
        X = val[pe_cols]
        prob = pipe.predict_proba(X)[:, 1]
        out["models"][algo] = {"brier_val": brier_score(y, prob), "n_val": int(len(y))}
    return out


def json_dumps(obj) -> str:
    return json.dumps(obj, indent=2)


def cmd_develop(config: str) -> int:
    cfg = load_v2_config(config)
    v1_art = cfg["_v1_artifacts"]
    dirs = _out_dirs(cfg)
    gate = dirs["development"] / "week1_gate.json"
    if not gate.is_file() or not json.loads(gate.read_text(encoding="utf-8")).get("pass"):
        print("Week 1 gate not passed. Run: python -m src.v2.cli inspect")
        return 1

    from src.v2.experiments import run_development

    data = load_v2_inputs(config)
    dev = build_development_frame(data)
    assign = data["assignments"]
    dev = dev.merge(assign[["sha256", "split"]], on="sha256", how="left")
    train_df = dev[dev["split"] == "train"].reset_index(drop=True)
    val_df = dev[dev["split"] == "val"].reset_index(drop=True)

    dev_cfg = cfg["development"]
    out = run_development(
        train_df,
        val_df,
        seed=int(cfg["v2"]["seed"]),
        n_folds=int(dev_cfg["inner_group_folds"]),
        cal_fraction=float(dev_cfg["threshold_calibration_fraction"]),
        budget=int(dev_cfg["selection_budget"]),
        fpr_target=float(cfg["v2"]["primary_fpr"]),
    )

    # Persist models (V2 directory only)
    import pickle

    model_dir = assert_v2_write_allowed(dirs["models"], v1_art)
    model_dir.mkdir(parents=True, exist_ok=True)
    for name, m in out["models"].items():
        with (model_dir / f"{name}_calibrated.pkl").open("wb") as f:
            pickle.dump(
                {
                    "models": m,
                    "fusion_quantile": out["fusion_selection"]["selected_quantile"],
                    "fusion_weight": out["fusion_selection"]["selected_weight"],
                    "review_band": out["validation_random_forest"]["selected_review_band"],
                },
                f,
            )

    serializable = {k: v for k, v in out.items() if k != "models"}
    write_json(dirs["development"] / "development_results.json", serializable, v1_art=v1_art)
    write_csv(
        dirs["development"] / "validation_arms_summary.csv",
        _arms_summary_table(serializable),
        v1_art=v1_art,
    )

    summ = serializable["development_summary"]
    week2 = {
        "gate": "week2",
        "pass": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "fusion_selected": out["fusion_selection"],
        "development_summary": summ,
        "gate2_policy_checks": {
            "inference_uses_only_permitted_coverage": True,
            "review_not_counted_as_correct": True,
            "no_test_labels_used": True,
        },
        "next_permitted_action": "blind_cohort_or_report_limitations",
        "claims": {
            "detection_improvement_on_val": summ["detection_improvement_on_val"],
            "triage_improvement_on_val": summ["triage_improvement_on_val"],
            "v2_improvement_confirmed": False,
            "sota_claim_supported": False,
        },
    }
    write_json(dirs["development"] / "week2_gate.json", week2, v1_art=v1_art)
    print(json_dumps({"week2_complete": True, "development_summary": summ}))
    return 0


def _arms_summary_table(serializable: dict) -> pd.DataFrame:
    rows = []
    for algo_key in ("validation_random_forest", "validation_lightgbm"):
        block = serializable.get(algo_key, {})
        for arm in ("B0_pe", "B1_pe_bn", "V2A_fusion"):
            if arm not in block:
                continue
            r = block[arm]
            rows.append(
                {
                    "evaluator": algo_key.replace("validation_", ""),
                    "arm": arm,
                    "tpr_fixed": r.get("tpr_fixed"),
                    "fpr_fixed": r.get("fpr_fixed"),
                    "threshold": r.get("threshold"),
                    "oracle_tpr_at_fpr_target": r.get("oracle_tpr_at_fpr_target"),
                    "roc_auc": r.get("roc_auc"),
                    "pr_auc": r.get("pr_auc"),
                    "brier": r.get("brier"),
                }
            )
        if "V2B_review" in block:
            rb = block["V2B_review"]
            rows.append(
                {
                    "evaluator": algo_key.replace("validation_", ""),
                    "arm": "V2B_review",
                    "tpr_fixed": rb.get("auto_malware_recall"),
                    "fpr_fixed": rb.get("auto_benign_fpr"),
                    "selective_error_rate": rb.get("selective_error_rate"),
                    "review_rate": rb.get("review_rate"),
                }
            )
    return pd.DataFrame(rows)


def cmd_freeze(config: str) -> int:
    cfg = load_v2_config(config)
    v1_art = cfg["_v1_artifacts"]
    dirs = _out_dirs(cfg)
    w2 = dirs["development"] / "week2_gate.json"
    dr = dirs["development"] / "development_results.json"
    if not w2.is_file() or not dr.is_file():
        print("Run develop before freeze.")
        return 1
    week2 = json.loads(w2.read_text(encoding="utf-8"))
    if not week2.get("pass"):
        print("Week 2 gate failed.")
        return 1
    dev_res = json.loads(dr.read_text(encoding="utf-8"))
    model_paths = {
        "random_forest": dirs["models"] / "random_forest_calibrated.pkl",
        "lightgbm": dirs["models"] / "lightgbm_calibrated.pkl",
    }
    missing = [k for k, p in model_paths.items() if not p.is_file()]
    if missing:
        print(f"Missing V2 models: {missing}")
        return 1
    from src.v2.freeze import build_frozen_protocol

    prereg = Path(cfg["_root"]) / "docs" / "v2_preregistration.md"
    protocol = build_frozen_protocol(
        v2_cfg=cfg,
        week2_gate=week2,
        development_results=dev_res,
        model_paths=model_paths,
        prereg_path=prereg,
    )
    out = dirs["blind"] / "protocol_frozen.json"
    write_json(out, protocol, v1_art=v1_art)
    print(json_dumps({"frozen_protocol": str(out)}))
    return 0


def cmd_evaluate_blind(config: str) -> int:
    cfg = load_v2_config(config)
    v1_art = cfg["_v1_artifacts"]
    dirs = _out_dirs(cfg)
    blind_cfg = cfg.get("blind", {})
    protocol_path = dirs["blind"] / "protocol_frozen.json"
    lock_path = dirs["blind"] / "evaluation_run.lock"

    if not blind_cfg.get("enabled"):
        print("blind.enabled=false")
        return 1
    if blind_cfg.get("require_frozen_protocol", True) and not protocol_path.is_file():
        print("Missing protocol_frozen.json — run: python -m src.v2.cli freeze")
        return 1
    if blind_cfg.get("write_once", True):
        from src.v2.blind import assert_run_once

        try:
            assert_run_once(lock_path)
        except RuntimeError as e:
            print(str(e))
            return 1

    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    replay = blind_cfg.get("historical_test_replay", {})
    confirmatory = False
    eval_label = "independent_blind"
    manifest_path = Path(cfg["_root"]) / blind_cfg.get("manifest", "artifacts/v2/blind/manifest.json")

    if replay.get("enabled") and not manifest_path.is_file():
        manifest_path = Path(cfg["_root"]) / replay["manifest_sha_file"]
        eval_label = replay.get("label", "historical_replay")
        confirmatory = bool(replay.get("confirmatory", False))
    elif not manifest_path.is_file():
        print("No blind manifest and historical_test_replay not configured.")
        return 1

    from src.v2.blind import (
        build_eval_frame,
        load_manifest,
        manifest_sha_set,
        validate_manifest_disjoint,
        write_run_lock,
    )
    from src.v2.evaluate import load_model_bundle, resolution_note, run_frozen_scoring

    data = load_v2_inputs(config)
    assign = data["assignments"]
    train_sha = set(assign[assign["split"] == "train"]["sha256"])
    val_sha = set(assign[assign["split"] == "val"]["sha256"])
    test_sha = set(assign[assign["split"] == "test"]["sha256"])
    manifest = load_manifest(manifest_path)
    m_sha = manifest_sha_set(manifest)
    allow_test = replay.get("enabled") and manifest_path.name.startswith("frozen_test")
    disjoint = validate_manifest_disjoint(
        m_sha,
        train_sha=train_sha,
        val_sha=val_sha,
        test_sha=test_sha,
        challenge_sha=data["challenge_sha"],
        allow_test_overlap=allow_test,
    )
    if not disjoint["pass"]:
        write_json(dirs["blind"] / "manifest_validation.json", disjoint, v1_art=v1_art)
        print("Manifest failed disjoint check:", disjoint["issues"])
        return 1

    train_df = build_development_frame(data)
    train_df = train_df.merge(assign[["sha256", "split"]], on="sha256")
    train_df = train_df[train_df["split"] == "train"].drop(columns=["split"])
    eval_df = build_eval_frame(m_sha, data["pe"], data["bn"], data["inventory"])
    missing_feat = m_sha - set(eval_df["sha256"])
    bundle = load_model_bundle(dirs["models"] / "random_forest_calibrated.pkl")
    seed = int(cfg["v2"]["seed"])
    fpr = float(cfg["v2"]["primary_fpr"])
    results = run_frozen_scoring(train_df, eval_df, model_bundle=bundle, protocol=protocol, fpr_target=fpr, seed=seed)
    results.pop("_scores", None)

    paired = results.get("paired_group_bootstrap", {})
    summary = {
        "evaluation_type": eval_label,
        "confirmatory": confirmatory,
        "v2_improvement_confirmed": False,
        "sota_claim_supported": False,
        "manifest_path": str(manifest_path),
        "n_requested": len(m_sha),
        "n_scored": len(eval_df),
        "n_missing_features": len(missing_feat),
        "resolution": resolution_note(eval_df),
        "arms": {k: results[k] for k in ("B0_pe", "B1_pe_bn", "V2A_fusion", "V2B_review") if k in results},
        "paired_group_bootstrap": paired,
        "V2A_bn_fusion_rate": results.get("V2A_bn_fusion_rate"),
    }
    b0 = results["B0_pe"]["tpr_fixed"]
    v2a = results["V2A_fusion"]["tpr_fixed"]
    summary["detection_delta_v2a_minus_b0"] = float(v2a - b0)
    summary["headline_metric"] = "tpr_fixed at frozen train-calibrated threshold"
    if confirmatory and v2a > b0 + 0.02 and results["V2A_fusion"]["fpr_fixed"] <= results["B0_pe"]["fpr_fixed"]:
        summary["note"] = "Confirmatory criterion met on independent cohort — review CI before claiming."
    else:
        summary["note"] = "Non-confirmatory or insufficient delta; do not claim V2 detection win."

    write_json(dirs["blind"] / "paired_results.json", summary, v1_art=v1_art)
    write_json(dirs["blind"] / "manifest_validation.json", disjoint, v1_art=v1_art)
    week3 = {
        "gate": "week3",
        "pass": True,
        "confirmatory_blind": confirmatory,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evaluation_label": eval_label,
        "detection_delta_v2a_minus_b0": summary["detection_delta_v2a_minus_b0"],
        "claims": {
            "v2_improvement_confirmed": False,
            "sota_claim_supported": False,
        },
    }
    write_json(dirs["blind"] / "week3_gate.json", week3, v1_art=v1_art)
    from src.v2.latency import duration_summary

    write_json(
        dirs["blind"] / "latency_bn_existing_features.json",
        duration_summary(data["bn"], m_sha),
        v1_art=v1_art,
    )
    write_run_lock(
        lock_path,
        {"ran_at": week3["generated_at"], "evaluation_type": eval_label, "n_scored": len(eval_df)},
    )
    print(json_dumps({"evaluate_complete": True, "summary": summary}))
    return 0


def cmd_report(config: str) -> int:
    cfg = load_v2_config(config)
    dev = cfg["_v2_artifacts"] / "development"
    if not (dev / "week1_gate.json").is_file():
        print("Run inspect first.")
        return 1
    w2 = dev / "week2_gate.json"
    dr = dev / "development_results.json"
    md = ["# SA2 V2 Development Report", ""]
    blind = cfg["_v2_artifacts"] / "blind" / "paired_results.json"
    if blind.is_file():
        br = json.loads(blind.read_text(encoding="utf-8"))
        md.extend(
            [
                "## Frozen evaluation (see confirmatory flag)",
                "",
                f"- Type: `{br.get('evaluation_type')}` | confirmatory: **{br.get('confirmatory')}**",
                *[
                    f"- {arm}: TPR {br['arms'][arm].get('tpr_fixed', float('nan')):.3f} at FPR "
                    f"{br['arms'][arm].get('fpr_fixed', float('nan')):.3f} (frozen threshold)"
                    for arm in ("B0_pe", "B1_pe_bn", "V2A_fusion")
                    if arm in br.get("arms", {})
                ],
                "",
            ]
        )
    if w2.is_file() and dr.is_file():
        summ = json.loads(dr.read_text(encoding="utf-8"))["development_summary"]
        md.extend(
            [
                "## Validation results (non-blind; not for confirmatory claims)",
                "",
                "| Arm | TPR (fixed threshold) | FPR (fixed threshold) | Oracle TPR (secondary) |",
                "|-----|------|------|------|",
                f"| B0 PE-only | {summ['B0_tpr_fixed']:.3f} | {summ['B0_fpr_fixed']:.3f} | {summ['B0_oracle_tpr']:.3f} |",
                f"| B1 naive PE+BN | {summ['B1_tpr_fixed']:.3f} | {summ['B1_fpr_fixed']:.3f} | {summ['B1_oracle_tpr']:.3f} |",
                f"| V2-A coverage fusion | {summ['V2A_tpr_fixed']:.3f} | {summ['V2A_fpr_fixed']:.3f} | {summ['V2A_oracle_tpr']:.3f} |",
                "",
                "## Triage (V2-B)",
                "",
                f"- Selective error **{summ['V2B_selective_error_rate']:.3f}** vs B0 full-auto **{summ['B0_full_auto_error_rate']:.3f}** "
                f"(automation {summ['V2B_automation_coverage']:.1%}, band {summ['selected_review_band']}).",
                "",
                f"Detection improvement on val: **{summ['detection_improvement_on_val']}** | Triage improvement: **{summ['triage_improvement_on_val']}**",
                "",
                "**No SOTA or confirmed V2 detection win.** Blind cohort required for H1.",
            ]
        )
    else:
        summary = json.loads((dev / "week1_gate.json").read_text(encoding="utf-8"))
        md.append(f"Week 1 gate pass: **{summary.get('pass')}**. Run `develop` for Week 2.")
    out = cfg["_v2_artifacts"] / "reports" / "development_report.md"
    p = assert_v2_write_allowed(out, cfg["_v1_artifacts"])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(md), encoding="utf-8")
    print(f"Wrote {p}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="src.v2.cli")
    sub = p.add_subparsers(dest="command", required=True)
    for name, fn in (
        ("inspect", cmd_inspect),
        ("develop", cmd_develop),
        ("freeze", cmd_freeze),
        ("evaluate-blind", cmd_evaluate_blind),
        ("report", cmd_report),
    ):
        sp = sub.add_parser(name)
        sp.add_argument("--config", default="configs/v2_experiment.yaml")
        sp.set_defaults(_fn=fn)
    args = p.parse_args(argv)
    return args._fn(args.config)


if __name__ == "__main__":
    raise SystemExit(main())
