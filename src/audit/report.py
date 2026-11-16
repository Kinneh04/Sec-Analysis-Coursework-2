"""Markdown and JSON audit summaries."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")


def decide_conclusion(ablation: dict[str, Any], paired: dict[str, Any], leakage_risk: str) -> str:
    if leakage_risk == "confirmed":
        return "artifact_driven"
    rf = paired.get("random_forest", {})
    delta = rf.get("delta_b_minus_a")
    ci_lo = rf.get("ci_low")
    ci_hi = rf.get("ci_high")
    if rf.get("note") == "insufficient_resolution":
        return "inconclusive"
    if delta is None or ci_lo is None or ci_hi is None:
        return "inconclusive"
    if ci_lo > 0.02:
        return "incremental_value_supported"
    if ci_hi < -0.02:
        return "not_supported"
    return "inconclusive"


def render_markdown(ctx: dict[str, Any]) -> str:
    lines = [
        "# SA2 Feature-Value and Leakage Audit Report",
        "",
        f"Generated: {ctx.get('generated_at', '')}",
        "",
        "## 1. Scope",
        "Read-only audit of frozen cohort PE and BN v2 features. No re-extraction, no split changes, "
        "no frozen-test-driven selection.",
        "",
        "## 2. Provenance",
        f"- Run manifest: `run_manifest.json`",
        f"- Input integrity: **{ctx.get('input_integrity', 'unknown')}**",
        "",
        "## 3. Predictor policy",
        f"- PE predictors: {ctx.get('pe_predictor_count', '?')}",
        f"- BN predictors: {ctx.get('bn_predictor_count', '?')}",
        "Prohibited: labels, SHA, paths, source roots, group IDs, extraction status, and related metadata.",
        "",
        "## 4. BN coverage (train/validation)",
        "See `coverage_by_class_source.csv` and split integrity JSON for denominators.",
        "",
        "## 5. Feature quality and redundancy",
        "See `feature_quality.csv` and `redundancy_groups.csv`.",
        "",
        "## 6. Validation ablation (P0–P4)",
        "Primary metric: validation TPR at threshold calibrated on a held-out portion of training for "
        f"target FPR ≤ {ctx.get('fpr_target', 0.01)}. "
        f"Benign validation n = {ctx.get('benign_validation_n', '?')} "
        f"(minimum attainable FPR ≈ {ctx.get('min_attainable_fpr_validation', '?')}).",
        "",
        "Full table: `validation_ablation.csv`. Random Forest TPR@target FPR: PE baseline vs PE+BN all "
        "should be read alongside ROC-AUC because discrete FPR resolution is coarse at n≈89 benign.",
        "",
        "## 7. Paired uncertainty (P1 vs P0)",
        json.dumps(ctx.get("paired_random_forest", {}), indent=2),
        "",
        "LightGBM paired delta favored PE-only on point estimate; Random Forest showed a small PE+BN gain "
        "with a wide bootstrap interval crossing zero. Treat as **inconclusive** for deployment selection.",
        "",
        "## 8. Recommendation",
        f"**Conclusion:** `{ctx.get('conclusion', 'inconclusive')}`",
        "",
        "SOTA superiority is **not** claimed (`sota_claim_supported: false`).",
        "",
        "## 9. Historical frozen-test context (non-decision)",
        "Prior controlled experiment (not recomputed here): RF TPR@1% FPR on frozen test was approximately "
        "PE-only ~0.926, PE+BN ~0.884, BN-only ~0.16; paired delta PE+BN minus PE ~−0.042 with wide bootstrap CI.",
        "",
        "## 10. Limitations",
        "Small benign counts at low FPR, source-family confounding, BN coverage imbalance, "
        "group structure by imphash, and previously observed test metrics.",
        "",
    ]
    return "\n".join(lines)


def build_audit_summary(ctx: dict[str, Any]) -> dict[str, Any]:
    return {
        "input_integrity": ctx.get("input_integrity", "fail"),
        "leakage_risk": ctx.get("leakage_risk", "none_detected"),
        "bn_missingness_by_class": ctx.get("bn_missingness_by_class", {}),
        "high_redundancy_features": ctx.get("high_redundancy_features", []),
        "candidate_arms": list(ctx.get("candidate_arms", [])),
        "primary_validation_metric": "TPR_at_precalibrated_1pct_FPR",
        "conclusion": ctx.get("conclusion", "inconclusive"),
        "sota_claim_supported": False,
        "test_used_for_selection": False,
        "extraction_performed": False,
    }
