"""V1 baseline reproduction from saved artifacts (read-only, descriptive)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd


V1_REFERENCE = {
    "random_forest__pe_v2": {"test_tpr_at_1pct_fpr": 0.9259259259259259},
    "random_forest__pe_bn_v2": {"test_tpr_at_1pct_fpr": 0.8835978835978836},
    "paired_rf_delta_pebn_minus_pe": {"delta_b_minus_a": -0.042328042328042326},
}


def load_v1_comparator_manifest(v1_art: Path) -> dict[str, Any]:
    test_csv = v1_art / "evaluations" / "test_results_v2.csv"
    paired_json = v1_art / "evaluations" / "paired_pe_vs_pebn_v2.json"
    summary_json = v1_art / "evaluations" / "controlled_experiment_summary.json"
    out: dict[str, Any] = {
        "sources": {
            "test_results_v2": str(test_csv),
            "paired_pe_vs_pebn_v2": str(paired_json),
            "controlled_experiment_summary": str(summary_json) if summary_json.is_file() else None,
        },
        "historical_context_only": True,
        "not_used_for_v2_selection": True,
        "rows": [],
        "paired_rf": {},
        "reproduction": {"pass": False, "checks": []},
    }
    if not test_csv.is_file():
        out["reproduction"]["checks"].append("missing_test_results_v2")
        return out

    df = pd.read_csv(test_csv)
    out["rows"] = df.to_dict(orient="records")

    tol_tpr = 1e-9
    tol_delta = 1e-6
    checks = []
    for run_id, ref in V1_REFERENCE.items():
        if run_id == "paired_rf_delta_pebn_minus_pe":
            continue
        row = df[df["run_id"] == run_id]
        if row.empty:
            checks.append({"run_id": run_id, "pass": False, "reason": "missing_row"})
            continue
        got = float(row.iloc[0]["test_tpr_at_1pct_fpr"])
        exp = ref["test_tpr_at_1pct_fpr"]
        ok = abs(got - exp) <= tol_tpr
        checks.append({"run_id": run_id, "pass": ok, "expected": exp, "got": got})

    if paired_json.is_file():
        paired = json.loads(paired_json.read_text(encoding="utf-8"))
        out["paired_rf"] = paired
        delta = paired.get("paired_delta_b_minus_a", {}).get("delta_b_minus_a")
        if delta is not None:
            exp_d = V1_REFERENCE["paired_rf_delta_pebn_minus_pe"]["delta_b_minus_a"]
            ok_d = abs(float(delta) - exp_d) <= tol_delta
            checks.append(
                {
                    "run_id": "paired_rf_delta_pebn_minus_pe",
                    "pass": ok_d,
                    "expected": exp_d,
                    "got": float(delta),
                }
            )

    out["reproduction"]["checks"] = checks
    out["reproduction"]["pass"] = bool(checks) and all(c.get("pass") for c in checks)
    out["interpretation"] = (
        "V1 frozen-test metrics reproduced from saved CSV/JSON for documentation only. "
        "V2 must not tune on this partition."
    )
    return out
