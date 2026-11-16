"""Freeze V2 protocol before any blind (or replay) scoring."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_commit() -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return None


def build_frozen_protocol(
    *,
    v2_cfg: dict,
    week2_gate: dict,
    development_results: dict,
    model_paths: dict[str, Path],
    prereg_path: Path,
) -> dict[str, Any]:
    fusion = week2_gate.get("fusion_selected") or development_results.get("fusion_selection", {})
    val_rf = development_results.get("validation_random_forest", {})
    return {
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "v2_seed": v2_cfg["v2"]["seed"],
        "git_commit": _git_commit(),
        "preregistration_sha256": _sha256_file(prereg_path) if prereg_path.is_file() else None,
        "primary_fpr": float(v2_cfg["v2"]["primary_fpr"]),
        "policy": {
            "fusion_eligibility_quantile": fusion.get("selected_quantile"),
            "fusion_weight": fusion.get("selected_weight"),
            "review_band_half_width": val_rf.get("selected_review_band"),
            "primary_model": "random_forest",
            "threshold_rule": "train_calibration_subset_pe_scores",
            "calibration_fraction": float(v2_cfg["development"]["threshold_calibration_fraction"]),
        },
        "models": {name: {"path": str(p), "sha256": _sha256_file(p)} for name, p in model_paths.items()},
        "development_summary_snapshot": development_results.get("development_summary", {}),
        "claims_locked": {
            "sota_claim_supported": False,
            "confirmatory_requires_independent_cohort": True,
        },
    }
