"""Read-only V2 inputs: frozen joins, integrity, predictor schema lock."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pandas as pd

from src.audit.inputs import _file_sha256, _load_challenge_sha, verify_split_integrity
from src.audit.schema import bn_predictor_columns, pe_predictor_columns, validate_predictor_list
from src.v2.config import load_v2_config


def v2_input_paths(v1_art: Path, feature_audit: Path) -> dict[str, Path]:
    return {
        "inventory": v1_art / "manifests" / "corpus_inventory.parquet",
        "split_assignments": v1_art / "manifests" / "split_assignments.parquet",
        "cohort_frozen": v1_art / "manifests" / "cohort_frozen.json",
        "pe_features": v1_art / "features" / "pe_features.parquet",
        "bn_features": v1_art / "features" / "bn_features_v2.parquet",
        "bn_coverage": v1_art / "evaluations" / "bn_coverage_v2.json",
        "v1_test_results": v1_art / "evaluations" / "test_results_v2.csv",
        "v1_paired_eval": v1_art / "evaluations" / "paired_pe_vs_pebn_v2.json",
        "audit_summary": feature_audit / "audit_summary.json",
        "audit_schema": feature_audit / "schema_report.json",
    }


def load_v2_inputs(cfg_path: str) -> dict[str, Any]:
    cfg = load_v2_config(cfg_path)
    v1_art = cfg["_v1_artifacts"]
    paths = v2_input_paths(v1_art, cfg["_feature_audit"])
    missing = [k for k, p in paths.items() if not p.is_file()]
    if missing:
        raise FileNotFoundError(f"Missing V2 inputs: {missing}")

    inv = pd.read_parquet(paths["inventory"])
    assign = pd.read_parquet(paths["split_assignments"])
    pe = pd.read_parquet(paths["pe_features"])
    bn = pd.read_parquet(paths["bn_features"])

    provenance = {k: {"path": str(p), "bytes": p.stat().st_size, "sha256": _file_sha256(p)} for k, p in paths.items()}

    data = {
        "v2_cfg": cfg,
        "v1_art": v1_art,
        "paths": paths,
        "provenance": provenance,
        "inventory": inv,
        "assignments": assign,
        "pe": pe,
        "bn": bn,
        "challenge_sha": _load_challenge_sha(v1_art),
        "train": pd.read_parquet(v1_art / "splits" / "train.parquet"),
        "val": pd.read_parquet(v1_art / "splits" / "val.parquet"),
    }
    return data


def verify_frozen_sha_files(data: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    assign = data["assignments"]
    art = data["v1_art"]
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


def build_development_frame(data: dict[str, Any]) -> pd.DataFrame:
    """Train+val feature table for V2 development (never loads test labels for selection modules)."""
    inv = data["inventory"][
        ["sha256", "label", "group_id", "file_size", "source", "software_source", "machine"]
    ].copy()
    pe = data["pe"].drop(columns=["label"], errors="ignore")
    bn = data["bn"].drop(columns=["label"], errors="ignore")
    status = data["bn"][["sha256", "analysis_status"]].rename(columns={"analysis_status": "bn_record_status"})
    feat = pe.merge(bn, on="sha256", how="outer")
    feat = feat.merge(inv, on="sha256", how="left")
    feat = feat.merge(status, on="sha256", how="left")
    if feat["label"].dtype == object:
        feat["label"] = feat["label"].map({"benign": 0, "malicious": 1})
    assign = data["assignments"]
    dev_sha = set(assign[assign["split"].isin(("train", "val"))]["sha256"])
    return feat[feat["sha256"].isin(dev_sha)].sort_values("sha256").reset_index(drop=True)


def predictor_schema_lock(frame: pd.DataFrame, *, strict: bool = True) -> dict[str, Any]:
    pe = pe_predictor_columns(frame)
    bn = bn_predictor_columns(frame)
    forbidden = validate_predictor_list(pe + bn, strict=strict)
    return {
        "pe_predictor_count": len(pe),
        "bn_predictor_count": len(bn),
        "forbidden_in_predictors": forbidden,
        "pe_columns": pe,
        "bn_columns": bn,
    }


def run_input_audit(data: dict[str, Any]) -> dict[str, Any]:
    split = verify_split_integrity(data)
    split["issues"].extend(verify_frozen_sha_files(data))
    split["pass"] = split["pass"] and not any("mismatch" in i or "missing_frozen" in i for i in split["issues"])
    dev = build_development_frame(data)
    schema = predictor_schema_lock(dev, strict=False)
    assign = data["assignments"]
    counts = assign[assign["split"].isin(("train", "val", "test"))].groupby("split").size().to_dict()
    class_counts = (
        data["inventory"]
        .merge(assign[["sha256", "split"]], on="sha256")
        .groupby(["split", "label"])
        .size()
        .to_dict()
    )
    return {
        "split_integrity": split,
        "schema_lock": {k: schema[k] for k in ("pe_predictor_count", "bn_predictor_count", "forbidden_in_predictors")},
        "split_counts": counts,
        "class_counts_by_split": {f"{a}|{b}": int(v) for (a, b), v in class_counts.items()},
        "development_rows": int(len(dev)),
        "feature_eligible_pe_rows": int(len(data["pe"])),
        "feature_eligible_bn_rows": int(len(data["bn"])),
        "inventory_rows": int(len(data["inventory"])),
        "input_hashes": data["provenance"],
    }
