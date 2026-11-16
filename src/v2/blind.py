"""Blind manifest validation and one-shot evaluation guards."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd


def load_manifest(path: Path) -> dict[str, Any]:
    if path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    # Plain SHA list
    sha = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    return {"sha256": sha, "format": "sha_list"}


def manifest_sha_set(manifest: dict[str, Any]) -> set[str]:
    if "sha256" in manifest:
        return set(manifest["sha256"])
    if "samples" in manifest:
        return {s["sha256"] for s in manifest["samples"]}
    raise ValueError("manifest missing sha256 or samples")


def validate_manifest_disjoint(
    manifest_sha: set[str],
    *,
    train_sha: set[str],
    val_sha: set[str],
    test_sha: set[str],
    challenge_sha: set[str],
    allow_test_overlap: bool = False,
) -> dict[str, Any]:
    issues = []
    overlap_train = manifest_sha & train_sha
    overlap_val = manifest_sha & val_sha
    overlap_test = manifest_sha & test_sha
    overlap_ch = manifest_sha & challenge_sha
    if overlap_train:
        issues.append(f"overlap_train:{len(overlap_train)}")
    if overlap_val:
        issues.append(f"overlap_val:{len(overlap_val)}")
    if overlap_test and not allow_test_overlap:
        issues.append(f"overlap_test:{len(overlap_test)}")
    if overlap_ch:
        issues.append(f"overlap_challenge:{len(overlap_ch)}")
    return {
        "pass": len(issues) == 0,
        "issues": issues,
        "n_manifest": len(manifest_sha),
        "allow_test_overlap": allow_test_overlap,
    }


def assert_run_once(lock_path: Path) -> None:
    if lock_path.is_file():
        raise RuntimeError(f"Blind evaluation already executed (lock: {lock_path}). Delete lock only for dev reset.")


def write_run_lock(lock_path: Path, payload: dict[str, Any]) -> None:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def build_eval_frame(
    sha_set: set[str],
    pe: pd.DataFrame,
    bn: pd.DataFrame,
    inventory: pd.DataFrame,
) -> pd.DataFrame:
    inv = inventory[
        ["sha256", "label", "group_id", "file_size", "source", "software_source", "machine"]
    ].copy()
    pe_x = pe.drop(columns=["label"], errors="ignore")
    bn_x = bn.drop(columns=["label", "analysis_status"], errors="ignore")
    feat = pe_x.merge(bn_x, on="sha256", how="inner")
    feat = feat.merge(inv, on="sha256", how="inner")
    status = bn[["sha256", "analysis_status"]].rename(columns={"analysis_status": "bn_record_status"})
    feat = feat.merge(status, on="sha256", how="left")
    if feat["label"].dtype == object:
        feat["label"] = feat["label"].map({"benign": 0, "malicious": 1})
    feat = feat[feat["sha256"].isin(sha_set)].sort_values("sha256").reset_index(drop=True)
    return feat
