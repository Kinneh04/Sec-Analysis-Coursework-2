"""Load frozen artifacts and verify split / label integrity (read-only)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pandas as pd

from src.common.config import artifacts, load_config


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_challenge_sha(art: Path) -> set[str]:
    out: set[str] = set()
    for name in ("challenge_qualitative_sha256.txt", "challenge_quantitative_sha256.txt", "challenge_sha256.txt"):
        p = art / "manifests" / name
        if not p.is_file():
            continue
        for ln in p.read_text(encoding="utf-8").splitlines():
            s = ln.strip()
            if s and not s.startswith("#"):
                out.add(s)
    return out


def load_audit_inputs(cfg_path: str) -> dict[str, Any]:
    cfg = load_config(cfg_path)
    art = artifacts(cfg)
    paths = {
        "inventory": art / "manifests" / "corpus_inventory.parquet",
        "split_assignments": art / "manifests" / "split_assignments.parquet",
        "pe_features": art / "features" / "pe_features.parquet",
        "bn_features": art / "features" / "bn_features_v2.parquet",
        "train_split": art / "splits" / "train.parquet",
        "val_split": art / "splits" / "val.parquet",
        "test_split": art / "splits" / "test.parquet",
    }
    missing = [k for k, p in paths.items() if not p.is_file()]
    if missing:
        raise FileNotFoundError(f"Missing audit inputs: {missing}")

    inv = pd.read_parquet(paths["inventory"])
    assign = pd.read_parquet(paths["split_assignments"])
    pe = pd.read_parquet(paths["pe_features"])
    bn = pd.read_parquet(paths["bn_features"])
    train = pd.read_parquet(paths["train_split"])
    val = pd.read_parquet(paths["val_split"])

    provenance = {}
    for key, p in paths.items():
        provenance[key] = {"path": str(p), "bytes": p.stat().st_size, "sha256": _file_sha256(p)}

    return {
        "cfg": cfg,
        "art": art,
        "paths": paths,
        "provenance": provenance,
        "inventory": inv,
        "assignments": assign,
        "pe": pe,
        "bn": bn,
        "train": train,
        "val": val,
        "challenge_sha": _load_challenge_sha(art),
    }


def verify_split_integrity(data: dict[str, Any]) -> dict[str, Any]:
    inv = data["inventory"]
    assign = data["assignments"]
    challenge = data["challenge_sha"]
    issues: list[str] = []

    if inv["sha256"].duplicated().any():
        issues.append("duplicate_sha256_in_inventory")
    if assign["sha256"].duplicated().any():
        issues.append("duplicate_sha256_in_split_assignments")
    if data["pe"]["sha256"].duplicated().any():
        issues.append("duplicate_sha256_in_pe_features")
    if data["bn"]["sha256"].duplicated().any():
        issues.append("duplicate_sha256_in_bn_features")

    model_splits = assign[assign["split"].isin(("train", "val", "test"))]
    overlap = model_splits.groupby("sha256")["split"].nunique()
    if (overlap > 1).any():
        issues.append("sha256_in_multiple_splits")

    if challenge:
        bad = assign[(assign["sha256"].isin(challenge)) & (assign["split"].isin(("train", "val", "test")))]
        if len(bad):
            issues.append("challenge_sha_in_train_val_test")

    for gid, g in model_splits.groupby("group_id"):
        splits = set(g["split"].unique())
        if len(splits) > 1:
            issues.append(f"group_leak:{gid[:24]}")
            if len(issues) > 50:
                break

    inv_labels = inv.set_index("sha256")["label"]
    for name, frame in (("train", data["train"]), ("val", data["val"])):
        merged = frame.merge(inv_labels.rename("inv_label"), left_on="sha256", right_index=True, how="left")
        mismatch = merged[merged["label"] != merged["inv_label"]]
        if len(mismatch):
            issues.append(f"label_mismatch_{name}:{len(mismatch)}")

    counts = model_splits.groupby("split").size().to_dict()
    pass_gate = len(issues) == 0
    return {
        "pass": pass_gate,
        "issues": issues[:100],
        "split_counts": counts,
        "challenge_excluded_count": len(challenge),
        "inventory_total": int(len(inv)),
        "pe_feature_rows": int(len(data["pe"])),
        "bn_feature_rows": int(len(data["bn"])),
    }


def build_model_tables(data: dict[str, Any]) -> dict[str, pd.DataFrame]:
    """Train/val modeling frames (test labels not loaded for modeling modules)."""
    meta = data["inventory"][
        ["sha256", "label", "file_size", "source", "software_source", "machine", "group_id"]
    ].copy()
    bn_status = data["bn"][["sha256", "analysis_status"]].rename(columns={"analysis_status": "bn_extraction_status"})
    pe = data["pe"].drop(columns=["label"], errors="ignore")
    bn = data["bn"].drop(columns=["analysis_status", "label"], errors="ignore")
    feat = pe.merge(bn, on="sha256", how="outer", suffixes=("", "_bn_dup"))
    feat = feat.merge(meta, on="sha256", how="left")
    feat = feat.merge(bn_status, on="sha256", how="left")
    if feat["label"].dtype == object:
        feat["label"] = feat["label"].map({"benign": 0, "malicious": 1})
    assign = data["assignments"]
    train_sha = set(assign[assign["split"] == "train"]["sha256"])
    val_sha = set(assign[assign["split"] == "val"]["sha256"])
    return {
        "train": feat[feat["sha256"].isin(train_sha)].sort_values("sha256").reset_index(drop=True),
        "val": feat[feat["sha256"].isin(val_sha)].sort_values("sha256").reset_index(drop=True),
    }
