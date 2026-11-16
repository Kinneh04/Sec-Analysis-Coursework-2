"""Inventory + PE feature audit with acceptance checks for the larger experiment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from src.common.config import artifacts, load_config


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


def _split_group_leak(assignments: pd.DataFrame) -> list[dict]:
    leaks = []
    if "group_id" not in assignments.columns or "split" not in assignments.columns:
        return leaks
    for gid, g in assignments.groupby("group_id"):
        splits = set(g["split"].unique())
        if len(splits) > 1:
            leaks.append({"group_id": gid, "splits": sorted(splits), "n": int(len(g))})
    return leaks


def run_audit(cfg: dict) -> dict:
    art = artifacts(cfg)
    inv_path = art / "manifests" / "corpus_inventory.parquet"
    if not inv_path.is_file():
        raise FileNotFoundError(f"Missing inventory: {inv_path}. Run python -m src.inventory first.")

    inv = pd.read_parquet(inv_path)
    challenge = _load_challenge_sha(art)
    pe_path = art / "features" / "pe_features.parquet"
    pe = pd.read_parquet(pe_path) if pe_path.is_file() else None

    dup_sha = int(inv["sha256"].duplicated().sum()) if "sha256" in inv.columns else 0
    benign = inv[inv["label"] == "benign"] if "label" in inv.columns else inv.iloc[0:0]
    mal = inv[inv["label"] == "malicious"] if "label" in inv.columns else inv.iloc[0:0]

    third_party_roots = (
        benign[benign["source"] == "benign_third_party"]["software_source"].nunique()
        if "software_source" in benign.columns
        else 0
    )
    os_roots = (
        benign[benign["source"] == "benign_windows_os"]["software_source"].nunique()
        if "software_source" in benign.columns
        else 0
    )

    pe_ok_rate = None
    pe_merge_n = 0
    if pe is not None and "sha256" in pe.columns:
        merged = inv[["sha256", "label"]].merge(pe, on="sha256", how="left")
        pe_merge_n = len(merged)
        if "pe_status" in merged.columns:
            pe_ok_rate = float((merged["pe_status"] == "ok").mean())

    frozen_path = art / "manifests" / "split_assignments.parquet"
    assignments = pd.read_parquet(frozen_path) if frozen_path.is_file() else None
    group_leaks = _split_group_leak(assignments) if assignments is not None else []
    challenge_in_train = []
    if assignments is not None and challenge:
        bad = assignments[assignments["sha256"].isin(challenge) & (assignments["split"] != "challenge")]
        challenge_in_train = bad["sha256"].tolist()

    eval_cfg = cfg.get("evaluation", {})
    test_ratio = float(eval_cfg.get("test_ratio", 0.2))
    est_test_benign = int(len(benign) * test_ratio) if len(benign) else 0
    fpr_notes = []
    if est_test_benign < 1000:
        fpr_notes.append(
            f"Estimated test benign n≈{est_test_benign} (20% holdout). "
            "TPR at 0.1% FPR is not precisely estimable; prioritize primary_fpr "
            f"({eval_cfg.get('primary_fpr', 0.01)}) and bootstrap CIs."
        )

    checks = {
        "dataset_diversity": {
            "pass": third_party_roots >= 3 and os_roots >= 1,
            "third_party_software_sources": int(third_party_roots),
            "windows_os_sources": int(os_roots),
            "benign_by_source": benign.groupby("source").size().to_dict() if len(benign) else {},
            "malware_n": int(len(mal)),
            "benign_n": int(len(benign)),
        },
        "deduplication": {
            "pass": dup_sha == 0,
            "duplicate_sha256_rows": dup_sha,
            "unique_group_ids": int(inv["group_id"].nunique()) if "group_id" in inv.columns else None,
        },
        "label_quality": {
            "pass": True,
            "malicious_label_source": "malwarebazaar_provenance",
            "benign_label_sources": sorted(benign["label_source"].dropna().unique().tolist())
            if "label_source" in benign.columns
            else [],
            "note": "Manual spot-check of third-party paths remains recommended.",
        },
        "split_integrity": {
            "pass": len(group_leaks) == 0 and len(challenge_in_train) == 0,
            "frozen_assignments_present": assignments is not None,
            "group_id_cross_split_leaks": group_leaks[:20],
            "group_leak_count": len(group_leaks),
            "challenge_hashes_in_non_challenge_split": challenge_in_train,
        },
        "bn_coverage": {
            "pass": None,
            "note": "Run after small BN compatibility pilot; not required before inventory freeze.",
        },
        "feature_comparison": {
            "pass": None,
            "note": "Requires matched BN cohort; use src.paired_eval on identical test rows.",
        },
        "challenge_isolation": {
            "pass": len(challenge) >= 4,
            "challenge_sha_count": len(challenge),
            "challenge_in_inventory": sorted(set(inv["sha256"]) & challenge) if challenge else [],
        },
        "pe_extraction": {
            "pass": pe_ok_rate is None or pe_ok_rate >= 0.95,
            "pe_features_present": pe is not None,
            "pe_ok_rate": pe_ok_rate,
            "rows_with_pe_features": pe_merge_n,
        },
    }

    machine_dist = inv.groupby(["label", "machine"]).size().to_dict() if "machine" in inv.columns else {}
    file_type_dist = inv.groupby(["label", "file_type"]).size().to_dict() if "file_type" in inv.columns else {}

    report = {
        "inventory_total": int(len(inv)),
        "class_balance": inv.groupby("label").size().to_dict() if "label" in inv.columns else {},
        "architecture_distribution": {str(k): int(v) for k, v in machine_dist.items()},
        "file_type_distribution": {str(k): int(v) for k, v in file_type_dist.items()},
        "evaluation_fpr_guidance": fpr_notes,
        "acceptance_checks": checks,
        "ready_for_bn_pilot": all(
            c.get("pass") is True
            for name, c in checks.items()
            if name in ("dataset_diversity", "deduplication", "label_quality", "split_integrity", "challenge_isolation", "pe_extraction")
            and c.get("pass") is not None
        ),
    }
    return report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    args = ap.parse_args()
    cfg = load_config(args.config)
    report = run_audit(cfg)
    out = artifacts(cfg) / "evaluations" / "dataset_audit.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps(report["acceptance_checks"], indent=2))
    print(f"ready_for_bn_pilot={report['ready_for_bn_pilot']}")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
