from __future__ import annotations

import argparse
import json

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from src.common.config import artifacts, load_config


def _feature_columns(df: pd.DataFrame, prefixes: tuple[str, ...]) -> list[str]:
    skip = {"pe_status", "pe_extractor", "bn_status", "bn_extractor", "bn_source", "bn_arch", "bn_error"}
    cols = [c for c in df.columns if c.startswith(prefixes) and c not in skip]
    return [c for c in cols if pd.api.types.is_numeric_dtype(df[c])]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--bn-version", choices=("v1", "v2"), default="v1")
    args = ap.parse_args()
    cfg = load_config(args.config)
    art = artifacts(cfg)
    inv = pd.read_parquet(art / "manifests" / "corpus_inventory.parquet")
    pe = pd.read_parquet(art / "features" / "pe_features.parquet")
    bn_name = "bn_features_v2.parquet" if args.bn_version == "v2" else "bn_features.parquet"
    bn = pd.read_parquet(art / "features" / bn_name)

    pe_cols = _feature_columns(pe, ("pe_",))
    if args.bn_version == "v2":
        bn_cols = _feature_columns(bn, ("bn_", "quality_"))
    else:
        bn_cols = _feature_columns(bn, ("cfg_", "mlil_", "legacy_hlil_regex_", "quality_"))

    challenge_sha: set[str] = set()
    for name in ("challenge_qualitative_sha256.txt", "challenge_quantitative_sha256.txt", "challenge_sha256.txt"):
        p = art / "manifests" / name
        if p.is_file():
            for ln in p.read_text(encoding="utf-8").splitlines():
                s = ln.strip()
                if s and not s.startswith("#"):
                    challenge_sha.add(s)

    frozen_path = art / "manifests" / "split_assignments.parquet"

    def _write_splits(frame: pd.DataFrame, prefix: str) -> dict:
        splits_dir = art / "splits"
        splits_dir.mkdir(parents=True, exist_ok=True)
        if frozen_path.is_file():
            assign = pd.read_parquet(frozen_path)
            assign = assign[assign["split"].isin(("train", "val", "test"))]
            merged = frame.merge(assign[["sha256", "split"]], on="sha256", how="inner")
            train = merged[merged["split"] == "train"].drop(columns=["split"])
            val = merged[merged["split"] == "val"].drop(columns=["split"])
            test = merged[merged["split"] == "test"].drop(columns=["split"])
        else:
            seed = int(cfg["models"]["random_seed"])
            labels = frame["label"].map({"benign": 0, "malicious": 1})
            groups = frame["group_id"].fillna(frame["sha256"])
            gss = GroupShuffleSplit(n_splits=1, test_size=cfg["evaluation"]["test_ratio"], random_state=seed)
            train_val_idx, test_idx = next(gss.split(frame, labels, groups))
            tv = frame.iloc[train_val_idx]
            test = frame.iloc[test_idx]
            labels_tv = labels.iloc[train_val_idx]
            groups_tv = groups.iloc[train_val_idx]
            val_ratio = cfg["evaluation"]["val_ratio"]
            train_ratio = cfg["evaluation"]["train_ratio"]
            val_rel = val_ratio / (train_ratio + val_ratio)
            gss2 = GroupShuffleSplit(n_splits=1, test_size=val_rel, random_state=seed + 1)
            train_idx, val_idx = next(gss2.split(tv, labels_tv, groups_tv))
            train = tv.iloc[train_idx]
            val = tv.iloc[val_idx]
        train.to_parquet(splits_dir / f"{prefix}train.parquet", index=False)
        val.to_parquet(splits_dir / f"{prefix}val.parquet", index=False)
        test.to_parquet(splits_dir / f"{prefix}test.parquet", index=False)
        return {"train": len(train), "val": len(val), "test": len(test), "prefix": prefix, "frozen": frozen_path.is_file()}

    pe_x = pe.drop(columns=[c for c in ("label",) if c in pe.columns])
    bn_x = bn.drop(columns=[c for c in ("label",) if c in bn.columns])
    inv_train = inv[~inv["sha256"].isin(challenge_sha)] if challenge_sha else inv
    merged_pe = inv_train[["sha256", "label", "group_id"]].merge(pe_x, on="sha256", how="inner")
    merged_bn = merged_pe.merge(bn_x, on="sha256", how="inner")

    meta = {
        "bn_version": args.bn_version,
        "challenge_excluded": len(challenge_sha),
        "pe_feature_count": len(pe_cols),
        "bn_feature_count": len(bn_cols),
        "pe_all_samples": len(merged_pe),
        "matched_bn_samples": len(merged_bn),
        "pe_all_splits": _write_splits(merged_pe, prefix="pe_all_"),
        "bn_matched_splits": _write_splits(merged_bn, prefix=""),
    }
    (art / "splits" / "split_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(meta)


if __name__ == "__main__":
    main()
