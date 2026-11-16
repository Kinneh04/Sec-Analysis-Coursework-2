"""Freeze train/val/test assignments (group-aware) before BN extraction."""

from __future__ import annotations

import argparse
import json

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from src.audit_dataset import _load_challenge_sha
from src.common.config import artifacts, load_config


def freeze_assignments(cfg: dict) -> dict:
    art = artifacts(cfg)
    inv_path = art / "manifests" / "corpus_inventory.parquet"
    inv = pd.read_parquet(inv_path)
    challenge = _load_challenge_sha(art)

    eval_cfg = cfg["evaluation"]
    seed = int(cfg["models"]["random_seed"])

    pool = inv[~inv["sha256"].isin(challenge)].copy()
    labels = pool["label"].map({"benign": 0, "malicious": 1})
    groups = pool["group_id"].fillna(pool["sha256"])

    gss = GroupShuffleSplit(n_splits=1, test_size=eval_cfg["test_ratio"], random_state=seed)
    train_val_idx, test_idx = next(gss.split(pool, labels, groups))
    tv = pool.iloc[train_val_idx]
    test = pool.iloc[test_idx]
    labels_tv = labels.iloc[train_val_idx]
    groups_tv = groups.iloc[train_val_idx]
    val_rel = eval_cfg["val_ratio"] / (eval_cfg["train_ratio"] + eval_cfg["val_ratio"])
    gss2 = GroupShuffleSplit(n_splits=1, test_size=val_rel, random_state=seed + 1)
    train_idx, val_idx = next(gss2.split(tv, labels_tv, groups_tv))
    train = tv.iloc[train_idx]
    val = tv.iloc[val_idx]

    def _rows(frame: pd.DataFrame, split: str) -> pd.DataFrame:
        return pd.DataFrame(
            {
                "sha256": frame["sha256"],
                "label": frame["label"],
                "group_id": frame["group_id"],
                "source": frame.get("source"),
                "software_source": frame.get("software_source"),
                "split": split,
            }
        )

    challenge_rows = []
    if challenge:
        in_inv = inv[inv["sha256"].isin(challenge)]
        for _, r in in_inv.iterrows():
            challenge_rows.append(
                {
                    "sha256": r["sha256"],
                    "label": r.get("label", "unknown"),
                    "group_id": r.get("group_id"),
                    "source": r.get("source"),
                    "software_source": r.get("software_source"),
                    "split": "challenge",
                }
            )

    assignments = pd.concat(
        [_rows(train, "train"), _rows(val, "val"), _rows(test, "test"), pd.DataFrame(challenge_rows)],
        ignore_index=True,
    )

    man = art / "manifests"
    man.mkdir(parents=True, exist_ok=True)
    assignments.to_parquet(man / "split_assignments.parquet", index=False)
    for split in ("train", "val", "test", "challenge"):
        sha = assignments[assignments["split"] == split]["sha256"].tolist()
        (man / f"frozen_{split}_sha256.txt").write_text("\n".join(sha) + ("\n" if sha else ""), encoding="utf-8")

    counts_by_label = {
        f"{split}|{label}": int(n)
        for (split, label), n in assignments.groupby(["split", "label"]).size().items()
    }
    meta = {
        "frozen": True,
        "random_seed": seed,
        "challenge_excluded_from_train_val_test": sorted(challenge),
        "counts": {k: int(v) for k, v in assignments.groupby("split").size().items()},
        "counts_by_label": counts_by_label,
        "unique_groups_by_split": {
            s: int(assignments[assignments["split"] == s]["group_id"].nunique()) for s in assignments["split"].unique()
        },
    }
    (man / "cohort_frozen.json").write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
    return meta


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    args = ap.parse_args()
    cfg = load_config(args.config)
    meta = freeze_assignments(cfg)
    print(json.dumps(meta, indent=2, default=str))


if __name__ == "__main__":
    main()
