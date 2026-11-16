"""V3 development frames: frozen train/val only (test rows are never loaded here)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from src.audit.schema import bn_predictor_columns, pe_predictor_columns
from src.common.config import artifacts, load_config
from src.v3.pe_features_v3 import v3_predictor_columns

DEV_SPLITS = ("train", "val")


def load_dev_frames(config: str = "configs/local.yaml") -> dict[str, Any]:
    cfg = load_config(config)
    art = artifacts(cfg)
    assign = pd.read_parquet(art / "manifests" / "split_assignments.parquet")
    dev_assign = assign[assign["split"].isin(DEV_SPLITS)][["sha256", "split"]]
    challenge = _challenge(art)
    dev_assign = dev_assign[~dev_assign["sha256"].isin(challenge)]

    inv = pd.read_parquet(art / "manifests" / "corpus_inventory.parquet")[
        ["sha256", "label", "group_id", "file_size", "source", "software_source", "benign_root"]
    ]
    pe1 = pd.read_parquet(art / "features" / "pe_features.parquet").drop(columns=["label"], errors="ignore")
    pe3 = pd.read_parquet(art / "features" / "pe_features_v3.parquet")
    bn = pd.read_parquet(art / "features" / "bn_features_v2.parquet").drop(columns=["label"], errors="ignore")
    bn = bn.rename(columns={"analysis_status": "bn_record_status"})

    frame = dev_assign.merge(inv, on="sha256", how="left", validate="one_to_one")
    frame = frame.merge(pe1, on="sha256", how="inner", validate="one_to_one")
    frame = frame.merge(pe3, on="sha256", how="inner", validate="one_to_one")
    frame = frame.merge(bn, on="sha256", how="left", validate="one_to_one")
    frame = frame[frame["v3_status"] == "ok"]
    frame["label"] = frame["label"].map({"benign": 0, "malicious": 1}).astype(int)
    frame = frame.sort_values("sha256").reset_index(drop=True)

    train = frame[frame["split"] == "train"].reset_index(drop=True)
    val = frame[frame["split"] == "val"].reset_index(drop=True)
    return {
        "cfg": cfg,
        "art": art,
        "train": train,
        "val": val,
        "feature_sets": feature_sets(train),
    }


POOL_COLS = ["sha256", "label", "group_id", "source", "origin"]


def load_pool(
    config: str,
    new_splits: tuple[str, ...] | None = None,
    *,
    include_v1_train: bool,
    cohorts: list[tuple[str, tuple[str, ...]]] | None = None,
) -> pd.DataFrame:
    """V1 train and/or tagged cohort rows with PE-v3 and V1-stable features.

    ``cohorts`` is a list of (tag, splits), e.g. [("v3", ("new_train",)), ("v3.1", ("blind",))].
    When ``cohorts`` is omitted, defaults to ``[("v3", new_splits)]``.
    """
    art = artifacts(load_config(config))
    v1s = pd.read_parquet(art / "v3" / "features" / "pe_v1_stable.parquet")
    v1s = v1s[v1s["v1s_status"] == "ok"]
    parts = []
    if include_v1_train:
        tr = load_dev_frames(config)["train"].copy()
        tr["origin"] = "v1_train"
        parts.append(tr[POOL_COLS + [c for c in tr.columns if c.startswith("pe3_") or c.startswith("v3_")]])
    spec = cohorts if cohorts is not None else ([("v3", tuple(new_splits or ()))])
    for tag, splits in spec:
        if not splits:
            continue
        split = pd.read_parquet(art / tag / "manifests" / "new_split_assignments.parquet")
        split = split[split["split"].isin(splits)]
        inv = pd.read_parquet(art / tag / "manifests" / "new_corpus_inventory.parquet")[
            ["sha256", "source", "imphash", "v1_overlap"]
        ]
        pe3 = pd.read_parquet(art / tag / "features" / "pe_features_v3_new.parquet")
        new = split.merge(inv, on="sha256", validate="one_to_one").merge(pe3, on="sha256", validate="one_to_one")
        new = new[new["v3_status"] == "ok"].copy()
        new["label"] = new["label"].map({"benign": 0, "malicious": 1}).astype(int)
        new["origin"] = f"{tag}_" + new["split"]
        parts.append(new[POOL_COLS + ["imphash", "v1_overlap"] + [c for c in new.columns if c.startswith("pe3_") or c.startswith("v3_")]])
    pool = pd.concat(parts, ignore_index=True)
    pool = pool.merge(v1s, on="sha256", how="inner", validate="one_to_one")
    return pool.sort_values("sha256").reset_index(drop=True)


def feature_sets(df: pd.DataFrame) -> dict[str, list[str]]:
    pe1 = pe_predictor_columns(df)
    pe3 = v3_predictor_columns(df)
    bn = bn_predictor_columns(df)
    return {
        "pe_v1": pe1,
        "pe_v3": pe3,
        "pe_v3_ts": v3_predictor_columns(df, include_timestamp=True),
        "pe_v3_bn": pe3 + bn,
    }


def _challenge(art: Path) -> set[str]:
    out: set[str] = set()
    for name in ("challenge_qualitative_sha256.txt", "challenge_quantitative_sha256.txt"):
        p = art / "manifests" / name
        if p.is_file():
            out |= {ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")}
    return out
