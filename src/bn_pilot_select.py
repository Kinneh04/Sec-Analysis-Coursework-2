"""Deterministic 60-sample BN compatibility cohort from frozen train split."""

from __future__ import annotations

import argparse
import hashlib
import json

import pandas as pd

from src.common.config import artifacts, load_config

PILOT_TARGETS = {
    "third_party_benign": 25,
    "windows_benign": 5,
    "malicious": 30,
}


def _size_bucket(file_size: int, small_bytes: int) -> str:
    if file_size <= small_bytes:
        return "small"
    if file_size <= 100_000:
        return "medium"
    return "large"


def _pilot_category(row: pd.Series) -> str | None:
    if row["label"] == "malicious":
        return "malicious"
    if row.get("source") == "benign_windows_os":
        return "windows_benign"
    if row.get("source") == "benign_third_party":
        return "third_party_benign"
    return None


def _deterministic_pick(pool: pd.DataFrame, n: int, seed: int, small_bytes: int) -> pd.DataFrame:
    if len(pool) <= n:
        return pool.sort_values("sha256").head(n)

    pool = pool.copy()
    pool["_size_bucket"] = pool["file_size"].fillna(0).astype(int).map(lambda s: _size_bucket(int(s), small_bytes))
    pool["_stratum"] = pool.apply(
        lambda r: "|".join(
            [
                str(r.get("software_source") or ""),
                str(r.get("machine") or ""),
                str(r.get("file_type") or ""),
                str(r["_size_bucket"]),
            ]
        ),
        axis=1,
    )
    strata = {k: g.sort_values("sha256") for k, g in pool.groupby("_stratum", sort=True)}
    order = sorted(strata.keys())
    picked: list[pd.Series] = []
    idx = {k: 0 for k in order}
    rank = 0
    while len(picked) < n and order:
        progressed = False
        for key in order:
            if len(picked) >= n:
                break
            i = idx[key]
            bucket = strata[key]
            if i < len(bucket):
                picked.append(bucket.iloc[i])
                idx[key] = i + 1
                progressed = True
        if not progressed:
            break
        rank += 1

    if len(picked) < n:
        remaining = pool[~pool["sha256"].isin({p["sha256"] for p in picked})].sort_values("sha256")
        for _, row in remaining.iterrows():
            if len(picked) >= n:
                break
            picked.append(row)

    out = pd.DataFrame(picked)
    out["pilot_rank"] = range(len(out))
    out["pilot_select_seed"] = seed
    return out.drop(columns=[c for c in ("_size_bucket", "_stratum") if c in out.columns])


def _boost_small_pe_samples(
    pilot: pd.DataFrame, inv: pd.DataFrame, small_bytes: int, min_small: int, seed: int
) -> pd.DataFrame:
    """Swap in small PEs from train pool when stratified pick under-represents them."""
    if int(pilot["is_small_pe"].sum()) >= min_small:
        return pilot
    need = min_small - int(pilot["is_small_pe"].sum())
    pool = inv[~inv["sha256"].isin(pilot["sha256"])].copy()
    pool["is_small_pe"] = pool["file_size"].fillna(0).astype(int) <= small_bytes
    small_pool = pool[pool["is_small_pe"]].sort_values("sha256")
    if small_pool.empty:
        return pilot
    out = pilot.copy()
    out["is_small_pe"] = out["file_size"].fillna(0).astype(int) <= small_bytes
    drop_candidates = out[(~out["is_small_pe"]) & (out["pilot_category"] == "malicious")].sort_values(
        "sha256", ascending=False
    )
    drop_idx = drop_candidates.index.tolist()
    for _, row in small_pool[small_pool["pilot_category"] == "malicious"].head(need).iterrows():
        if not drop_idx:
            break
        drop_i = drop_idx.pop(0)
        repl = row.copy()
        repl["pilot_category"] = "malicious"
        out.loc[drop_i] = repl
    out["is_small_pe"] = out["file_size"].fillna(0).astype(int) <= small_bytes
    return out.sort_values("pilot_category").reset_index(drop=True)


def select_pilot_cohort(cfg: dict) -> pd.DataFrame:
    art = artifacts(cfg)
    exp = cfg.get("experiment", {})
    seed = int(cfg.get("models", {}).get("random_seed", 42))
    small_bytes = int(exp.get("bn_pilot_small_pe_bytes", 8192))

    assign = pd.read_parquet(art / "manifests" / "split_assignments.parquet")
    train_sha = set(assign[assign["split"] == "train"]["sha256"])
    inv = pd.read_parquet(art / "manifests" / "corpus_inventory.parquet")
    inv = inv[inv["sha256"].isin(train_sha) & (inv["inventory_status"] == "ok")].copy()
    inv["pilot_category"] = inv.apply(_pilot_category, axis=1)
    inv = inv[inv["pilot_category"].notna()]

    parts: list[pd.DataFrame] = []
    for cat, need in PILOT_TARGETS.items():
        pool = inv[inv["pilot_category"] == cat]
        parts.append(_deterministic_pick(pool, need, seed + abs(hash(cat)) % 1000, small_bytes))

    pilot = pd.concat(parts, ignore_index=True)
    pilot["is_small_pe"] = pilot["file_size"].fillna(0).astype(int) <= small_bytes
    pilot = _boost_small_pe_samples(pilot, inv, small_bytes, min_small=5, seed=seed)
    pilot["pilot_id"] = pilot.apply(
        lambda r: hashlib.sha256(f"{r['sha256']}:pilot60".encode()).hexdigest()[:16], axis=1
    )
    return pilot


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    args = ap.parse_args()
    cfg = load_config(args.config)
    pilot = select_pilot_cohort(cfg)
    man = artifacts(cfg) / "manifests"
    man.mkdir(parents=True, exist_ok=True)
    path = man / "bn_pilot_60.parquet"
    pilot.to_parquet(path, index=False)
    sha_path = man / "bn_pilot_60_sha256.txt"
    sha_path.write_text("\n".join(pilot["sha256"].tolist()) + "\n", encoding="utf-8")
    meta = {
        "n": int(len(pilot)),
        "by_category": pilot.groupby("pilot_category").size().to_dict(),
        "by_software_source": pilot.groupby("software_source").size().to_dict(),
        "small_pe_count": int(pilot["is_small_pe"].sum()),
        "machine_counts": pilot.groupby("machine").size().to_dict(),
        "split_source": "train_only",
        "note_imphash": (
            "Frozen splits group malware by imphash when available; imphash does not guarantee "
            "family cohesion and can merge unrelated samples. Consider family/time metadata for final eval."
        ),
    }
    (man / "bn_pilot_60_meta.json").write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
    print(json.dumps(meta, indent=2))
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
