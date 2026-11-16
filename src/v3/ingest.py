"""Ingest a new labeled PE corpus into a frozen group-aware new_train / blind split.

Read-only: files are hashed and parsed with pefile, never executed.

Usage:
  python -m src.v3.ingest --manifest new_labels.csv        # columns: path,label[,source]
  python -m src.v3.ingest --benign-dir D:\\clean --malicious-dir D:\\mal
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pefile

from src.common.config import artifacts, load_config
from src.common.hashing import sha256_file
from src.v3.pe_features_v3 import extract_manifest

PE_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ".efi", ""}
LABELS = {"benign", "malicious"}
BLIND_FRACTION = 0.5
MIN_BLIND_BENIGN = 300


def imphash_of(path: Path) -> str:
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        h = pe.get_imphash() or ""
        pe.close()
        return h
    except Exception:
        return ""


def _is_pe(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            head = fh.read(0x40)
            if head[:2] != b"MZ" or len(head) < 0x40:
                return False
            off = int.from_bytes(head[0x3C:0x40], "little")
            fh.seek(off)
            return fh.read(4) == b"PE\0\0"
    except OSError:
        return False


def group_id_for(label: str, path: Path, imphash: str, sha: str, root: Path | None) -> str:
    """Same group scheme as V1: malware by imphash, benign by install directory."""
    if label == "malicious":
        return f"mb_imphash:{imphash}" if imphash else f"mb_sha:{sha[:16]}"
    base = root if root is not None else path.parent
    try:
        rel = path.relative_to(base)
        anchor = rel.parent.as_posix().lower() if rel.parent.parts else "."
    except ValueError:
        anchor = "."
    root_key = hashlib.sha256(str(base.resolve()).encode("utf-8")).hexdigest()[:10]
    return f"benign_dir:{root_key}:{anchor}"


def collect_rows(manifest: Path | None, benign_dirs: list[str], malicious_dirs: list[str], max_mb: float) -> pd.DataFrame:
    items: list[tuple[Path, str, str, Path | None]] = []
    if manifest is not None:
        m = pd.read_parquet(manifest) if manifest.suffix == ".parquet" else pd.read_csv(manifest)
        missing = {"path", "label"} - set(m.columns)
        if missing:
            raise ValueError(f"manifest missing columns: {sorted(missing)}")
        for r in m.itertuples(index=False):
            label = str(r.label).strip().lower()
            if label not in LABELS:
                raise ValueError(f"unknown label {r.label!r} for {r.path}")
            src = str(getattr(r, "source", "") or f"manifest_{label}")
            items.append((Path(str(r.path)), label, src, None))
    for label, dirs in (("benign", benign_dirs), ("malicious", malicious_dirs)):
        for d in dirs:
            root = Path(d)
            for p in root.rglob("*"):
                if p.is_file() and p.suffix.lower() in PE_SUFFIXES:
                    items.append((p, label, f"dir_{label}:{root.name}", root))

    max_bytes = int(max_mb * 1024 * 1024)
    rows = []
    for path, label, src, root in items:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= 0 or size > max_bytes or not _is_pe(path):
            continue
        sha = sha256_file(path)
        imph = imphash_of(path)
        rows.append({
            "sha256": sha, "path": str(path), "file_size": size, "label": label, "source": src,
            "imphash": imph, "group_id": group_id_for(label, path, imph, sha, root),
        })
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    conflict = df.groupby("sha256")["label"].nunique()
    bad = set(conflict[conflict > 1].index)
    df = df[~df["sha256"].isin(bad)].drop_duplicates("sha256").reset_index(drop=True)
    df.attrs["label_conflicts_dropped"] = len(bad)
    return df


def v1_reference(art: Path, *, prior_cohort_tags: tuple[str, ...] = ()) -> dict[str, set[str]]:
    inv = pd.read_parquet(art / "manifests" / "corpus_inventory.parquet")
    cache = art / "v3" / "manifests" / "v1_imphash.parquet"
    if cache.is_file():
        imp = pd.read_parquet(cache)
    else:
        imp = pd.DataFrame({
            "sha256": inv["sha256"],
            "imphash": [imphash_of(Path(p)) if Path(str(p)).is_file() else "" for p in inv["relative_path"]],
        })
        cache.parent.mkdir(parents=True, exist_ok=True)
        imp.to_parquet(cache, index=False)
    sha = set(inv["sha256"])
    gid = set(inv["group_id"].astype(str))
    imph = {h for h in imp["imphash"].astype(str) if h}
    for tag in prior_cohort_tags:
        p = art / tag / "manifests" / "new_corpus_inventory.parquet"
        if not p.is_file():
            continue
        prev = pd.read_parquet(p)
        sha |= set(prev["sha256"])
        gid |= set(prev["group_id"].astype(str))
        if "imphash" in prev.columns:
            imph |= {h for h in prev["imphash"].astype(str) if h}
    return {"sha256": sha, "group_id": gid, "imphash": imph}


def assign_split(df: pd.DataFrame, ref: dict[str, set[str]], *, seed: int, blind_fraction: float = BLIND_FRACTION) -> pd.DataFrame:
    """Group-aware split. Groups sharing a group_id or imphash with V1 cannot enter blind."""
    df = df[~df["sha256"].isin(ref["sha256"])].copy()
    df["v1_overlap"] = df["group_id"].isin(ref["group_id"]) | (df["imphash"].ne("") & df["imphash"].isin(ref["imphash"]))
    g = df.groupby("group_id").agg(
        label=("label", lambda s: s.mode().iloc[0]), n=("sha256", "size"), forced=("v1_overlap", "any")
    ).reset_index()
    rng = np.random.default_rng(seed)
    blind_groups: set[str] = set()
    for label, gl in g.groupby("label"):
        target = blind_fraction * gl["n"].sum()
        eligible = gl[~gl["forced"]].iloc[rng.permutation(int((~gl["forced"]).sum()))]
        taken = 0
        for r in eligible.itertuples(index=False):
            if taken >= target:
                break
            blind_groups.add(r.group_id)
            taken += r.n
    df["split"] = np.where(df["group_id"].isin(blind_groups), "blind", "new_train")
    return df.sort_values("sha256").reset_index(drop=True)


def _sha_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def freeze(df: pd.DataFrame, out_dir: Path, *, seed: int, extra: dict[str, Any], lock_name: str = "new_corpus_freeze.json") -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    lock = out_dir / lock_name
    if lock.exists():
        raise FileExistsError(f"{lock} exists; the new corpus split is already frozen")
    inv_path = out_dir / "new_corpus_inventory.parquet"
    split_path = out_dir / "new_split_assignments.parquet"
    df.to_parquet(inv_path, index=False)
    df[["sha256", "split", "group_id", "label"]].to_parquet(split_path, index=False)
    counts = df.groupby(["split", "label"]).size().unstack(fill_value=0)
    blind_benign = int(counts.loc["blind", "benign"]) if "blind" in counts.index and "benign" in counts.columns else 0
    meta = {
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "counts": {s: {k: int(v) for k, v in row.items()} for s, row in counts.iterrows()},
        "groups": {s: int(df[df["split"] == s]["group_id"].nunique()) for s in df["split"].unique()},
        "v1_overlap_rows_forced_to_new_train": int(df["v1_overlap"].sum()),
        "blind_benign": blind_benign,
        "meets_min_blind_benign": blind_benign >= MIN_BLIND_BENIGN,
        "inventory_sha256": _sha_file(inv_path),
        "split_sha256": _sha_file(split_path),
        **extra,
    }
    lock.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--manifest", type=Path, default=None)
    ap.add_argument("--benign-dir", action="append", default=[])
    ap.add_argument("--malicious-dir", action="append", default=[])
    ap.add_argument("--seed", type=int, default=20261101)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--cohort-tag", default="v3", help="artifacts/<tag>/ (e.g. v3.1)")
    ap.add_argument("--prior-cohorts", default="", help="Comma-separated prior tags whose SHA/groups/imphash force new_train")
    args = ap.parse_args(argv)
    if args.manifest is None and not (args.benign_dir or args.malicious_dir):
        ap.error("provide --manifest or at least one --benign-dir/--malicious-dir")

    cfg = load_config(args.config)
    art = artifacts(cfg)
    max_mb = float(cfg.get("analysis", {}).get("max_file_size_mb", 50))
    rows = collect_rows(args.manifest, args.benign_dir, args.malicious_dir, max_mb)
    if rows.empty:
        print("No PE files found.")
        return 1
    tag = args.cohort_tag
    prior = tuple(t.strip() for t in args.prior_cohorts.split(",") if t.strip())
    df = assign_split(rows, v1_reference(art, prior_cohort_tags=prior), seed=args.seed)
    out_root = art / tag
    meta = freeze(df, out_root / "manifests", seed=args.seed, extra={
        "cohort_tag": tag,
        "prior_cohorts": list(prior),
        "label_conflicts_dropped": int(rows.attrs.get("label_conflicts_dropped", 0)),
        "n_collected": int(len(rows)),
        "n_after_v1_sha_dedup": int(len(df)),
    })
    print(json.dumps(meta, indent=2))
    if not meta["meets_min_blind_benign"]:
        print(f"WARNING: blind has {meta['blind_benign']} benign rows (< {MIN_BLIND_BENIGN}); 1% FPR will not be resolvable.")
    feat = extract_manifest(list(zip(df["path"], df["sha256"])), out_root / "features" / "pe_features_v3_new.parquet", workers=args.workers)
    print(f"PE-v3 extracted: {int((feat['v3_status'] == 'ok').sum())}/{len(feat)} ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
