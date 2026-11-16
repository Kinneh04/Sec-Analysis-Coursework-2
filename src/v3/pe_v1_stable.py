"""V1 PE features with process-stable import buckets (V3 baseline).

`src.pe_features` buckets imports with Python's salted `hash()`, so its 256 bucket columns
cannot be reproduced for new files. This module reuses the V1 scalar features unchanged and
replaces only the buckets with MD5 bucketing. Columns are prefixed `pe1s_`.

  python -m src.v3.pe_v1_stable --workers 6
"""

from __future__ import annotations

import argparse
import os
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

import pandas as pd
import pefile

from src.common.config import artifacts, load_config
from src.pe_features import extract_pe_features
from src.v3.data import DEV_SPLITS, _challenge
from src.v3.pe_features_v3 import stable_bucket

EXTRACTOR_VERSION = "pe_v1_stable"
BUCKETS = 256


def _imports(path: Path) -> list[str]:
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    out: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode(errors="replace").lower()
        for imp in entry.imports:
            if imp.name:
                out.append(f"{dll}!{imp.name.decode(errors='replace')}")
            elif imp.ordinal is not None:
                out.append(f"{dll}!ord{imp.ordinal}")
    pe.close()
    return out


def extract_pe_v1_stable(path: Path) -> dict[str, Any]:
    v1 = extract_pe_features(path)
    out: dict[str, Any] = {"v1s_extractor": EXTRACTOR_VERSION, "v1s_status": v1.get("pe_status", "error")}
    for k, v in v1.items():
        if k.startswith("pe_imphash_h") or k in ("pe_status", "pe_extractor"):
            continue
        out["pe1s_" + k[3:]] = v
    if out["v1s_status"] != "ok":
        return out
    counts = [0] * BUCKETS
    try:
        for imp in _imports(path):
            counts[stable_bucket(imp, BUCKETS)] += 1
    except Exception:
        pass
    for i, c in enumerate(counts):
        out[f"pe1s_imp_h{i:03d}"] = c
    return out


def _worker(args: tuple[str, str]) -> dict[str, Any]:
    path, sha = args
    try:
        r = extract_pe_v1_stable(Path(path))
    except Exception as e:
        r = {"v1s_status": f"error:{type(e).__name__}", "v1s_extractor": EXTRACTOR_VERSION}
    r["sha256"] = sha
    return r


def v1s_predictor_columns(df: pd.DataFrame) -> list[str]:
    return sorted(c for c in df.columns if c.startswith("pe1s_") and pd.api.types.is_numeric_dtype(df[c]))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--append-cohort", default=None, help="Only extract paths from artifacts/<tag>/manifests not already in pe_v1_stable.parquet")
    args = ap.parse_args(argv)
    art = artifacts(load_config(args.config))
    out = art / "v3" / "features" / "pe_v1_stable.parquet"
    existing_sha: set[str] = set()
    if out.is_file():
        existing_sha = set(pd.read_parquet(out, columns=["sha256"])["sha256"])

    if args.append_cohort:
        inv = pd.read_parquet(art / args.append_cohort / "manifests" / "new_corpus_inventory.parquet")[["path", "sha256"]]
        inv = inv[~inv["sha256"].isin(existing_sha)]
        jobs = list(zip(inv["path"], inv["sha256"]))
    else:
        assign = pd.read_parquet(art / "manifests" / "split_assignments.parquet")
        dev = assign[assign["split"].isin(DEV_SPLITS) & ~assign["sha256"].isin(_challenge(art))]
        inv = pd.read_parquet(art / "manifests" / "corpus_inventory.parquet")
        v1_rows = dev.merge(inv[["sha256", "relative_path"]], on="sha256")[["relative_path", "sha256"]]
        new = pd.read_parquet(art / "v3" / "manifests" / "new_corpus_inventory.parquet")[["path", "sha256"]]
        jobs = list(zip(v1_rows["relative_path"].astype(str), v1_rows["sha256"])) + list(zip(new["path"], new["sha256"]))

    rows = []
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        for i, r in enumerate(ex.map(_worker, jobs, chunksize=8), 1):
            rows.append(r)
            if i % 250 == 0:
                print(f"  {i}/{len(jobs)}", flush=True)
    df = pd.DataFrame(rows)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.append_cohort and out.is_file():
        df = pd.concat([pd.read_parquet(out), df], ignore_index=True).drop_duplicates("sha256", keep="last")
    tmp = out.with_suffix(".tmp")
    df.to_parquet(tmp, index=False)
    tmp.replace(out)
    print(f"{int((df['v1s_status'] == 'ok').sum())}/{len(df)} ok, {len(v1s_predictor_columns(df))} predictors -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
