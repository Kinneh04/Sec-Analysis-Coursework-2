"""EMBER v3 (thrember) features and the pretrained EMBER2024 PE reference model.

Static parsing only; files are never executed.

  python -m src.v4.ember extract --workers 6        # all known cohorts -> artifacts/v4/features/ember_v3.parquet
"""

from __future__ import annotations

import argparse
import os
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd

from src.common.config import artifacts, load_config
from src.v3.data import DEV_SPLITS, _challenge

EMBER_DIM = 2568
MODEL_DIR = Path("artifacts/ember2024/models/artifacts/ember2024/models")
COHORT_TAGS = ("v3", "v3.1", "v3.2", "v4")


def ember_columns() -> list[str]:
    return [f"em_{i:04d}" for i in range(EMBER_DIM)]


def pretrained_model(name: str = "PE") -> lgb.Booster:
    return lgb.Booster(model_file=str(MODEL_DIR / f"EMBER2024_{name}.model"))


def _worker(args: tuple[str, str]) -> tuple[str, np.ndarray | None, str]:
    import thrember

    path, sha = args
    try:
        vec = np.asarray(thrember.PEFeatureExtractor().feature_vector(Path(path).read_bytes()), dtype=np.float32)
        if vec.shape[0] != EMBER_DIM:
            return sha, None, f"bad_dim:{vec.shape[0]}"
        return sha, vec, "ok"
    except Exception as e:
        return sha, None, f"error:{type(e).__name__}"


def known_files(art: Path) -> pd.DataFrame:
    """sha256 + path for V1 train/val and every cohort inventory on disk."""
    assign = pd.read_parquet(art / "manifests" / "split_assignments.parquet")
    dev = assign[assign["split"].isin(DEV_SPLITS) & ~assign["sha256"].isin(_challenge(art))]
    inv = pd.read_parquet(art / "manifests" / "corpus_inventory.parquet")[["sha256", "relative_path"]]
    parts = [dev.merge(inv, on="sha256")[["sha256", "relative_path"]].rename(columns={"relative_path": "path"})]
    for tag in COHORT_TAGS:
        p = art / tag / "manifests" / "new_corpus_inventory.parquet"
        if p.is_file():
            parts.append(pd.read_parquet(p)[["sha256", "path"]])
    return pd.concat(parts, ignore_index=True).drop_duplicates("sha256").reset_index(drop=True)


def extract(files: pd.DataFrame, out: Path, *, workers: int) -> pd.DataFrame:
    existing = pd.read_parquet(out) if out.is_file() else None
    done = set(existing["sha256"]) if existing is not None else set()
    jobs = [(p, s) for s, p in zip(files["sha256"], files["path"]) if s not in done]
    print(f"EMBER v3: {len(done)} cached, {len(jobs)} to extract", flush=True)
    shas, vecs, status = [], [], []
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for i, (sha, vec, st) in enumerate(ex.map(_worker, jobs, chunksize=16), 1):
            shas.append(sha)
            status.append(st)
            vecs.append(vec if vec is not None else np.full(EMBER_DIM, np.nan, dtype=np.float32))
            if i % 500 == 0:
                print(f"  {i}/{len(jobs)}", flush=True)
    new = pd.DataFrame(np.vstack(vecs) if vecs else np.empty((0, EMBER_DIM), np.float32), columns=ember_columns())
    new.insert(0, "em_status", status)
    new.insert(0, "sha256", shas)
    df = pd.concat([existing, new], ignore_index=True) if existing is not None else new
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    df.to_parquet(tmp, index=False)
    tmp.replace(out)
    print(f"{int((df['em_status'] == 'ok').sum())}/{len(df)} ok -> {out}")
    return df


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["extract"])
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    args = ap.parse_args(argv)
    art = artifacts(load_config(args.config))
    extract(known_files(art), art / "v4" / "features" / "ember_v3.parquet", workers=args.workers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
