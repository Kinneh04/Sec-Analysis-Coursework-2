"""Build and freeze the V4 blind cohort (benign from Windows locations unused in earlier waves;
malware from 2026 MalwareBazaar batches). Read-only; nothing is executed.

  python -m src.v4.cohort --n-benign 450 --n-malicious 450
"""

from __future__ import annotations

import argparse
import os
import random
from pathlib import Path

import pandas as pd

from src.common.config import artifacts, load_config
from src.v3 import ingest
from src.v3.new_cohort import excluded_sha_and_paths
from src.v3.pe_features_v3 import extract_manifest
from src.v3.temporal_eval import sample_temporal_malware

PRIOR_TAGS = ("v3", "v3.1", "v3.2")
PE_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"}
PER_DIR_CAP = 2
BENIGN_ROOT_CAPS = {
    r"C:\Windows\WinSxS": 160,
    r"C:\Windows\Microsoft.NET": 80,
    r"C:\Windows\SystemApps": 60,
    r"C:\Windows\assembly": 80,
    r"C:\ProgramData": 40,
    os.path.expandvars(r"%LOCALAPPDATA%\Programs"): 100,
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft"): 60,
    r"C:\Windows\diagnostics": 15,
}
MAX_BYTES = 16 * 1024 * 1024


def sample_benign_new_roots(seed: int, exclude_paths: set[str]) -> list[dict]:
    rng = random.Random(seed)
    out: list[dict] = []
    for root, cap in BENIGN_ROOT_CAPS.items():
        by_dir: dict[str, list[Path]] = {}
        for p in Path(root).rglob("*"):
            try:
                if p.suffix.lower() not in PE_SUFFIXES or not p.is_file() or p.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            if str(p).lower() in exclude_paths:
                continue
            by_dir.setdefault(str(p.parent).lower(), []).append(p)
        dirs = sorted(by_dir)
        rng.shuffle(dirs)
        taken = 0
        for d in dirs:
            files = sorted(by_dir[d])
            rng.shuffle(files)
            for p in files[:PER_DIR_CAP]:
                if taken >= cap:
                    break
                out.append({"path": str(p), "label": "benign", "source": f"benign_v4:{Path(root).name}"})
                taken += 1
            if taken >= cap:
                break
    return out


def temporal_reference(art: Path) -> tuple[set[str], set[str]]:
    p = art / "v3.3" / "temporal_eval" / "manifest.csv"
    if not p.is_file():
        return set(), set()
    m = pd.read_csv(p)
    imp = set(m.get("imphash", pd.Series(dtype=str)).dropna().astype(str)) - {"", "nan"}
    return set(m["sha256"].dropna().astype(str)), imp


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--n-benign", type=int, default=450)
    ap.add_argument("--n-malicious", type=int, default=450)
    ap.add_argument("--min-date", default="2026-01-01")
    ap.add_argument("--seed", type=int, default=20261105)
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    art = artifacts(cfg)
    out_dir = art / "v4" / "manifests"
    if (out_dir / "new_corpus_freeze.json").exists():
        print("V4 cohort already frozen")
        return 1
    ex_sha, ex_paths = excluded_sha_and_paths(art, PRIOR_TAGS)
    t_sha, t_imp = temporal_reference(art)
    ex_sha |= t_sha

    benign = sample_benign_new_roots(args.seed, ex_paths)[: args.n_benign * 2]
    malware = sample_temporal_malware(cfg, args.n_malicious * 2, args.min_date, ex_sha, args.seed)
    labels = out_dir / "new_cohort_labels.csv"
    out_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(benign + [{k: r[k] for k in ("path", "label", "source")} for r in malware]).to_csv(labels, index=False)

    rows = ingest.collect_rows(labels, [], [], float(cfg.get("analysis", {}).get("max_file_size_mb", 50)))
    ref = ingest.v1_reference(art, prior_cohort_tags=PRIOR_TAGS)
    ref["sha256"] |= t_sha
    ref["imphash"] |= t_imp
    df = ingest.assign_split(rows, ref, seed=args.seed, blind_fraction=1.0)
    blind = df[df["split"] == "blind"]
    keep = pd.concat([
        blind[blind["label"] == "benign"].sample(frac=1.0, random_state=args.seed).head(args.n_benign),
        blind[blind["label"] == "malicious"].sample(frac=1.0, random_state=args.seed).head(args.n_malicious),
    ])
    df = pd.concat([keep, df[df["split"] != "blind"]]).sort_values("sha256").reset_index(drop=True)
    df.loc[~df["sha256"].isin(keep["sha256"]), "split"] = "excluded"
    meta = ingest.freeze(df, out_dir, seed=args.seed, extra={
        "cohort_tag": "v4", "prior_cohorts": list(PRIOR_TAGS) + ["v3.3_temporal"],
        "malware_min_batch_date": args.min_date, "benign_roots": list(BENIGN_ROOT_CAPS),
        "per_dir_cap": PER_DIR_CAP,
    })
    print(meta["counts"], meta["groups"])
    b = df[df["split"] == "blind"]
    extract_manifest(list(zip(b["path"], b["sha256"])), art / "v4" / "features" / "pe_features_v3_new.parquet", workers=args.workers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
