"""Sample a new labeled cohort from local sources, then ingest via src.v3.ingest.

  python -m src.v3.new_cohort --cohort-tag v3.1 --prior-cohorts v3 --pe64-malicious-frac 0.5
"""

from __future__ import annotations

import argparse
import random
from collections import defaultdict
from pathlib import Path

import pandas as pd

from src.common.config import artifacts, load_config
from src.common.pe_utils import malware_path
from src.v3 import ingest

BENIGN_ROOTS = (
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
)
PE_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"}
PER_VENDOR_CAP = 40


def _all_benign_roots(cfg: dict) -> list[str]:
    extra = [str(p) for p in (cfg.get("paths") or {}).get("benign_roots") or []]
    seen: set[str] = set()
    out: list[str] = []
    for r in extra + list(BENIGN_ROOTS):
        key = r.lower()
        if key not in seen:
            out.append(r)
            seen.add(key)
    return out


def _benign_dir_key(path: Path, root: Path) -> str:
    rel = path.relative_to(root)
    parent = rel.parent.as_posix().lower() if rel.parent.parts else "."
    return f"{root.resolve()}|{parent}"


def used_benign_dir_keys(art: Path, prior_tags: tuple[str, ...], cfg: dict) -> set[str]:
    keys: set[str] = set()
    roots = [Path(r) for r in _all_benign_roots(cfg)]

    def add_path(path_str: str) -> None:
        p = Path(path_str)
        for root in roots:
            try:
                keys.add(_benign_dir_key(p, root))
            except ValueError:
                continue

    inv = pd.read_parquet(art / "manifests" / "corpus_inventory.parquet")
    for p in inv["relative_path"].astype(str):
        add_path(p)
    for tag in prior_tags:
        prev_p = art / tag / "manifests" / "new_corpus_inventory.parquet"
        if prev_p.is_file():
            for p in pd.read_parquet(prev_p)["path"].astype(str):
                add_path(p)
    return keys


def _benign_candidates(max_bytes: int, roots: list[str]) -> dict[str, list[Path]]:
    by_vendor: dict[str, list[Path]] = defaultdict(list)
    for root in roots:
        base = Path(root)
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            try:
                if p.suffix.lower() not in PE_SUFFIXES or not p.is_file() or p.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            parts = p.relative_to(base).parts
            vendor = parts[0] if len(parts) > 1 else "."
            by_vendor[f"{root}|{vendor}"].append(p)
    return by_vendor


def sample_benign(
    n: int,
    max_bytes: int,
    seed: int,
    exclude_paths: set[str],
    *,
    roots: list[str],
    used_dir_keys: set[str] | None = None,
    vendor_skip: int = 0,
    vendor_cap: int = PER_VENDOR_CAP,
) -> list[dict]:
    rng = random.Random(seed)
    by_vendor = _benign_candidates(max_bytes, roots)
    unseen_pools: list[tuple[str, list[Path]]] = []
    seen_pools: list[tuple[str, list[Path]]] = []
    for key in sorted(by_vendor):
        root_path = Path(key.split("|")[0])
        files = [p for p in by_vendor[key] if str(p).lower() not in exclude_paths]
        rng.shuffle(files)
        files = files[vendor_skip : vendor_skip + vendor_cap]
        if used_dir_keys:
            u, s = [], []
            for p in files:
                (u if _benign_dir_key(p, root_path) not in used_dir_keys else s).append(p)
            if u:
                unseen_pools.append((key, u))
            if s:
                seen_pools.append((key, s))
        else:
            seen_pools.append((key, files))
    pools = unseen_pools + seen_pools
    rng.shuffle(pools)
    out: list[dict] = []
    idx = [0] * len(pools)
    while len(out) < n:
        progressed = False
        for i, (key, files) in enumerate(pools):
            if len(out) >= n:
                break
            if idx[i] < len(files):
                root = key.split("|")[0]
                src = "benign_windows_os" if "\\windows\\" in root.lower() else "benign_third_party"
                out.append({"path": str(files[idx[i]]), "label": "benign", "source": src})
                idx[i] += 1
                progressed = True
        if not progressed:
            break
    return out


def sample_malicious(
    cfg: dict, n: int, seed: int, exclude_sha: set[str], *, pe64_fraction: float = 0.0,
) -> list[dict]:
    m = pd.read_csv(cfg["paths"]["malware_analysis_csv"], usecols=["sha256", "rel_path", "ext", "die_filetype"])
    m = m[~m["sha256"].isin(exclude_sha)]
    m = m[m["ext"].fillna("").str.lower().str.lstrip(".").isin({s.lstrip(".") for s in PE_SUFFIXES} | {""})]
    corpus = Path(cfg["paths"]["malware_corpus"])
    pe64 = m[m["die_filetype"].astype(str).str.upper() == "PE64"]
    pe32 = m[m["die_filetype"].astype(str).str.upper() != "PE64"]
    n64 = int(round(n * pe64_fraction)) if pe64_fraction > 0 else 0
    n32 = n - n64
    rng = random.Random(seed)

    def take(frame: pd.DataFrame, k: int) -> list[dict]:
        frame = frame.sample(frac=1.0, random_state=seed + hash(frame.shape[0]) % 997).reset_index(drop=True)
        out: list[dict] = []
        for r in frame.itertuples(index=False):
            if len(out) >= k:
                break
            p = malware_path(corpus, str(r.rel_path))
            if p.is_file():
                out.append({"path": str(p), "label": "malicious", "source": "malwarebazaar"})
        return out

    rows = take(pe64, n64) + take(pe32, n32)
    rng.shuffle(rows)
    return rows[:n]


def excluded_sha_and_paths(art: Path, prior_tags: tuple[str, ...]) -> tuple[set[str], set[str]]:
    inv = pd.read_parquet(art / "manifests" / "corpus_inventory.parquet")
    sha = set(inv["sha256"])
    paths = {str(p).lower() for p in inv["relative_path"]}
    for tag in prior_tags:
        p = art / tag / "manifests" / "new_corpus_inventory.parquet"
        if p.is_file():
            prev = pd.read_parquet(p)
            sha |= set(prev["sha256"])
            paths |= {str(x).lower() for x in prev["path"]}
    return sha, paths


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--n-benign", type=int, default=1200)
    ap.add_argument("--n-malicious", type=int, default=1200)
    ap.add_argument("--seed", type=int, default=20261101)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--cohort-tag", default="v3")
    ap.add_argument("--prior-cohorts", default="", help="Comma-separated tags (e.g. v3)")
    ap.add_argument("--pe64-malicious-frac", type=float, default=0.0)
    ap.add_argument("--benign-vendor-skip", type=int, default=0, help="Skip first N files per vendor bucket (v3.2 default: 40)")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    art = artifacts(cfg)
    prior = tuple(t.strip() for t in args.prior_cohorts.split(",") if t.strip())
    ex_sha, ex_paths = excluded_sha_and_paths(art, prior)
    max_bytes = int(float(cfg.get("analysis", {}).get("max_file_size_mb", 50)) * 1024 * 1024)
    roots = _all_benign_roots(cfg)
    dir_keys = used_benign_dir_keys(art, prior, cfg) if args.cohort_tag == "v3.2" else None
    skip = args.benign_vendor_skip if args.benign_vendor_skip else (40 if args.cohort_tag == "v3.2" else 0)
    rows = sample_benign(
        args.n_benign, max_bytes, args.seed, ex_paths, roots=roots,
        used_dir_keys=dir_keys, vendor_skip=skip, vendor_cap=80 if args.cohort_tag == "v3.2" else PER_VENDOR_CAP,
    )
    rows += sample_malicious(cfg, args.n_malicious, args.seed, ex_sha, pe64_fraction=args.pe64_malicious_frac)
    out_dir = art / args.cohort_tag / "manifests"
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = out_dir / "new_cohort_labels.csv"
    pd.DataFrame(rows).to_csv(manifest, index=False)
    print(f"Wrote {manifest}: {len(rows)} rows (pe64_frac={args.pe64_malicious_frac})")
    prior_arg = ",".join(prior)
    return ingest.main([
        "--config", args.config, "--manifest", str(manifest), "--seed", str(args.seed),
        "--workers", str(args.workers), "--cohort-tag", args.cohort_tag,
        *(["--prior-cohorts", prior_arg] if prior_arg else []),
    ])


if __name__ == "__main__":
    raise SystemExit(main())
