"""Build and freeze the V9 replication cohort (docs/v9_preregistration.md). Read-only; nothing is executed.

  python -m src.v9.cohort --n-benign 1000 --n-malicious 600
"""

from __future__ import annotations

import argparse
import os

import pandas as pd

from src.common.config import artifacts, load_config
from src.v3 import ingest
from src.v3.new_cohort import excluded_sha_and_paths
from src.v3.temporal_eval import sample_temporal_malware
from src.v4 import cohort as v4_cohort
from src.v4.cohort import PER_DIR_CAP, temporal_reference

PRIOR_TAGS = ("v3", "v3.1", "v3.2", "v4", "v7", "v8")
COMPONENT_ROOTS = {
    r"C:\Windows\WinSxS": 900,
    r"C:\Windows\Microsoft.NET": 250,
    r"C:\Windows\assembly": 300,
    r"C:\Windows\SystemApps": 40,
    r"C:\ProgramData": 15,
    os.path.expandvars(r"%LOCALAPPDATA%\Programs"): 30,
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft"): 50,
}
APPLICATION_ROOTS = {
    r"C:\Program Files": 1200,
    r"C:\Program Files (x86)": 900,
    r"C:\Windows\System32\DriverStore": 200,
}


def family(path: str) -> str:
    p = path.lower()
    return "applications" if any(p.startswith(r.lower()) for r in APPLICATION_ROOTS) else "components"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--n-benign", type=int, default=1000)
    ap.add_argument("--n-malicious", type=int, default=600)
    ap.add_argument("--min-date", default="2026-01-01")
    ap.add_argument("--seed", type=int, default=20261107)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    art = artifacts(cfg)
    out_dir = art / "v9" / "manifests"
    if (out_dir / "new_corpus_freeze.json").exists():
        print("V9 cohort already frozen")
        return 1
    ex_sha, ex_paths = excluded_sha_and_paths(art, PRIOR_TAGS)
    t_sha, t_imp = temporal_reference(art)
    ex_sha |= t_sha
    extra = [pd.read_csv(art / p) for p in ("v6/manifests/gate_queue.csv", "v7/manifests/bn_queue.csv", "v8/manifests/bn_queue.csv")]
    for q in extra:
        ex_sha |= set(q["sha256"])
        ex_paths |= {str(p).lower() for p in q["path"]}

    v4_cohort.BENIGN_ROOT_CAPS.clear()
    v4_cohort.BENIGN_ROOT_CAPS.update({**COMPONENT_ROOTS, **APPLICATION_ROOTS})
    benign = v4_cohort.sample_benign_new_roots(args.seed, ex_paths)
    for b in benign:
        b["source"] = f"benign_v9:{family(b['path'])}"
    malware = sample_temporal_malware(cfg, args.n_malicious * 10, args.min_date, ex_sha, args.seed)
    labels = out_dir / "new_cohort_labels.csv"
    out_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(benign + [{k: r[k] for k in ("path", "label", "source")} for r in malware]).to_csv(labels, index=False)

    rows = ingest.collect_rows(labels, [], [], float(cfg.get("analysis", {}).get("max_file_size_mb", 50)))
    ref = ingest.v1_reference(art, prior_cohort_tags=PRIOR_TAGS)
    ref["sha256"] |= ex_sha
    ref["imphash"] |= t_imp
    df = ingest.assign_split(rows, ref, seed=args.seed, blind_fraction=1.0)
    df = df[df["split"] == "blind"].copy()
    keep = pd.concat([
        df[df["label"] == "benign"].sample(frac=1.0, random_state=args.seed).head(args.n_benign),
        df[df["label"] == "malicious"].sample(frac=1.0, random_state=args.seed).head(args.n_malicious),
    ])
    df["split"] = "excluded"
    df.loc[df["sha256"].isin(keep["sha256"]), "split"] = "blind"
    df = df.sort_values("sha256").reset_index(drop=True)
    meta = ingest.freeze(df, out_dir, seed=args.seed, extra={
        "cohort_tag": "v9", "prior_cohorts": list(PRIOR_TAGS) + ["v3.3_temporal", "v6_gate"],
        "malware_min_batch_date": args.min_date, "benign_roots": list(COMPONENT_ROOTS) + list(APPLICATION_ROOTS),
        "per_dir_cap": PER_DIR_CAP,
    })
    print(meta["counts"], meta["groups"])
    b = df[df["split"] == "blind"]
    print(b[b["label"] == "benign"]["source"].value_counts().to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
