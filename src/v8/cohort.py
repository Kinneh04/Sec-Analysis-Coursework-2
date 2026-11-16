"""Build and freeze the V8 blind cohort (docs/v8_preregistration.md). Read-only; nothing is executed.

  python -m src.v8.cohort --n-benign 450 --n-malicious 450
"""

from __future__ import annotations

import argparse

import pandas as pd

from src.common.config import artifacts, load_config
from src.v3 import ingest
from src.v3.new_cohort import excluded_sha_and_paths
from src.v3.temporal_eval import sample_temporal_malware
from src.v4 import cohort as v4_cohort
from src.v4.cohort import PER_DIR_CAP, temporal_reference

PRIOR_TAGS = ("v3", "v3.1", "v3.2", "v4", "v7")
BENIGN_ROOT_CAPS = {
    r"C:\Program Files": 500,
    r"C:\Program Files (x86)": 450,
    r"C:\Windows\System32\DriverStore": 250,
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--n-benign", type=int, default=450)
    ap.add_argument("--n-malicious", type=int, default=450)
    ap.add_argument("--min-date", default="2026-01-01")
    ap.add_argument("--seed", type=int, default=20261106)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    art = artifacts(cfg)
    out_dir = art / "v8" / "manifests"
    if (out_dir / "new_corpus_freeze.json").exists():
        print("V8 cohort already frozen")
        return 1
    ex_sha, ex_paths = excluded_sha_and_paths(art, PRIOR_TAGS)
    t_sha, t_imp = temporal_reference(art)
    ex_sha |= t_sha
    gate = pd.read_csv(art / "v6" / "manifests" / "gate_queue.csv")
    v7q = pd.read_csv(art / "v7" / "manifests" / "bn_queue.csv")
    ex_sha |= set(gate["sha256"]) | set(v7q["sha256"])
    ex_paths |= {str(p).lower() for p in pd.concat([gate["path"], v7q["path"]])}

    v4_cohort.BENIGN_ROOT_CAPS.clear()
    v4_cohort.BENIGN_ROOT_CAPS.update(BENIGN_ROOT_CAPS)
    benign = v4_cohort.sample_benign_new_roots(args.seed, ex_paths)
    for b in benign:
        b["source"] = b["source"].replace("benign_v4:", "benign_v8:")
    malware = sample_temporal_malware(cfg, args.n_malicious * 6, args.min_date, ex_sha, args.seed)
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
        "cohort_tag": "v8", "prior_cohorts": list(PRIOR_TAGS) + ["v3.3_temporal", "v6_gate"],
        "malware_min_batch_date": args.min_date, "benign_roots": list(BENIGN_ROOT_CAPS), "per_dir_cap": PER_DIR_CAP,
    })
    print(meta["counts"], meta["groups"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
