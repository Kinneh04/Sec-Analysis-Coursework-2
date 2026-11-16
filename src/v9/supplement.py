"""Freeze the V9s malware-only supplement (docs/v9_preregistration.md, amendment A1).

  python -m src.v9.supplement --n-malicious 400
"""

from __future__ import annotations

import argparse

import pandas as pd

from src.common.config import artifacts, load_config
from src.v3 import ingest
from src.v3.new_cohort import excluded_sha_and_paths
from src.v3.temporal_eval import sample_temporal_malware
from src.v4.cohort import temporal_reference

PRIOR_TAGS = ("v3", "v3.1", "v3.2", "v4", "v7", "v8", "v9")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--n-malicious", type=int, default=400)
    ap.add_argument("--seed", type=int, default=20261108)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    art = artifacts(cfg)
    out_dir = art / "v9s" / "manifests"
    if (out_dir / "new_corpus_freeze.json").exists():
        print("V9s supplement already frozen")
        return 1
    ex_sha, _ = excluded_sha_and_paths(art, PRIOR_TAGS)
    t_sha, t_imp = temporal_reference(art)
    ex_sha |= t_sha
    for p in ("v6/manifests/gate_queue.csv", "v7/manifests/bn_queue.csv", "v8/manifests/bn_queue.csv"):
        ex_sha |= set(pd.read_csv(art / p)["sha256"])
    malware = [r for r in sample_temporal_malware(cfg, 100000, "2025-01-01", ex_sha, args.seed) if r["batch_date"] < "2026-01-01"]
    malware = malware[: args.n_malicious * 8]
    labels = out_dir / "new_cohort_labels.csv"
    out_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([{k: r[k] for k in ("path", "label", "source")} for r in malware]).to_csv(labels, index=False)
    rows = ingest.collect_rows(labels, [], [], float(cfg.get("analysis", {}).get("max_file_size_mb", 50)))
    ref = ingest.v1_reference(art, prior_cohort_tags=PRIOR_TAGS)
    ref["sha256"] |= ex_sha
    ref["imphash"] |= t_imp
    df = ingest.assign_split(rows, ref, seed=args.seed, blind_fraction=1.0)
    df = df[df["split"] == "blind"].copy()
    keep = df.sample(frac=1.0, random_state=args.seed).head(args.n_malicious)
    df["split"] = "excluded"
    df.loc[df["sha256"].isin(keep["sha256"]), "split"] = "blind"
    df = df.sort_values("sha256").reset_index(drop=True)
    meta = ingest.freeze(df, out_dir, seed=args.seed, extra={"cohort_tag": "v9s", "prior_cohorts": list(PRIOR_TAGS) + ["v3.3_temporal", "v6_gate"],
                                                              "malware_batch_range": ["2025-01-01", "2025-12-31"]})
    print(meta["counts"], meta["groups"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
