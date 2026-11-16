"""V7 Binary Ninja extraction queues: 700 training-pool files plus the frozen blind cohort.

Training files are a seeded random sample of the V4 Binary Ninja training subset (pool files with
known paths), drawn without reference to any model score. Blind files are listed last.

  python -m src.v7.queues
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

SEED = 20261104
N_TRAIN = 700
OUT = Path("artifacts/v7/manifests/bn_queue.csv")


def main() -> int:
    v4 = pd.read_csv("artifacts/v4/manifests/bn_queue.csv")
    gate = set(pd.read_csv("artifacts/v6/manifests/gate_queue.csv")["sha256"])
    tr = v4[(v4.role == "train") & ~v4.sha256.isin(gate)].sample(n=N_TRAIN, random_state=SEED)[["sha256", "path"]]
    split = pd.read_parquet("artifacts/v7/manifests/new_split_assignments.parquet")
    inv = pd.read_parquet("artifacts/v7/manifests/new_corpus_inventory.parquet")[["sha256", "path"]]
    bl = split[split.split == "blind"][["sha256"]].merge(inv, on="sha256")
    q = pd.concat([tr.assign(role="train"), bl.assign(role="blind")], ignore_index=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    q.to_csv(OUT, index=False)
    print(q.role.value_counts().to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
