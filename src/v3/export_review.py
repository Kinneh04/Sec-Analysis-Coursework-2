"""Export blind false positives / false negatives for analyst review."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from src.v3.data import load_pool


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cohort-tag", default="v3.2")
    ap.add_argument("--config", default="configs/local.yaml")
    args = ap.parse_args(argv)

    tag = args.cohort_tag
    root = Path(f"artifacts/{tag}/blind")
    scores = pd.read_parquet(root / "blind_scores.parquet")
    blind = load_pool(args.config, include_v1_train=False, cohorts=[(tag, ("blind",))])
    inv = pd.read_parquet(Path(f"artifacts/{tag}/manifests/new_corpus_inventory.parquet"))[["sha256", "path", "label", "source"]]
    df = scores.merge(inv, on="sha256", how="left")
    df = df.merge(blind[["sha256", "group_id", "label"]], on="sha256", how="left", suffixes=("", "_bl"))
    if "label_bl" in df.columns:
        df["label"] = df["label_bl"].fillna(df.get("label"))
        df = df.drop(columns=["label_bl"], errors="ignore")
    res = json.loads((root / "blind_results.json").read_text(encoding="utf-8"))
    thr_v3 = res["candidate_pe_v3"]["threshold"]
    thr_v1 = res["baseline_pe_v1s"]["threshold"]

    df["pred_v3"] = df["score_pe_v3"] >= thr_v3
    df["pred_v1s"] = df["score_pe_v1s"] >= thr_v1
    df["label_name"] = df["label"].map({0: "benign", 1: "malicious"})

    rows = []
    fp = fn = None
    for arm, pred in (("pe_v3", "pred_v3"), ("pe_v1s", "pred_v1s")):
        fp = df[(df["label"] == 0) & df[pred]]
        fn = df[(df["label"] == 1) & ~df[pred]]
        for kind, part in (("false_positive", fp), ("false_negative", fn)):
            for r in part.itertuples(index=False):
                rows.append({
                    "arm": arm, "kind": kind, "sha256": r.sha256, "path": r.path,
                    "source": r.source, "group_id": r.group_id,
                    "score": getattr(r, "score_pe_v3" if arm == "pe_v3" else "score_pe_v1s"),
                })
    out = root / "analyst_review.csv"
    pd.DataFrame(rows).sort_values(["arm", "kind", "path"]).to_csv(out, index=False)
    print(f"Wrote {out} ({len(rows)} rows; v3 FP={len(fp)} FN={len(fn)} on pe_v3 arm)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
