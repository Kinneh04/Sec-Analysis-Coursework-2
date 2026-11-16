"""Temporal holdout: score unused MalwareBazaar batches with frozen models (no retraining).

Uses malware with batch_date on or after --min-date and benign files not in any prior cohort.
This is a supplementary generalization check, not a replacement for the preregistered blind lock.

  python -m src.v3.temporal_eval --model-tag v3.2 --min-date 2026-01-01
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from src.common.config import artifacts, load_config
from src.common.hashing import sha256_file
from src.common.pe_utils import malware_path
from src.metrics import tpr_at_fpr
from src.v3.new_cohort import (
    PE_SUFFIXES,
    _all_benign_roots,
    excluded_sha_and_paths,
    sample_benign,
    used_benign_dir_keys,
)
from src.v3.pe_features_v3 import extract_manifest
from src.v3.pe_v1_stable import extract_pe_v1_stable
from src.v3.score import load_bundle, score_row
from src.v3.stats import paired_group_bootstrap_fixed, rates_at_threshold


def _used_sha(art: Path) -> set[str]:
    sha, _ = excluded_sha_and_paths(art, ("v3", "v3.1", "v3.2"))
    return sha


def sample_temporal_malware(cfg: dict, n: int, min_date: str, exclude_sha: set[str], seed: int) -> list[dict]:
    m = pd.read_csv(
        cfg["paths"]["malware_analysis_csv"],
        usecols=["sha256", "rel_path", "ext", "batch_date", "die_filetype", "imphash"],
    )
    m = m[~m["sha256"].isin(exclude_sha)]
    m = m[m["batch_date"].astype(str) >= min_date]
    m = m[m["ext"].fillna("").str.lower().str.lstrip(".").isin({s.lstrip(".") for s in PE_SUFFIXES} | {""})]
    m = m.sort_values("batch_date", ascending=False).drop_duplicates("sha256")
    m = m.sample(frac=1.0, random_state=seed)
    corpus = Path(cfg["paths"]["malware_corpus"])
    out: list[dict] = []
    for r in m.itertuples(index=False):
        if len(out) >= n:
            break
        p = malware_path(corpus, str(r.rel_path))
        if not p.is_file():
            continue
        out.append({
            "path": str(p), "label": "malicious", "source": f"malwarebazaar:{r.batch_date}",
            "sha256": str(r.sha256), "batch_date": str(r.batch_date), "imphash": str(r.imphash or ""),
        })
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--model-tag", default="v3.2")
    ap.add_argument("--min-date", default="2026-01-01")
    ap.add_argument("--n-malicious", type=int, default=450)
    ap.add_argument("--n-benign", type=int, default=250)
    ap.add_argument("--seed", type=int, default=20261104)
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    art = artifacts(cfg)
    out_dir = art / "v3.3" / "temporal_eval"
    out_dir.mkdir(parents=True, exist_ok=True)
    lock = out_dir / "temporal_eval.lock"
    if lock.exists():
        print(f"{lock} exists; delete to re-run")
        return 1

    ex_sha, ex_paths = excluded_sha_and_paths(art, ("v3", "v3.1", "v3.2"))
    max_bytes = int(float(cfg.get("analysis", {}).get("max_file_size_mb", 50)) * 1024 * 1024)
    roots = _all_benign_roots(cfg)
    dir_keys = used_benign_dir_keys(art, ("v3", "v3.1", "v3.2"), cfg)
    mal = sample_temporal_malware(cfg, args.n_malicious, args.min_date, ex_sha, args.seed)
    ben = sample_benign(
        args.n_benign, max_bytes, args.seed + 1, ex_paths, roots=roots,
        used_dir_keys=dir_keys, vendor_skip=80, vendor_cap=100,
    )
    for r in ben:
        r["batch_date"] = ""
        try:
            r["sha256"] = sha256_file(Path(r["path"]))
        except OSError:
            r["sha256"] = ""
    rows = list({r["sha256"]: r for r in mal + ben if r.get("sha256")}.values())
    manifest = out_dir / "manifest.csv"
    pd.DataFrame(rows).to_csv(manifest, index=False)

    pe3_path = out_dir / "pe_features_v3.parquet"
    extract_manifest([(r["path"], r["sha256"]) for r in rows], pe3_path, workers=args.workers)
    pe3 = pd.read_parquet(pe3_path)
    pe3 = pe3[pe3["v3_status"] == "ok"]

    v1s_rows = []
    for r in rows:
        if r["sha256"] not in set(pe3["sha256"]):
            continue
        v1 = extract_pe_v1_stable(Path(r["path"]))
        v1["sha256"] = r["sha256"]
        v1s_rows.append(v1)
    v1s = pd.DataFrame(v1s_rows)
    v1s = v1s[v1s["v1s_status"] == "ok"]
    meta = pd.DataFrame(rows)[["sha256", "path", "label", "source", "batch_date"]]
    meta["label"] = meta["label"].map({"benign": 0, "malicious": 1})
    frame = meta.merge(pe3, on="sha256").merge(v1s, on="sha256")

    bundle = load_bundle(args.model_tag, verify=False)
    scored = [score_row(r.to_dict(), bundle) for _, r in frame.iterrows()]
    scores = pd.DataFrame(scored)
    eval_df = frame.merge(scores[["sha256", "pe_v3_probability", "pe_v1s_probability", "pe_v3_flagged", "pe_v1s_flagged"]], on="sha256")

    y = eval_df["label"].to_numpy()
    groups = eval_df["sha256"].astype(str).to_numpy()  # file-level groups for bootstrap
    pc = eval_df["pe_v3_probability"].to_numpy()
    pb = eval_df["pe_v1s_probability"].to_numpy()
    thr_c = bundle["pe_v3"]["threshold"]
    thr_b = bundle["pe_v1s"]["threshold"]

    report = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "model_tag": args.model_tag,
        "min_malware_batch_date": args.min_date,
        "confirmatory": False,
        "note": "Frozen V3.2 thresholds; no retraining on this sample.",
        "n": int(len(eval_df)),
        "n_benign": int((y == 0).sum()),
        "n_malicious": int((y == 1).sum()),
        "batch_dates": eval_df[eval_df.label == 1]["batch_date"].value_counts().head(10).astype(int).to_dict(),
        "candidate_fixed": rates_at_threshold(y, pc, thr_c),
        "baseline_fixed": rates_at_threshold(y, pb, thr_b),
        "paired": paired_group_bootstrap_fixed(y, pb, thr_b, pc, thr_c, groups, seed=args.seed),
        "matched_fpr": {},
    }
    for fpr in (0.005, 0.01, 0.02):
        ba = tpr_at_fpr(y, pb, fpr)
        ca = tpr_at_fpr(y, pc, fpr)
        report["matched_fpr"][str(fpr)] = {"baseline_tpr": ba["tpr"], "candidate_tpr": ca["tpr"], "delta": ca["tpr"] - ba["tpr"]}

    (out_dir / "temporal_eval.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    eval_df.to_parquet(out_dir / "scored.parquet", index=False)
    lock.write_text(report["evaluated_at"], encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("n", "n_benign", "n_malicious", "candidate_fixed", "baseline_fixed", "paired")}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
