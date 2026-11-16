"""One-shot V3 blind evaluation of the frozen candidate (pe_v3) against the frozen baseline (pe_v1s).

  python -m src.v3.blind --run

Refuses to run if the freeze manifest does not verify or the run-once lock exists.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pickle
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from src.common.config import artifacts, load_config
from src.metrics import tpr_at_fpr
from src.v3 import freeze
from src.v3.cohorts import train_cohorts_for_tag as _train_cohorts
from src.v3.data import load_pool
from src.v3.stats import paired_group_bootstrap_fixed, rates_at_threshold

MIN_GAIN = 0.02


def _load_model(layout: dict[str, Any], name: str) -> dict[str, Any]:
    with layout["models"][name].open("rb") as fh:
        return pickle.load(fh)


def _row_hash(df: pd.DataFrame, cols: list[str]) -> pd.Series:
    vals = df[cols].astype(float).round(6).fillna(-999).to_numpy()
    return pd.Series([hashlib.md5(r.tobytes()).hexdigest() for r in vals], index=df.index)


def disjointness(blind: pd.DataFrame, train_pool: pd.DataFrame, art: Path, cols: list[str]) -> dict[str, Any]:
    v1_inv = pd.read_parquet(art / "manifests" / "corpus_inventory.parquet")
    v1_imp = pd.read_parquet(art / "v3" / "manifests" / "v1_imphash.parquet")
    train_imp = set(v1_imp["imphash"].astype(str)) | set(train_pool.get("imphash", pd.Series(dtype=str)).dropna().astype(str))
    train_imp.discard("")
    blind_imp = blind["imphash"].fillna("").astype(str)
    dup_vec = _row_hash(blind, cols).isin(set(_row_hash(train_pool, cols)))
    return {
        "sha_overlap_v1_all_splits": int(blind["sha256"].isin(set(v1_inv["sha256"])).sum()),
        "sha_overlap_training_pool": int(blind["sha256"].isin(set(train_pool["sha256"])).sum()),
        "group_overlap_training_pool": int(blind["group_id"].isin(set(train_pool["group_id"])).sum()),
        "group_overlap_v1_all_splits": int(blind["group_id"].isin(set(v1_inv["group_id"].astype(str))).sum()),
        "imphash_overlap_training": int((blind_imp.ne("") & blind_imp.isin(train_imp)).sum()),
        "identical_pe_v3_vector_in_training": int(dup_vec.sum()),
        "_dup_mask": dup_vec.to_numpy(),
    }


def _arm(y: np.ndarray, p: np.ndarray, thr: float) -> dict[str, Any]:
    return {
        "threshold": thr,
        "fixed": rates_at_threshold(y, p, thr),
        "roc_auc": float(roc_auc_score(y, p)),
        "pr_auc": float(average_precision_score(y, p)),
    }


def error_breakdown(blind: pd.DataFrame, pred: np.ndarray, cfg: dict, *, cohort_tag: str) -> dict[str, Any]:
    b = blind.assign(pred=pred)
    mal = b[b["label"] == 1].copy()
    meta = pd.read_csv(cfg["paths"]["malware_analysis_csv"], usecols=["sha256", "die_filetype", "die_packer", "die_compiler"])
    mal = mal.merge(meta, on="sha256", how="left")
    mal["packed"] = mal["die_packer"].notna() & mal["die_packer"].astype(str).str.strip().ne("")
    mal["size_bucket"] = pd.cut(mal["pe3_file_size"] if "pe3_file_size" in mal else mal["pe1s_file_size"],
                                [0, 100e3, 1e6, 10e6, np.inf], labels=["<100KB", "100KB-1MB", "1-10MB", ">10MB"])

    def tab(df: pd.DataFrame, col: str, top: int = 10) -> list[dict]:
        g = df.groupby(col, observed=True).agg(n=("pred", "size"), detected=("pred", "sum"))
        g["tpr"] = g["detected"] / g["n"]
        return g.sort_values("n", ascending=False).head(top).reset_index().astype({col: str}).to_dict("records")

    ben = b[b["label"] == 0].copy()
    inv = pd.read_parquet(Path(cfg["paths"]["artifacts_dir"]) / cohort_tag / "manifests" / "new_corpus_inventory.parquet")[["sha256", "path"]]
    ben = ben.merge(inv, on="sha256", how="left")
    fps = ben[ben["pred"] == 1]
    return {
        "fn_by_filetype": tab(mal, "die_filetype"),
        "fn_by_packed": tab(mal, "packed"),
        "fn_by_size": tab(mal, "size_bucket"),
        "fn_by_compiler": tab(mal, "die_compiler"),
        "fp_by_source": tab(ben, "source"),
        "false_positive_paths": sorted(fps["path"].astype(str).tolist()),
    }


def run(config: str, *, cohort_tag: str = "v3") -> dict[str, Any]:
    layout = freeze.cohort_layout(cohort_tag)
    out_dir = Path(f"artifacts/{cohort_tag}/blind")
    lock = out_dir / "blind_run.lock"
    bad = freeze.verify(layout["freeze_path"], tag=cohort_tag)
    if bad:
        raise SystemExit(f"Freeze verification failed: {bad}")
    if lock.exists():
        raise SystemExit(f"{lock} exists: the blind evaluation has already been run")
    out_dir.mkdir(parents=True, exist_ok=True)
    lock.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")

    cfg = load_config(config)
    art = artifacts(cfg)
    cand, base = _load_model(layout, "pe_v3"), _load_model(layout, "pe_v1s")
    blind = load_pool(config, include_v1_train=False, cohorts=[(cohort_tag, ("blind",))])
    train_pool = load_pool(config, include_v1_train=True, cohorts=_train_cohorts(cohort_tag))
    if set(train_pool["sha256"]) != set(cand["training_pool_sha256"]):
        raise SystemExit("Training pool differs from the frozen model's training pool")

    checks = disjointness(blind, train_pool, art, cand["cols"])
    dup_mask = checks.pop("_dup_mask")
    y = blind["label"].to_numpy()
    groups = blind["group_id"].astype(str).to_numpy()
    p_c = cand["model"].predict_proba(blind[cand["cols"]])[:, 1]
    p_b = base["model"].predict_proba(blind[base["cols"]])[:, 1]

    matched: dict[str, Any] = {}
    for fpr in (0.005, 0.01):
        ba = tpr_at_fpr(y, p_b, fpr)
        ca = tpr_at_fpr(y, p_c, fpr)
        matched[f"fpr_{fpr:.3f}"] = {
            "baseline_tpr": float(ba["tpr"]), "candidate_tpr": float(ca["tpr"]),
            "delta_candidate_minus_baseline": float(ca["tpr"] - ba["tpr"]),
            "note": "Descriptive only: thresholds re-picked on blind rows.",
        }

    res: dict[str, Any] = {
        "cohort_tag": cohort_tag,
        "run_at": datetime.now(timezone.utc).isoformat(),
        "freeze_manifest_sha256": freeze.sha256_path(layout["freeze_path"]),
        "matched_fpr_descriptive": matched,
        "n_blind": int(len(blind)), "n_benign": int((y == 0).sum()), "n_malicious": int((y == 1).sum()),
        "n_groups": int(len(np.unique(groups))),
        "disjointness": checks,
        "candidate_pe_v3": _arm(y, p_c, cand["threshold"]),
        "baseline_pe_v1s": _arm(y, p_b, base["threshold"]),
        "paired_candidate_minus_baseline": paired_group_bootstrap_fixed(y, p_b, base["threshold"], p_c, cand["threshold"], groups),
    }
    keep = ~dup_mask
    if dup_mask.any():
        res["sensitivity_excluding_identical_vectors"] = {
            "n": int(keep.sum()),
            "candidate": rates_at_threshold(y[keep], p_c[keep], cand["threshold"]),
            "baseline": rates_at_threshold(y[keep], p_b[keep], base["threshold"]),
        }
    pr = res["paired_candidate_minus_baseline"]
    c, bl = res["candidate_pe_v3"]["fixed"], res["baseline_pe_v1s"]["fixed"]
    res["decision"] = {
        "tpr_gain": pr["delta_tpr_b_minus_a"],
        "gain_ge_min": pr["delta_tpr_b_minus_a"] >= MIN_GAIN,
        "ci_lower_gt_0": pr["delta_tpr_ci95"][0] > 0,
        "fpr_not_higher": c["fpr"] <= bl["fpr"],
    }
    res["decision"]["improvement_supported"] = all(res["decision"][k] for k in ("gain_ge_min", "ci_lower_gt_0", "fpr_not_higher"))
    res["errors_candidate"] = error_breakdown(blind, (p_c >= cand["threshold"]).astype(int), cfg, cohort_tag=cohort_tag)
    res["errors_baseline"] = error_breakdown(blind, (p_b >= base["threshold"]).astype(int), cfg, cohort_tag=cohort_tag)
    res["sota_claim_supported"] = False
    (out_dir / "blind_results.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    pd.DataFrame({"sha256": blind["sha256"], "label": y, "group_id": groups, "score_pe_v3": p_c, "score_pe_v1s": p_b}).to_parquet(out_dir / "blind_scores.parquet", index=False)
    return res


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--run", action="store_true", help="Required: acknowledges this is the single blind run")
    ap.add_argument("--cohort-tag", default="v3")
    args = ap.parse_args(argv)
    if not args.run:
        ap.error("pass --run to perform the single blind evaluation")
    r = run(args.config, cohort_tag=args.cohort_tag)
    print(json.dumps({k: r[k] for k in ("n_blind", "n_benign", "n_malicious", "disjointness", "decision")}, indent=2))
    for arm in ("candidate_pe_v3", "baseline_pe_v1s"):
        f = r[arm]["fixed"]
        print(f"{arm}: TPR {f['tpr']:.3f} {f['tpr_ci95']}  FPR {f['fpr']:.4f} ({f['fp']}/{f['n_benign']}) {f['fpr_ci95']}  "
              f"ROC-AUC {r[arm]['roc_auc']:.4f}  PR-AUC {r[arm]['pr_auc']:.4f}")
    print("paired:", json.dumps(r["paired_candidate_minus_baseline"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
