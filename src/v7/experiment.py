"""V7 experiment (docs/v7_preregistration.md): Binary Ninja capability + HLIL features vs EMBER2024.

  python -m src.v7.experiment select     # train-only candidate selection (C7a vs C7b)
  python -m src.v7.experiment freeze     # fit all arms, freeze thresholds and hashes
  python -m src.v7.experiment blind --run
"""

from __future__ import annotations

import argparse
import json
import pickle
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from src.metrics import tpr_at_fpr
from src.v3.cohorts import train_cohorts_for_tag
from src.v3.data import load_pool
from src.v3.search import fit_oof_threshold
from src.v3.stats import paired_group_bootstrap_fixed, rates_at_threshold
from src.v4.ember import ember_columns, pretrained_model
from src.v4.experiment import CFG_NAME, SEED, TARGET_FPR, TIE_TOL, _logit, _sha_file, fit_r2
from src.v6 import bn_capabilities, bn_hlil
from src.v6.evasion_strata import stratum, traits

CONFIG = "configs/local.yaml"
ROOT = Path("artifacts/v7")
PREREG = Path("docs/v7_preregistration.md")
USABLE = ("ok", "partial")


def _bn(shas: list[str]) -> pd.DataFrame:
    c = bn_capabilities.build(shas)
    h = bn_hlil.build(shas)
    df = c.merge(h, on="sha256")
    df.loc[~df["cap6_status"].isin(USABLE), bn_capabilities.cap6_columns(df)] = np.nan
    df.loc[~df["hl6_status"].isin(USABLE), bn_hlil.hl6_columns(df)] = np.nan
    return df


def training_frames() -> dict[str, Any]:
    pool = load_pool(CONFIG, include_v1_train=True, cohorts=train_cohorts_for_tag("v3.2"))[["sha256", "label", "group_id"]]
    gate = pd.read_csv("artifacts/v6/manifests/gate_queue.csv")[["sha256", "label", "group_id"]]
    pool = pd.concat([pool.assign(origin="v4_pool"), gate.assign(origin="v6_gate")], ignore_index=True).drop_duplicates("sha256")
    ember = pd.concat([pd.read_parquet("artifacts/v4/features/ember_v3.parquet"),
                       pd.read_parquet("artifacts/v3.3/temporal_eval/ember_v3.parquet")]).drop_duplicates("sha256")
    pool = pool.merge(ember, on="sha256")
    pool = pool[pool["em_status"] == "ok"].reset_index(drop=True)
    pool["r1_score"] = pretrained_model("PE").predict(pool[ember_columns()].to_numpy())
    pool["r1_logit"] = _logit(pool["r1_score"].to_numpy())
    pool = pool.merge(_bn(list(pool["sha256"])), on="sha256", how="left")
    mask = pool["cap6_status"].isin(USABLE).to_numpy()
    return {"pool": pool, "bn_mask": mask,
            "bn_status_counts": {"cap6": pool["cap6_status"].value_counts().to_dict(), "hl6": pool["hl6_status"].value_counts().to_dict()}}


def candidate_columns(df: pd.DataFrame) -> dict[str, list[str]]:
    cap, hl = bn_capabilities.cap6_columns(df), bn_hlil.hl6_columns(df)
    return {"C7a": ["r1_logit"] + cap + hl, "C7b": ["r1_logit"] + cap}


def select() -> dict[str, Any]:
    fr = training_frames()
    pool, mask = fr["pool"], fr["bn_mask"]
    y = pool["label"].to_numpy()
    rows = {}
    for name, cols in candidate_columns(pool).items():
        f = fit_oof_threshold(pool, cols, CFG_NAME, SEED, TARGET_FPR)
        oof = f["oof_scores"]
        r = rates_at_threshold(y[mask], oof[mask], f["threshold"])
        rows[name] = {"oof_tpr": f["oof_rates"]["tpr"], "oof_fpr": f["oof_rates"]["fpr"], "oof_auc": float(roc_auc_score(y, oof)),
                      "n_features": len(cols), "bn_rows_tpr": r["tpr"], "bn_rows_fpr": r["fpr"]}
        print(f"  {name}: {rows[name]}", flush=True)
    r1 = pool["r1_score"].to_numpy()
    thr_r1 = float(tpr_at_fpr(y, r1, TARGET_FPR)["threshold"])
    best = max(rows, key=lambda k: rows[k]["oof_tpr"])
    tied = [k for k in rows if rows[k]["oof_tpr"] >= rows[best]["oof_tpr"] - TIE_TOL]
    selected = max(tied, key=lambda k: rows[k]["oof_auc"])
    out = {"n_pool": int(len(pool)), "n_bn_rows": int(mask.sum()), "bn_status_counts": fr["bn_status_counts"],
           "candidates": rows, "R1_pool_tpr_descriptive": rates_at_threshold(y, r1, thr_r1)["tpr"],
           "selected": selected, "preregistration_sha256": _sha_file(PREREG)}
    (ROOT / "development").mkdir(parents=True, exist_ok=True)
    (ROOT / "development" / "selection.json").write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    return out


def freeze() -> dict[str, Any]:
    fdir = ROOT / "freeze"
    manifest_path = fdir / "freeze_manifest.json"
    if manifest_path.exists():
        raise SystemExit(f"{manifest_path} exists")
    sel = json.loads((ROOT / "development" / "selection.json").read_text(encoding="utf-8"))["selected"]
    fr = training_frames()
    pool = fr["pool"]
    cols = candidate_columns(pool)[sel]
    cand = fit_oof_threshold(pool, cols, CFG_NAME, SEED, TARGET_FPR)
    cand.pop("oof_scores")
    r2 = fit_r2(pool)
    thr_r1 = float(tpr_at_fpr(pool["label"].to_numpy(), pool["r1_score"].to_numpy(), TARGET_FPR)["threshold"])
    models = ROOT / "models"
    models.mkdir(parents=True, exist_ok=True)
    bundle = {"candidate": {**cand, "name": sel, "training_sha256": sorted(pool["sha256"])},
              "R2": {**r2, "training_sha256": sorted(pool["sha256"])},
              "R1": {"threshold": thr_r1, "model_file": "EMBER2024_PE.model"}}
    for k, v in bundle.items():
        with (models / f"{k}.pkl").open("wb") as fh:
            pickle.dump(v, fh)
    fdir.mkdir(parents=True, exist_ok=True)
    tracked = [PREREG, ROOT / "manifests" / "new_split_assignments.parquet", ROOT / "manifests" / "new_corpus_freeze.json",
               ROOT / "manifests" / "bn_queue.csv", ROOT / "development" / "selection.json",
               *[models / f"{k}.pkl" for k in bundle], *sorted(Path("src/v7").glob("*.py")),
               Path("src/v6/bn_capabilities.py"), Path("src/v6/bn_hlil.py"), Path("src/v6/unpack.py")]
    meta = {"frozen_at": datetime.now(timezone.utc).isoformat(), "candidate": sel,
            "thresholds": {k: v["threshold"] for k, v in bundle.items()},
            "candidate_train_oof": cand["oof_rates"], "r2_train_oof": r2["oof_rates"],
            "files": {p.as_posix(): _sha_file(p) for p in tracked}}
    manifest_path.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
    return meta


def _verify() -> list[str]:
    meta = json.loads((ROOT / "freeze" / "freeze_manifest.json").read_text(encoding="utf-8"))
    return [f for f, d in meta["files"].items() if not Path(f).is_file() or _sha_file(Path(f)) != d]


def blind() -> dict[str, Any]:
    bad = _verify()
    if bad:
        raise SystemExit(f"freeze verification failed: {bad}")
    lock = ROOT / "blind" / "blind_run.lock"
    if lock.exists():
        raise SystemExit(f"{lock} exists: blind already run")
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")

    split = pd.read_parquet(ROOT / "manifests" / "new_split_assignments.parquet")
    b = split[split["split"] == "blind"].copy()
    b["label"] = b["label"].map({"benign": 0, "malicious": 1}).astype(int)
    inv = pd.read_parquet(ROOT / "manifests" / "new_corpus_inventory.parquet")[["sha256", "source", "path"]]
    b = b.merge(inv, on="sha256").merge(pd.read_parquet(ROOT / "features" / "ember_v3.parquet"), on="sha256", how="left")
    em_ok = b["em_status"] == "ok"
    dropped = int((~em_ok).sum())
    b = b[em_ok].reset_index(drop=True)
    b = b.merge(_bn(list(b["sha256"])), on="sha256", how="left")
    b["r1_score"] = pretrained_model("PE").predict(b[ember_columns()].to_numpy())
    b["r1_logit"] = _logit(b["r1_score"].to_numpy())
    b["stratum"] = [stratum(traits(p)) for p in b["path"]]

    arms = {k: pickle.load((ROOT / "models" / f"{k}.pkl").open("rb")) for k in ("candidate", "R2", "R1")}
    cand = arms["candidate"]
    for c in cand["cols"]:
        if c not in b.columns:
            b[c] = np.nan
    scores = {"candidate": cand["model"].predict_proba(b[cand["cols"]])[:, 1],
              "R2": arms["R2"]["model"].predict(b[ember_columns()].to_numpy()),
              "R1": b["r1_score"].to_numpy()}
    y = b["label"].to_numpy()
    groups = b["group_id"].astype(str).to_numpy()
    bn_cov = b["cap6_status"].isin(USABLE).to_numpy()
    res: dict[str, Any] = {
        "run_at": datetime.now(timezone.utc).isoformat(), "candidate": cand["name"],
        "n": int(len(b)), "n_benign": int((y == 0).sum()), "n_malicious": int((y == 1).sum()),
        "n_groups": int(len(np.unique(groups))), "dropped_no_ember": dropped,
        "bn_coverage": {"cap6": {"benign": float(bn_cov[y == 0].mean()), "malicious": float(bn_cov[y == 1].mean())},
                        "hl6": {lab: float(b.loc[y == v, "hl6_status"].isin(USABLE).mean()) for lab, v in (("benign", 0), ("malicious", 1))}},
        "arms": {}, "paired": {}, "secondary": {},
    }
    for k, s in scores.items():
        thr = arms[k]["threshold"]
        res["arms"][k] = {"threshold": thr, "fixed": rates_at_threshold(y, s, thr), "roc_auc": float(roc_auc_score(y, s)),
                          "pr_auc": float(average_precision_score(y, s))}
    decision = {}
    for ref in ("R1", "R2"):
        pr = paired_group_bootstrap_fixed(y, scores[ref], arms[ref]["threshold"], scores["candidate"], cand["threshold"], groups, seed=SEED)
        res["paired"][f"candidate_minus_{ref}"] = pr
        decision[ref] = {"tpr_higher_ci_lower_gt_0": pr["delta_tpr_ci95"][0] > 0,
                         "fpr_not_higher": res["arms"]["candidate"]["fixed"]["fpr"] <= res["arms"][ref]["fixed"]["fpr"]}
        decision[ref]["beaten"] = all(decision[ref].values())
    res["decision"] = {**decision, "beats_ember2024": all(d["beaten"] for d in decision.values())}
    for name, m in (("ordinary_stratum", b["stratum"].to_numpy() == "ordinary"), ("bn_covered", bn_cov)):
        if (y[m] == 0).any() and (y[m] == 1).any():
            res["secondary"][name] = {k: {**rates_at_threshold(y[m], s[m], arms[k]["threshold"]), "n": int(m.sum())} for k, s in scores.items()}
    res["secondary"]["matched_fpr_tpr"] = {str(f): {k: float(tpr_at_fpr(y, s, f)["tpr"]) for k, s in scores.items()} for f in (0.005, 0.01)}
    res["sota_claim_supported"] = False
    (ROOT / "blind" / "blind_results.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    pd.DataFrame({"sha256": b["sha256"], "label": y, "group_id": groups, "source": b["source"], "path": b["path"], "stratum": b["stratum"],
                  "bn_covered": bn_cov, **{f"score_{k}": v for k, v in scores.items()}}).to_parquet(ROOT / "blind" / "blind_scores.parquet", index=False)
    return res


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["select", "freeze", "blind"])
    ap.add_argument("--run", action="store_true")
    args = ap.parse_args(argv)
    if args.command == "select":
        print(json.dumps(select(), indent=2, default=str))
    elif args.command == "freeze":
        print(json.dumps({k: v for k, v in freeze().items() if k != "files"}, indent=2, default=str))
    else:
        if not args.run:
            ap.error("blind requires --run")
        r = blind()
        print(json.dumps({k: r[k] for k in ("n", "n_benign", "n_malicious", "bn_coverage", "decision")}, indent=2))
        for k, a in r["arms"].items():
            f = a["fixed"]
            print(f"{k}: TPR {f['tpr']:.3f} {f['tpr_ci95']}  FPR {f['fpr']:.4f} ({f['fp']}/{f['n_benign']})  AUC {a['roc_auc']:.4f}")
        print(json.dumps(r["paired"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
