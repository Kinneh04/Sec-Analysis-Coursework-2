"""V9 one-shot replication of the frozen V8 blend (docs/v9_preregistration.md, including amendment A1).

  python -m src.v9.replicate --run     # writes artifacts/v9/blind/replication_results.json (locked)
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.v3.stats import paired_group_bootstrap_fixed, rates_at_threshold
from src.v4.ember import ember_columns, pretrained_model
from src.v4.experiment import _logit
from src.v7.experiment import USABLE, _bn
from src.v8.experiment import _verify as verify_v8
from src.v9.cohort import family
from src.v9.robustness import (TRAIN_FPRS, auc_bootstrap, candidate_score, compare, load_bundles, thresholds_for,
                               training_calibration)

ROOT = Path("artifacts/v9")


def frame() -> pd.DataFrame:
    parts = []
    for tag in ("v9", "v9s"):
        root = Path(f"artifacts/{tag}")
        split = pd.read_parquet(root / "manifests" / "new_split_assignments.parquet")
        b = split[split["split"] == "blind"].copy()
        inv = pd.read_parquet(root / "manifests" / "new_corpus_inventory.parquet")[["sha256", "source", "path"]]
        parts.append(b.merge(inv, on="sha256").assign(cohort=tag))
    b = pd.concat(parts, ignore_index=True)
    b["label"] = b["label"].map({"benign": 0, "malicious": 1}).astype(int)
    em = pd.read_parquet(ROOT / "features" / "ember_v3.parquet")
    b = b.merge(em, on="sha256", how="left")
    b["dropped_no_ember"] = b["em_status"] != "ok"
    return b


def evaluate(b: pd.DataFrame, bundles: dict[str, Any], cal: dict[str, Any]) -> dict[str, Any]:
    cb = bundles["candidate"]
    y, groups = b["label"].to_numpy(), b["group_id"].astype(str).to_numpy()
    s_r1 = b["r1_score"].to_numpy()
    s_c = candidate_score(cb, b, cb["w"], cb["t_blend"], cb["thr_r1"])
    s_r2 = bundles["R2"]["model"].predict(b[ember_columns()].to_numpy())
    res = compare(y, groups, s_c, s_r1, cb["thr_r1"])
    res["R2"] = rates_at_threshold(y, s_r2, bundles["R2"]["threshold"])
    res["paired_vs_R2"] = paired_group_bootstrap_fixed(y, s_r2, bundles["R2"]["threshold"], s_c, 0.0, groups, seed=42)
    res["n"], res["n_benign"], res["n_malicious"] = int(len(b)), int((y == 0).sum()), int((y == 1).sum())
    res["n_groups"] = int(len(np.unique(groups)))
    return res


def run() -> dict[str, Any]:
    bad = verify_v8()
    if bad:
        raise SystemExit(f"V8 freeze verification failed: {bad}")
    lock = ROOT / "blind" / "replication_run.lock"
    if lock.exists():
        raise SystemExit(f"{lock} exists: replication already run")
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")

    bundles = load_bundles()
    cal = training_calibration(bundles["candidate"])
    b = frame()
    dropped = int(b["dropped_no_ember"].sum())
    b = b[~b["dropped_no_ember"]].reset_index(drop=True)
    b = b.merge(_bn(list(b["sha256"])), on="sha256", how="left")
    b["r1_score"] = pretrained_model("PE").predict(b[ember_columns()].to_numpy())
    b["r1_logit"] = _logit(b["r1_score"].to_numpy())
    b["covered"] = (b["cap6_status"].isin(USABLE) & b["hl6_status"].isin(USABLE)).to_numpy()
    b["family"] = [family(p) if l == 0 else "malware" for p, l in zip(b["path"], b["label"])]
    b["ext"] = b["path"].str.lower().str.extract(r"\.(exe|dll|sys|ocx|cpl|scr)(?:\.malware)?$", expand=False).fillna("other")

    cb = bundles["candidate"]
    y = b["label"].to_numpy()
    primary = evaluate(b, bundles, cal)
    decision = {}
    for ref, pr, arm in (("R1", primary["paired"], primary["R1"]), ("R2", primary["paired_vs_R2"], primary["R2"])):
        decision[ref] = {"tpr_higher_ci_lower_gt_0": pr["delta_tpr_ci95"][0] > 0,
                         "fpr_not_higher": primary["candidate"]["fpr"] <= arm["fpr"]}
        decision[ref]["met"] = all(decision[ref].values())
    res: dict[str, Any] = {"run_at": datetime.now(timezone.utc).isoformat(), "dropped_no_ember": dropped,
                           "coverage": {"benign": float(b.loc[y == 0, "covered"].mean()), "malicious": float(b.loc[y == 1, "covered"].mean())},
                           "primary": primary, "decision": {**decision, "v8_improvement_replicated": decision["R1"]["met"]},
                           "secondary": {}}
    groups = b["group_id"].astype(str).to_numpy()
    s_c = candidate_score(cb, b, cb["w"], cb["t_blend"], cb["thr_r1"])
    res["secondary"]["auc_candidate_vs_r1"] = auc_bootstrap(y, b["r1_logit"].to_numpy(), s_c, groups)
    res["secondary"]["operating_points"] = {}
    for fpr in TRAIN_FPRS:
        thr_r1, t_b = thresholds_for(cal, cb["w"], fpr)
        o = compare(y, groups, candidate_score(cb, b, cb["w"], t_b, thr_r1), b["r1_score"].to_numpy(), thr_r1)
        res["secondary"]["operating_points"][str(fpr)] = {k: o[k] for k in ("gained_tp", "lost_tp", "added_fp", "removed_fp", "mcnemar_exact_p_two_sided_malware")} | {
            "cand_tp": o["candidate"]["tp"], "cand_fp": o["candidate"]["fp"], "r1_tp": o["R1"]["tp"], "r1_fp": o["R1"]["fp"]}
    subsets = {"malware_2026_v9": (b["label"] == 0) | (b["cohort"] == "v9"), "malware_2025_v9s": (b["label"] == 0) | (b["cohort"] == "v9s"),
               "benign_components": (b["label"] == 1) | (b["family"] == "components"), "benign_applications": (b["label"] == 1) | (b["family"] == "applications"),
               "bn_covered": b["covered"]}
    for name, m in subsets.items():
        sb = b[m.to_numpy()].reset_index(drop=True)
        o = evaluate(sb, bundles, cal)
        res["secondary"][name] = {k: o[k] for k in ("gained_tp", "lost_tp", "added_fp", "removed_fp", "mcnemar_exact_p_two_sided_malware", "n_benign", "n_malicious")} | {
            "cand": {k: o["candidate"][k] for k in ("tp", "fp", "tpr", "fpr")}, "R1": {k: o["R1"][k] for k in ("tp", "fp", "tpr", "fpr")},
            "R2": {k: o["R2"][k] for k in ("tp", "fp", "tpr", "fpr")}, "delta_tpr_ci95_vs_R1": o["paired"]["delta_tpr_ci95"]}
    res["secondary"]["by_ext"] = {}
    for val in sorted(b["ext"].unique()):
        m = (b["ext"] == val).to_numpy()
        c, r = s_c[m] >= 0, b["r1_score"].to_numpy()[m] >= cb["thr_r1"]
        yy = y[m]
        res["secondary"]["by_ext"][val] = {"n_mal": int((yy == 1).sum()), "n_ben": int((yy == 0).sum()), "cand_tp": int((c & (yy == 1)).sum()),
                                           "r1_tp": int((r & (yy == 1)).sum()), "cand_fp": int((c & (yy == 0)).sum()), "r1_fp": int((r & (yy == 0)).sum())}
    v8 = pd.read_parquet("artifacts/v8/blind/blind_scores.parquet")
    pooled_y = np.concatenate([y, v8["label"].to_numpy()])
    pooled_c = np.concatenate([s_c, v8["score_candidate"].to_numpy()])
    pooled_r = np.concatenate([b["r1_score"].to_numpy(), v8["score_R1"].to_numpy()])
    pooled_g = np.concatenate([groups, ("v8:" + v8["group_id"].astype(str)).to_numpy()])
    p = compare(pooled_y, pooled_g, pooled_c, pooled_r, cb["thr_r1"])
    res["secondary"]["pooled_v8_v9"] = {k: p[k] for k in ("gained_tp", "lost_tp", "added_fp", "removed_fp", "mcnemar_exact_p_two_sided_malware")} | {
        "delta_tpr_ci95": p["paired"]["delta_tpr_ci95"], "cand": {k: p["candidate"][k] for k in ("tp", "fp", "tpr", "fpr")},
        "R1": {k: p["R1"][k] for k in ("tp", "fp", "tpr", "fpr")}}
    (ROOT / "blind" / "replication_results.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    pd.DataFrame({"sha256": b["sha256"], "label": y, "group_id": groups, "cohort": b["cohort"], "family": b["family"], "covered": b["covered"],
                  "score_candidate": s_c, "score_R1": b["r1_score"]}).to_parquet(ROOT / "blind" / "replication_scores.parquet", index=False)
    return res


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", action="store_true")
    args = ap.parse_args(argv)
    if not args.run:
        ap.error("requires --run")
    r = run()
    p = r["primary"]
    print(json.dumps({"decision": r["decision"], "coverage": r["coverage"], "n": p["n"], "n_benign": p["n_benign"], "n_malicious": p["n_malicious"]}, indent=2))
    for arm in ("candidate", "R1", "R2"):
        a = p[arm]
        print(f"{arm}: TPR {a['tpr']:.4f} ({a['tp']}/{a['n_malicious']})  FPR {a['fpr']:.4f} ({a['fp']}/{a['n_benign']})")
    print("vs R1:", p["paired"]["delta_tpr_b_minus_a"], p["paired"]["delta_tpr_ci95"], "gained", p["gained_tp"], "lost", p["lost_tp"],
          "FP +", p["added_fp"], "-", p["removed_fp"], "McNemar p", p["mcnemar_exact_p_two_sided_malware"])
    print("vs R2:", p["paired_vs_R2"]["delta_tpr_b_minus_a"], p["paired_vs_R2"]["delta_tpr_ci95"])
    print(json.dumps(r["secondary"], indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
