"""Robustness analyses of the frozen V8 blend on held-out cohorts (no refitting of frozen models).

Cohorts: V8 blind (its one-shot result is already recorded) and V7 blind (consumed; never in training).
Operating points other than the frozen one use thresholds derived from training data only.

  python -m src.v9.robustness     # writes artifacts/v9/robustness.json
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from scipy.stats import binomtest
from sklearn.metrics import roc_auc_score

from src.metrics import tpr_at_fpr
from src.v3.stats import paired_group_bootstrap_fixed, rates_at_threshold
from src.v4.ember import ember_columns, pretrained_model
from src.v4.experiment import _logit
from src.v7.experiment import USABLE, _bn, training_frames
from src.v8 import blend

OUT = Path("artifacts/v9")
TRAIN_FPRS = (0.0025, 0.005, 0.01, 0.02, 0.05)
WEIGHTS = (0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1.0)


def load_bundles() -> dict[str, Any]:
    return {k: pickle.load(open(f"artifacts/v8/models/{k}.pkl", "rb")) for k in ("candidate", "R1", "R2")}


def cohort_frame(tag: str) -> pd.DataFrame:
    root = Path(f"artifacts/{tag}")
    split = pd.read_parquet(root / "manifests" / "new_split_assignments.parquet")
    b = split[split["split"] == "blind"].copy()
    b["label"] = b["label"].map({"benign": 0, "malicious": 1}).astype(int)
    inv = pd.read_parquet(root / "manifests" / "new_corpus_inventory.parquet")[["sha256", "source", "path"]]
    em = pd.read_parquet(root / "features" / "ember_v3.parquet")
    b = b.merge(inv, on="sha256").merge(em, on="sha256")
    b = b[b["em_status"] == "ok"].reset_index(drop=True)
    b = b.merge(_bn(list(b["sha256"])), on="sha256", how="left")
    b["r1_score"] = pretrained_model("PE").predict(b[ember_columns()].to_numpy())
    b["r1_logit"] = _logit(b["r1_score"].to_numpy())
    b["covered"] = (b["cap6_status"].isin(USABLE) & b["hl6_status"].isin(USABLE)).to_numpy()
    b["ext"] = b["path"].str.lower().str.extract(r"\.(exe|dll|sys|ocx|cpl|scr)(?:\.malware)?$", expand=False).fillna("other")
    b["batch_month"] = b["source"].str.extract(r"malwarebazaar:(\d{4}-\d{2})", expand=False).fillna("benign")
    return b


def training_calibration(bundle: dict[str, Any]) -> dict[str, Any]:
    """Training-only quantities for alternative operating points and weights."""
    fr = training_frames()
    pool = fr["pool"]
    sub = pool[fr["bn_mask"]].reset_index(drop=True)
    X, y = sub[bundle["cols"]].to_numpy(dtype=float), sub["label"].to_numpy()
    bn_oof = _logit(blend._oof(X, y, sub["group_id"], 0))
    return {"pool_y": pool["label"].to_numpy(), "pool_r1": pool["r1_score"].to_numpy(), "sub_y": y,
            "sub_r1": sub["r1_score"].to_numpy(), "sub_r1l": sub["r1_logit"].to_numpy(), "sub_bn_oof": bn_oof}


def candidate_score(bundle: dict[str, Any], df: pd.DataFrame, w: float, t_blend: float, thr_r1: float) -> np.ndarray:
    bl = _logit(bundle["model"].predict_proba(df[bundle["cols"]].to_numpy(dtype=float))[:, 1])
    covered = df["covered"].to_numpy()
    return np.where(covered, df["r1_logit"].to_numpy() + w * bl - t_blend, df["r1_logit"].to_numpy() - float(_logit(np.array([thr_r1]))[0]))


def thresholds_for(cal: dict[str, Any], w: float, fpr: float) -> tuple[float, float]:
    thr_r1 = float(tpr_at_fpr(cal["pool_y"], cal["pool_r1"], fpr)["threshold"])
    flagged = int(((cal["sub_r1"] >= thr_r1) & (cal["sub_y"] == 0)).sum())
    blend_oof = cal["sub_r1l"] + w * cal["sub_bn_oof"]
    return thr_r1, blend._thr_count(blend_oof[cal["sub_y"] == 0], flagged)


def compare(y: np.ndarray, groups: np.ndarray, s_c: np.ndarray, s_r1: np.ndarray, thr_r1: float) -> dict[str, Any]:
    c, r = s_c >= 0, s_r1 >= thr_r1
    gained, lost = int((c & ~r & (y == 1)).sum()), int((~c & r & (y == 1)).sum())
    add_fp, rem_fp = int((c & ~r & (y == 0)).sum()), int((~c & r & (y == 0)).sum())
    n_disc = gained + lost
    return {"candidate": rates_at_threshold(y, s_c, 0.0), "R1": rates_at_threshold(y, s_r1, thr_r1),
            "gained_tp": gained, "lost_tp": lost, "added_fp": add_fp, "removed_fp": rem_fp,
            "mcnemar_exact_p_two_sided_malware": float(binomtest(gained, n_disc, 0.5).pvalue) if n_disc else 1.0,
            "paired": paired_group_bootstrap_fixed(y, s_r1, thr_r1, s_c, 0.0, groups, seed=42)}


def auc_bootstrap(y: np.ndarray, a: np.ndarray, b: np.ndarray, groups: np.ndarray, n_boot: int = 1000) -> dict[str, Any]:
    uniq, inv = np.unique(groups, return_inverse=True)
    idx_by_g = [np.where(inv == i)[0] for i in range(len(uniq))]
    rng = np.random.default_rng(42)
    d = []
    for _ in range(n_boot):
        pick = np.concatenate([idx_by_g[i] for i in rng.integers(0, len(uniq), len(uniq))])
        if len(np.unique(y[pick])) < 2:
            continue
        d.append(roc_auc_score(y[pick], b[pick]) - roc_auc_score(y[pick], a[pick]))
    return {"auc_a": float(roc_auc_score(y, a)), "auc_b": float(roc_auc_score(y, b)), "delta": float(roc_auc_score(y, b) - roc_auc_score(y, a)),
            "delta_ci95": [float(np.quantile(d, 0.025)), float(np.quantile(d, 0.975))]}


def analyze(tag: str, bundles: dict[str, Any], cal: dict[str, Any]) -> dict[str, Any]:
    cb = bundles["candidate"]
    df = cohort_frame(tag)
    y, groups = df["label"].to_numpy(), df["group_id"].astype(str).to_numpy()
    s_r1 = df["r1_score"].to_numpy()
    res: dict[str, Any] = {"n": int(len(df)), "n_benign": int((y == 0).sum()), "n_malicious": int((y == 1).sum()),
                           "coverage": {"benign": float(df.loc[y == 0, "covered"].mean()), "malicious": float(df.loc[y == 1, "covered"].mean())}}
    s_c = candidate_score(cb, df, cb["w"], cb["t_blend"], cb["thr_r1"])
    res["frozen"] = compare(y, groups, s_c, s_r1, cb["thr_r1"])
    res["frozen"]["R2"] = rates_at_threshold(y, bundles["R2"]["model"].predict(df[ember_columns()].to_numpy()), bundles["R2"]["threshold"])
    res["auc_candidate_vs_r1"] = auc_bootstrap(y, df["r1_logit"].to_numpy(), s_c, groups)
    res["operating_points"] = {}
    for fpr in TRAIN_FPRS:
        thr_r1, t_b = thresholds_for(cal, cb["w"], fpr)
        res["operating_points"][str(fpr)] = compare(y, groups, candidate_score(cb, df, cb["w"], t_b, thr_r1), s_r1, thr_r1)
    res["weights"] = {}
    for w in WEIGHTS:
        thr_r1, t_b = thresholds_for(cal, w, 0.01)
        r = compare(y, groups, candidate_score(cb, df, w, t_b, thr_r1), s_r1, thr_r1)
        res["weights"][str(w)] = {k: r[k] for k in ("gained_tp", "lost_tp", "added_fp", "removed_fp")}
    res["by_group"] = {}
    for col in ("ext", "batch_month"):
        res["by_group"][col] = {}
        for val, d in df.groupby(col):
            m = df[col].to_numpy() == val
            c, r = s_c[m] >= 0, s_r1[m] >= cb["thr_r1"]
            yy = y[m]
            res["by_group"][col][str(val)] = {"n_mal": int((yy == 1).sum()), "n_ben": int((yy == 0).sum()),
                                              "cand_tp": int((c & (yy == 1)).sum()), "r1_tp": int((r & (yy == 1)).sum()),
                                              "cand_fp": int((c & (yy == 0)).sum()), "r1_fp": int((r & (yy == 0)).sum())}
    return res


def main() -> int:
    bundles = load_bundles()
    cal = training_calibration(bundles["candidate"])
    out = {tag: analyze(tag, bundles, cal) for tag in ("v8", "v7")}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "robustness.json").write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    for tag, r in out.items():
        f = r["frozen"]
        print(tag, "n", r["n"], "cand", f["candidate"]["tp"], f["candidate"]["fp"], "R1", f["R1"]["tp"], f["R1"]["fp"],
              "gained", f["gained_tp"], "lost", f["lost_tp"], "addFP", f["added_fp"], "remFP", f["removed_fp"],
              "p", round(f["mcnemar_exact_p_two_sided_malware"], 4), "dTPR CI", [round(x, 4) for x in f["paired"]["delta_tpr_ci95"]])
        print("   AUC", {k: (round(v, 4) if isinstance(v, float) else [round(x, 4) for x in v]) for k, v in r["auc_candidate_vs_r1"].items()})
        for fpr, o in r["operating_points"].items():
            print("   op", fpr, "cand", o["candidate"]["tp"], o["candidate"]["fp"], "R1", o["R1"]["tp"], o["R1"]["fp"], "gain/loss", o["gained_tp"], o["lost_tp"], "fp +/-", o["added_fp"], o["removed_fp"])
        print("   weights", r["weights"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
