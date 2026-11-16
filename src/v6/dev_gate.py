"""V6 development gate on consumed cohorts (V3.2 blind, 2026 temporal check, V4 blind).

These cohorts were already used for evaluation, so they serve only as development data here.

  python -m src.v6.dev_gate queue      # writes artifacts/v6/manifests/gate_queue.csv
  python -m src.v6.dev_gate evaluate   # writes artifacts/v6/dev_gate.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from src.v4.ember import ember_columns, pretrained_model
from src.v6.bn_capabilities import build, cap6_columns
from src.v6.evasion_strata import stratum, traits

OUT = Path("artifacts/v6")
QUEUE = OUT / "manifests" / "gate_queue.csv"
R1_THRESHOLD = 0.35368360073284755  # V4 frozen R1 threshold (1% FPR on the V4 training pool)
SEED = 20261103
N_DETECTED_MAL = 200
N_BENIGN = 350


def labeled_files() -> pd.DataFrame:
    inv = pd.read_parquet("artifacts/v3.2/manifests/new_corpus_inventory.parquet")
    v32 = pd.read_parquet("artifacts/v3.2/blind/blind_scores.parquet")[["sha256", "label", "group_id"]]
    v32 = v32.merge(inv[["sha256", "path"]].drop_duplicates("sha256"), on="sha256").assign(dev_set="v3.2_blind")
    tmp = pd.read_parquet("artifacts/v3.3/temporal_eval/scored.parquet", columns=["sha256", "path", "label"])
    tmp = tmp.drop_duplicates("sha256").assign(dev_set="temporal_2026", group_id=lambda d: "tmp:" + d.sha256.str[:12])
    v4 = pd.read_parquet("artifacts/v4/blind/blind_scores.parquet")[["sha256", "label", "group_id", "path"]].assign(dev_set="v4_blind")
    df = pd.concat([v32, tmp, v4], ignore_index=True).drop_duplicates("sha256")
    ember = pd.concat([pd.read_parquet("artifacts/v4/features/ember_v3.parquet"),
                       pd.read_parquet("artifacts/v3.3/temporal_eval/ember_v3.parquet")]).drop_duplicates("sha256")
    ember = ember[ember.em_status == "ok"]
    df = df.merge(ember[["sha256", *ember_columns()]], on="sha256")
    df["r1_score"] = pretrained_model("PE").predict(df[ember_columns()].to_numpy())
    df = df.drop(columns=ember_columns())
    df["r1_missed"] = (df.label == 1) & (df.r1_score < R1_THRESHOLD)
    t = pd.DataFrame([traits(p) for p in df.path])
    df = pd.concat([df.reset_index(drop=True), t], axis=1)
    df["stratum"] = [stratum(r) for r in t.to_dict("records")]
    return df


def make_queue() -> pd.DataFrame:
    df = labeled_files()
    rng = np.random.default_rng(SEED)
    missed = df[df.r1_missed]
    det = df[(df.label == 1) & ~df.r1_missed]
    ben = df[df.label == 0]
    det = det.iloc[rng.choice(len(det), min(N_DETECTED_MAL, len(det)), replace=False)]
    ben = ben.iloc[rng.choice(len(ben), min(N_BENIGN, len(ben)), replace=False)]
    q = pd.concat([missed, ben, det])  # extraction order: the gate needs missed malware and benign first
    QUEUE.parent.mkdir(parents=True, exist_ok=True)
    q.to_csv(QUEUE, index=False)
    print(df.groupby(["label", "r1_missed", "stratum"]).size().to_string())
    print(f"queue {len(q)}: missed {len(missed)}, detected {len(det)}, benign {len(ben)}")
    return q


def evaluate() -> dict:
    q = pd.read_csv(QUEUE)
    f = build(q.sha256.tolist())
    df = q.merge(f, on="sha256")
    ok = df[df.cap6_status.isin(["ok", "partial"])].copy()
    groups = {"missed_mal": ok[ok.r1_missed], "detected_mal": ok[(ok.label == 1) & ~ok.r1_missed], "benign": ok[ok.label == 0]}
    cols = cap6_columns(ok)
    rate = {}
    for c in cols:
        rate[c] = {g: round(float((d[c] > 0).mean()), 3) if len(d) else None for g, d in groups.items()}
    strong = rate.get("cap6_strong_any", {})
    rule_any = (ok[[c for c in cols if c.startswith("cap6_r_")]] > 0).any(axis=1)
    ok["strong_or_rule"] = (ok.get("cap6_strong_any", 0) > 0) | rule_any
    gate_a = {g: round(float(ok.loc[d.index, "strong_or_rule"].mean()), 3) if len(d) else None for g, d in groups.items()}
    by_stratum = ok.groupby(["stratum", "label", "r1_missed"]).strong_or_rule.agg(["mean", "size"]).reset_index()
    res = {
        "n_queue": int(len(q)), "n_analyzed": int(len(ok)),
        "status_counts": df.cap6_status.value_counts().to_dict(),
        "group_sizes": {g: int(len(d)) for g, d in groups.items()},
        "strong_any_rate": strong,
        "strong_or_rule_rate": gate_a,
        "gate_a_pass": bool(gate_a["missed_mal"] is not None and gate_a["missed_mal"] >= 0.30 and gate_a["benign"] <= 0.03),
        "indicator_rates": rate,
        "by_stratum": by_stratum.to_dict("records"),
    }
    (OUT / "dev_gate.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    return res


def _thr_at_fpr(benign_scores: np.ndarray, fpr: float = 0.01) -> float:
    s = np.sort(benign_scores)[::-1]
    k = int(np.floor(fpr * len(s)))
    return float(np.nextafter(s[k], np.inf)) if k < len(s) else float(s[-1])


def model_gate(n_splits: int = 5, seeds: tuple[int, ...] = (0, 1, 2)) -> dict:
    """Gate B: grouped CV on the gate set. Stacker (R1 logit + cap6) versus R1 alone, each thresholded
    at 1% FPR on its own out-of-fold benign scores."""
    import lightgbm as lgb
    from sklearn.model_selection import StratifiedGroupKFold

    q = pd.read_csv(QUEUE)
    df = q.merge(build(q.sha256.tolist()), on="sha256")
    cols = cap6_columns(df)
    df.loc[~df.cap6_status.isin(["ok", "partial"]), cols] = np.nan
    r1 = np.clip(df.r1_score.to_numpy(), 1e-6, 1 - 1e-6)
    X = np.column_stack([np.log(r1 / (1 - r1)), df[cols].to_numpy(dtype=float)])
    y = df.label.to_numpy()
    out = []
    for seed in seeds:
        oof = np.zeros(len(df))
        for tr, te in StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed).split(X, y, df.group_id):
            m = lgb.LGBMClassifier(n_estimators=200, num_leaves=7, min_child_samples=10, learning_rate=0.05,
                                   feature_fraction=0.7, verbose=-1, random_state=seed)
            m.fit(X[tr], y[tr])
            oof[te] = m.predict_proba(X[te])[:, 1]
        res = {}
        for name, s in (("stacker", oof), ("R1", r1)):
            t = _thr_at_fpr(s[y == 0])
            pred = s >= t
            res[name] = {"tp": int((pred & (y == 1)).sum()), "fp": int((pred & (y == 0)).sum()),
                         "tp_missed_set": int((pred & df.r1_missed.to_numpy()).sum())}
        res["extra_tp"] = res["stacker"]["tp"] - res["R1"]["tp"]
        res["extra_fp"] = res["stacker"]["fp"] - res["R1"]["fp"]
        out.append(res)
    gate_b = all(r["extra_tp"] >= 5 and r["extra_fp"] <= 0 for r in out)
    summary = {"n": int(len(df)), "n_mal": int(y.sum()), "n_ben": int((y == 0).sum()), "per_seed": out, "gate_b_pass": gate_b}
    path = OUT / "dev_gate.json"
    cur = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    cur["model_gate"] = summary
    path.write_text(json.dumps(cur, indent=2, default=str), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["queue", "evaluate", "model"])
    args = ap.parse_args(argv)
    if args.command == "queue":
        make_queue()
    elif args.command == "model":
        print(json.dumps(model_gate(), indent=2))
    else:
        r = evaluate()
        print(json.dumps({k: v for k, v in r.items() if k not in ("indicator_rates", "by_stratum")}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
