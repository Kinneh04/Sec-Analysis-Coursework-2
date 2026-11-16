"""V8 experiment (docs/v8_preregistration.md): gentle blend of EMBER2024 with a Binary Ninja model.

  python -m src.v8.experiment freeze      # fit on training data only; freeze thresholds and hashes
  python -m src.v8.experiment blind --run # one-shot evaluation on the frozen V8 cohort
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

from src.v3.stats import paired_group_bootstrap_fixed, rates_at_threshold
from src.v4.ember import ember_columns, pretrained_model
from src.v4.experiment import SEED, _logit, _sha_file, fit_r2
from src.v7.experiment import USABLE, _bn, training_frames
from src.v8 import blend

ROOT = Path("artifacts/v8")
PREREG = Path("docs/v8_preregistration.md")


def freeze() -> dict[str, Any]:
    fdir = ROOT / "freeze"
    manifest = fdir / "freeze_manifest.json"
    if manifest.exists():
        raise SystemExit(f"{manifest} exists")
    fr = training_frames()
    pool = fr["pool"]
    cand = blend.fit(pool, fr["bn_mask"])
    r2 = fit_r2(pool)
    models = ROOT / "models"
    models.mkdir(parents=True, exist_ok=True)
    bundle = {"candidate": {**cand, "training_sha256": sorted(pool["sha256"])},
              "R2": {**r2, "training_sha256": sorted(pool["sha256"])},
              "R1": {"threshold": cand["thr_r1"], "model_file": "EMBER2024_PE.model"}}
    for k, v in bundle.items():
        with (models / f"{k}.pkl").open("wb") as fh:
            pickle.dump(v, fh)
    fdir.mkdir(parents=True, exist_ok=True)
    tracked = [PREREG, ROOT / "manifests" / "new_split_assignments.parquet", ROOT / "manifests" / "new_corpus_freeze.json",
               ROOT / "manifests" / "bn_queue.csv", *[models / f"{k}.pkl" for k in bundle], *sorted(Path("src/v8").glob("*.py")),
               Path("src/v7/experiment.py"), Path("src/v6/bn_capabilities.py"), Path("src/v6/bn_hlil.py"), Path("src/v6/unpack.py")]
    meta = {"frozen_at": datetime.now(timezone.utc).isoformat(), "w": cand["w"], "weight_table": cand["weight_table"],
            "thresholds": {"candidate_blend": cand["t_blend"], "R1": cand["thr_r1"], "R2": r2["threshold"]},
            "train": {k: cand[k] for k in ("train_bn_rows", "train_r1_flagged_benign_bn_rows", "train_blend_flagged_benign_bn_rows")},
            "r2_train_oof": r2["oof_rates"], "files": {p.as_posix(): _sha_file(p) for p in tracked}}
    manifest.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
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

    arms = {k: pickle.load((ROOT / "models" / f"{k}.pkl").open("rb")) for k in ("candidate", "R2", "R1")}
    cov = (b["cap6_status"].isin(USABLE) & b["hl6_status"].isin(USABLE)).to_numpy()
    _, cand_score = blend.decide(arms["candidate"], b, cov)
    scores = {"candidate": cand_score, "R2": arms["R2"]["model"].predict(b[ember_columns()].to_numpy()), "R1": b["r1_score"].to_numpy()}
    thr = {"candidate": 0.0, "R2": arms["R2"]["threshold"], "R1": arms["R1"]["threshold"]}
    y = b["label"].to_numpy()
    groups = b["group_id"].astype(str).to_numpy()
    res: dict[str, Any] = {"run_at": datetime.now(timezone.utc).isoformat(), "w": arms["candidate"]["w"],
                           "n": int(len(b)), "n_benign": int((y == 0).sum()), "n_malicious": int((y == 1).sum()),
                           "n_groups": int(len(np.unique(groups))), "dropped_no_ember": dropped,
                           "bn_coverage": {"benign": float(cov[y == 0].mean()), "malicious": float(cov[y == 1].mean())},
                           "arms": {}, "paired": {}, "secondary": {}}
    for k, s in scores.items():
        res["arms"][k] = {"threshold": thr[k], "fixed": rates_at_threshold(y, s, thr[k]), "roc_auc": float(roc_auc_score(y, s)),
                          "pr_auc": float(average_precision_score(y, s))}
    decision = {}
    for ref in ("R1", "R2"):
        pr = paired_group_bootstrap_fixed(y, scores[ref], thr[ref], scores["candidate"], 0.0, groups, seed=SEED)
        res["paired"][f"candidate_minus_{ref}"] = pr
        decision[ref] = {"tpr_higher_ci_lower_gt_0": pr["delta_tpr_ci95"][0] > 0,
                         "fpr_not_higher": res["arms"]["candidate"]["fixed"]["fpr"] <= res["arms"][ref]["fixed"]["fpr"]}
        decision[ref]["beaten"] = all(decision[ref].values())
    res["decision"] = {**decision, "beats_ember2024": all(d["beaten"] for d in decision.values())}
    cd, rd = scores["candidate"] >= 0, scores["R1"] >= thr["R1"]
    res["secondary"]["vs_R1_discordance"] = {"gained_tp": int((cd & ~rd & (y == 1)).sum()), "lost_tp": int((~cd & rd & (y == 1)).sum()),
                                             "added_fp": int((cd & ~rd & (y == 0)).sum()), "removed_fp": int((~cd & rd & (y == 0)).sum())}
    if (y[cov] == 0).any() and (y[cov] == 1).any():
        res["secondary"]["bn_covered"] = {k: rates_at_threshold(y[cov], s[cov], thr[k]) for k, s in scores.items()}
    res["sota_claim_supported"] = False
    (ROOT / "blind" / "blind_results.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    pd.DataFrame({"sha256": b["sha256"], "label": y, "group_id": groups, "source": b["source"], "path": b["path"], "bn_covered": cov,
                  **{f"score_{k}": v for k, v in scores.items()}}).to_parquet(ROOT / "blind" / "blind_scores.parquet", index=False)
    return res


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["freeze", "blind"])
    ap.add_argument("--run", action="store_true")
    args = ap.parse_args(argv)
    if args.command == "freeze":
        print(json.dumps({k: v for k, v in freeze().items() if k != "files"}, indent=2, default=str))
    else:
        if not args.run:
            ap.error("blind requires --run")
        r = blind()
        print(json.dumps({k: r[k] for k in ("n", "n_benign", "n_malicious", "bn_coverage", "decision")}, indent=2))
        for k, a in r["arms"].items():
            f = a["fixed"]
            print(f"{k}: TPR {f['tpr']:.3f} {f['tpr_ci95']}  FPR {f['fpr']:.4f} ({f['fp']}/{f['n_benign']})  AUC {a['roc_auc']:.4f}")
        print(json.dumps({"paired": r["paired"], "secondary": r["secondary"]}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
