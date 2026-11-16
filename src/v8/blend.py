"""V8 candidate: gentle score blend of EMBER2024 (R1) with a Binary Ninja-only model.

    score = logit(R1) + w * logit(BN model)      on files with Binary Ninja features
    decision = score >= t_blend                  (covered files)
    decision = R1 >= thr_R1                      (files without Binary Ninja features)

Fitting uses training data only:
  - BN model: LightGBM over cap6_* + hl6_* (no EMBER inputs), scored out of fold on training rows
    with Binary Ninja features (StratifiedGroupKFold, 5 folds).
  - w: chosen from WEIGHTS by nested half-split evaluation on those rows (highest mean extra TP over
    w = 0 with mean extra FP <= 0; ties go to the smaller w).
  - t_blend: the lowest threshold whose benign count on the out-of-fold blend scores of the covered
    training rows does not exceed the benign count R1 flags on the same rows at thr_R1.
"""

from __future__ import annotations

from typing import Any

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from src.metrics import tpr_at_fpr
from src.v4.experiment import TARGET_FPR, _logit
from src.v6 import bn_capabilities, bn_hlil

PARAMS = dict(n_estimators=300, num_leaves=15, min_child_samples=20, feature_fraction=0.7, learning_rate=0.05, verbose=-1)
WEIGHTS = (0.0, 0.05, 0.1, 0.2, 0.3, 0.5)
N_SEEDS = 10


def bn_columns(df: pd.DataFrame) -> list[str]:
    return bn_capabilities.cap6_columns(df) + bn_hlil.hl6_columns(df)


def _oof(X: np.ndarray, y: np.ndarray, groups: pd.Series, seed: int) -> np.ndarray:
    oof = np.zeros(len(y))
    for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed).split(X, y, groups):
        oof[te] = lgb.LGBMClassifier(random_state=seed, **PARAMS).fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
    return oof


def _thr_count(benign_scores: np.ndarray, max_flagged: int) -> float:
    """Lowest threshold flagging at most max_flagged of the given benign scores."""
    s = np.sort(benign_scores)[::-1]
    if max_flagged >= len(s):
        return float(s[-1])
    return float(np.nextafter(s[max_flagged], np.inf))


def _thr_fpr(benign_scores: np.ndarray, fpr: float = TARGET_FPR) -> float:
    return _thr_count(benign_scores, int(np.floor(fpr * len(benign_scores))))


def select_weight(X: np.ndarray, y: np.ndarray, r1l: np.ndarray, groups: pd.Series) -> dict[str, Any]:
    gains = {w: [] for w in WEIGHTS}
    fps = {w: [] for w in WEIGHTS}
    gs = groups.astype(str)
    for seed in range(N_SEEDS):
        bl = _logit(_oof(X, y, groups, seed))
        half = set(np.random.default_rng(seed).choice(gs.unique(), gs.nunique() // 2, replace=False))
        a = gs.isin(half).to_numpy()
        for cal, ev in ((a, ~a), (~a, a)):
            base = None
            for w in WEIGHTS:
                s = r1l + w * bl
                t = _thr_fpr(s[cal & (y == 0)])
                tp, fp = int(((s >= t) & ev & (y == 1)).sum()), int(((s >= t) & ev & (y == 0)).sum())
                base = base or (tp, fp)
                gains[w].append(tp - base[0])
                fps[w].append(fp - base[1])
    table = {str(w): {"mean_extra_tp": float(np.mean(gains[w])), "mean_extra_fp": float(np.mean(fps[w]))} for w in WEIGHTS}
    ok = [w for w in WEIGHTS if w > 0 and table[str(w)]["mean_extra_fp"] <= 0]
    best = max(ok, key=lambda w: (round(table[str(w)]["mean_extra_tp"], 6), -w)) if ok else 0.0
    return {"w": float(best), "table": table}


def fit(pool: pd.DataFrame, bn_mask: np.ndarray) -> dict[str, Any]:
    y_all, r_all = pool["label"].to_numpy(), pool["r1_score"].to_numpy()
    thr_r1 = float(tpr_at_fpr(y_all, r_all, TARGET_FPR)["threshold"])
    sub = pool[bn_mask].reset_index(drop=True)
    cols = bn_columns(sub)
    X, y, r1l = sub[cols].to_numpy(dtype=float), sub["label"].to_numpy(), sub["r1_logit"].to_numpy()
    sel = select_weight(X, y, r1l, sub["group_id"])
    w = sel["w"]
    blend_oof = r1l + w * _logit(_oof(X, y, sub["group_id"], 0))
    r1_flagged_benign = int(((sub["r1_score"].to_numpy() >= thr_r1) & (y == 0)).sum())
    t_blend = _thr_count(blend_oof[y == 0], r1_flagged_benign)
    model = lgb.LGBMClassifier(random_state=0, **PARAMS).fit(X, y)
    return {"cols": cols, "model": model, "w": w, "weight_table": sel["table"], "thr_r1": thr_r1, "t_blend": t_blend,
            "train_bn_rows": int(len(sub)), "train_r1_flagged_benign_bn_rows": r1_flagged_benign,
            "train_blend_flagged_benign_bn_rows": int((blend_oof[y == 0] >= t_blend).sum())}


def decide(bundle: dict[str, Any], df: pd.DataFrame, covered: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Return (decision, score). Score is the blend on covered rows and logit(R1) shifted to the same
    decision boundary on uncovered rows, so a single threshold of 0 applies to both."""
    r1l = df["r1_logit"].to_numpy()
    bl = _logit(bundle["model"].predict_proba(df[bundle["cols"]].to_numpy(dtype=float))[:, 1])
    blend = r1l + bundle["w"] * bl - bundle["t_blend"]
    plain = r1l - float(_logit(np.array([bundle["thr_r1"]]))[0])
    score = np.where(covered, blend, plain)
    return score >= 0, score
