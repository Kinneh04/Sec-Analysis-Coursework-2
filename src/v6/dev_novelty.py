"""Development check: fraction of a file's functions whose fingerprint never occurs in benign files.

Fingerprint = (instruction count, called APIs, referenced strings) from the V6 per-function cache.
Benign fingerprint sets are built from benign files in other CV folds (grouped), so a file never
matches against itself or its directory group.

  python -m src.v6.dev_novelty
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from src.v6.bn_capabilities import CACHE_DIR
from src.v6.dev_gate import OUT, QUEUE, _thr_at_fpr

MIN_INSN = 12


def fingerprints(sha: str) -> list[str] | None:
    p = CACHE_DIR / f"{sha}.json"
    if not p.is_file():
        return None
    d = json.loads(p.read_text(encoding="utf-8"))
    if d.get("analysis_status") not in ("ok", "partial"):
        return None
    out = []
    for f in d.get("functions") or []:
        n = (f.get("ind") or {}).get("n_insn", 0)
        if n < MIN_INSN:
            continue
        key = json.dumps([n, f.get("apis") or [], f.get("strings") or []])
        out.append(hashlib.blake2b(key.encode(), digest_size=8).hexdigest())
    return out


def main() -> int:
    q = pd.read_csv(QUEUE)
    fps = {s: fingerprints(s) for s in q.sha256}
    q = q[[fps[s] is not None and len(fps[s]) > 0 for s in q.sha256]].reset_index(drop=True)
    y = q.label.to_numpy()
    res = {}
    for seed in range(5):
        novel = np.full(len(q), np.nan)
        for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed).split(q, y, q.group_id):
            ben = Counter()
            for i in tr:
                if y[i] == 0:
                    ben.update(set(fps[q.sha256[i]]))
            for i in te:
                f = fps[q.sha256[i]]
                novel[i] = sum(1 for h in f if h not in ben) / len(f)
        q[f"novel_{seed}"] = novel
    q["novel"] = q[[f"novel_{s}" for s in range(5)]].mean(axis=1)
    for name, m in (("missed_mal", q.r1_missed), ("detected_mal", (q.label == 1) & ~q.r1_missed), ("benign", q.label == 0)):
        v = q.loc[m, "novel"]
        res[name] = {"n": int(len(v)), "median_novel_frac": round(float(v.median()), 3), "frac_ge_0.9": round(float((v >= 0.9).mean()), 3)}
    from sklearn.metrics import roc_auc_score
    res["auc_novel_missed_vs_benign"] = round(float(roc_auc_score(np.r_[np.ones(q.r1_missed.sum()), np.zeros((y == 0).sum())],
                                                                   np.r_[q.loc[q.r1_missed, "novel"], q.loc[y == 0, "novel"]])), 3)
    r1 = np.clip(q.r1_score.to_numpy(), 1e-6, 1 - 1e-6)
    X = np.column_stack([np.log(r1 / (1 - r1)), q.novel.to_numpy()])
    r1_tp = int(((r1 >= _thr_at_fpr(r1[y == 0])) & (y == 1)).sum())
    extra = []
    for seed in range(10):
        oof = np.zeros(len(q))
        for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed).split(X, y, q.group_id):
            m = lgb.LGBMClassifier(n_estimators=150, num_leaves=5, min_child_samples=10, learning_rate=0.05, verbose=-1, random_state=seed)
            m.fit(X[tr], y[tr])
            oof[te] = m.predict_proba(X[te])[:, 1]
        extra.append(int(((oof >= _thr_at_fpr(oof[y == 0])) & (y == 1)).sum()) - r1_tp)
    res["stacker_r1_plus_novel"] = {"r1_tp": r1_tp, "extra_tp_per_seed": extra, "median": float(np.median(extra))}
    (OUT / "dev_novelty.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
