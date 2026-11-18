"""Build artifacts/v8/feature_reference.json: training-pool statistics used to explain V8 verdicts.

Aggregate statistics only (medians, non-zero rates, modes, class counts, R1 operating points); no hash,
path or per-file row is stored. The pool is the V8 training pool: the 5,864 files listed in
candidate.pkl["training_sha256"], assembled the way src.v7.experiment.training_frames() does it
(EMBER v3 vectors from artifacts/v4/features and artifacts/v3.3/temporal_eval, labels from the cohort
manifests and the V6 gate queue, Binary Ninja features from the v6 cap/hlil caches via src.v7.experiment._bn).

EMBER2024 (R1) was trained by its authors on their own data, not on this pool: the medians describe the
files this deployment was tuned on, not R1's training set.

  python -m src.webscan.reference --artifacts D:\\SA2_full_export\\artifacts
  python -m src.webscan.reference --artifacts ../SA2_full_export/artifacts --out artifacts/v8/feature_reference.json
"""

from __future__ import annotations

import argparse
import json
import math
import pickle
import warnings
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
OUT = Path("artifacts/v8/feature_reference.json")
CANDIDATE = Path("artifacts/v8/models/candidate.pkl")
USABLE = ("ok", "partial")  # src.v7.experiment.USABLE
EXPECTED = {"n": 5864, "benign": 3506, "malicious": 2358, "bn_cap6": 1256}  # bn_cap6 = candidate.pkl train_bn_rows
R1_THR_1PCT = 0.31491410519549656  # frozen thr_R1 (candidate.pkl); must be reproduced
FPRS = (0.01, 0.02, 0.05)
CATEGORICAL = ("em_general_is_pe", "em_general_start_byte_0", "em_general_start_byte_1", "em_general_start_byte_2",
               "em_general_start_byte_3", "em_header_coff_machine", "em_header_optional_subsystem")


def _abs(p: Path) -> Path:
    return p if p.is_absolute() else ROOT / p


def _num(x: float) -> float:
    """Compact JSON number: 5 significant digits."""
    x = float(x)
    if not math.isfinite(x):
        return 0.0
    return float(f"{x:.5g}")


def labels(art: Path) -> dict[str, int]:
    """sha256 -> label (0 benign, 1 malicious) from every manifest load_pool()/training_frames() read labels from."""
    out: dict[str, int] = {}
    srcs = [pd.read_parquet(art / "manifests" / "split_assignments.parquet")[["sha256", "label"]]]
    for tag in ("v3", "v3.1", "v3.2"):  # src.v3.cohorts.WAVES up to v3.2
        srcs.append(pd.read_parquet(art / tag / "manifests" / "new_split_assignments.parquet")[["sha256", "label"]])
    srcs.append(pd.read_csv(art / "v6" / "manifests" / "gate_queue.csv")[["sha256", "label"]])
    for df in srcs:
        for sha, lab in zip(df["sha256"], df["label"]):
            v = {"benign": 0, "malicious": 1}.get(lab, lab)
            v = int(v)
            if out.get(sha, v) != v:
                raise SystemExit(f"conflicting labels for one training file in {art}")
            out[sha] = v
    return out


def ember_matrix(art: Path, shas: set[str]) -> tuple[list[str], np.ndarray]:
    """EMBER v3 vectors for the pool, same sources and precedence as training_frames() (v4 first, then v3.3)."""
    import pyarrow.parquet as pq

    cols = ["sha256", "em_status"] + [f"em_{i:04d}" for i in range(2568)]
    order: list[str] = []
    rows: list[np.ndarray] = []
    seen: set[str] = set()
    for p in (art / "v4" / "features" / "ember_v3.parquet", art / "v3.3" / "temporal_eval" / "ember_v3.parquet"):
        pf = pq.ParquetFile(p)
        for rg in range(pf.num_row_groups):
            t = pf.read_row_group(rg, columns=cols)
            sh = t.column("sha256").to_pylist()
            st = t.column("em_status").to_pylist()
            keep = [i for i, (s, ok) in enumerate(zip(sh, st)) if s in shas and s not in seen and ok == "ok"]
            # drop_duplicates("sha256") keeps the first occurrence, so a later bad-status duplicate never replaces it
            seen.update(s for s in sh if s in shas)
            if not keep:
                continue
            sub = t.take(keep)
            mat = np.column_stack([sub.column(c).to_numpy(zero_copy_only=False) for c in cols[2:]]).astype(np.float32)
            order += [sh[i] for i in keep]
            rows.append(mat)
            del t, sub
    return order, np.vstack(rows)


def bn_frame(art: Path, shas: list[str]) -> pd.DataFrame:
    """src.v7.experiment._bn() reading the v6 caches under `art` (read-only)."""
    from src.v6 import bn_capabilities, bn_hlil

    recs = []
    for sha in shas:
        row: dict[str, Any] = {"sha256": sha}
        for kind, mod, key in (("cap_cache", bn_capabilities, "cap6_status"), ("hlil_cache", bn_hlil, "hl6_status")):
            p = art / "v6" / kind / f"{sha}.json"
            doc = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {"analysis_status": "missing"}
            row[key] = doc.get("analysis_status", "missing")
            row.update(mod.features_from_doc(doc))
        recs.append(row)
    df = pd.DataFrame(recs)
    cap = [c for c in df.columns if c.startswith("cap6_") and c != "cap6_status"]
    hl = [c for c in df.columns if c.startswith("hl6_") and c != "hl6_status"]
    df.loc[~df["cap6_status"].isin(USABLE), cap] = np.nan
    df.loc[~df["hl6_status"].isin(USABLE), hl] = np.nan
    return df


def _stats(b: np.ndarray, m: np.ndarray) -> list[float]:
    b, m = b[~np.isnan(b)], m[~np.isnan(m)]
    return [_num(np.median(b)) if b.size else 0.0, _num(np.median(m)) if m.size else 0.0,
            round(float((b != 0).mean()), 3) if b.size else 0.0, round(float((m != 0).mean()), 3) if m.size else 0.0]


def _mode(v: np.ndarray) -> tuple[float, float]:
    vals, cnt = np.unique(v, return_counts=True)
    i = int(np.argmax(cnt))
    return _num(vals[i]), round(float(cnt[i] / len(v)), 4)


def _class(mask: np.ndarray, y: np.ndarray, flagged: np.ndarray, how: str) -> dict[str, Any]:
    return {"benign": int((mask & (y == 0)).sum()), "malicious": int((mask & (y == 1)).sum()),
            "benign_flagged_r1": int((mask & (y == 0) & flagged).sum()),
            "malicious_flagged_r1": int((mask & (y == 1) & flagged).sum()), "how": how}


def section_slot(name: str) -> tuple[int, int]:
    """(slot, sign) of a lower-cased section name in thrember's section FeatureHasher(50)."""
    from sklearn.feature_extraction import FeatureHasher

    x = FeatureHasher(50, input_type="string").transform([[name]])
    return int(x.indices[0]), int(np.sign(x.data[0]))


def _cached(cache: Path | None, key: str, fn: Any) -> Any:
    """Optional pickle memo for slow steps (lets the build resume in short sessions). Never written next to the output."""
    if cache is None:
        return fn()
    p = cache / f"{key}.pkl"
    if p.is_file():
        with p.open("rb") as fh:
            return pickle.load(fh)
    v = fn()
    cache.mkdir(parents=True, exist_ok=True)
    with p.open("wb") as fh:
        pickle.dump(v, fh)
    return v


def build(art: Path, cache: Path | None = None) -> dict[str, Any]:
    import lightgbm as lgb

    from src.metrics import tpr_at_fpr
    from src.v8 import deploy
    from src.v8.ember_map import ember_feature_names

    warnings.filterwarnings("ignore")
    with _abs(CANDIDATE).open("rb") as fh:
        cand = pickle.load(fh)
    train = set(cand["training_sha256"])
    lab = labels(art)
    missing = [s for s in train if s not in lab]
    if missing:
        raise SystemExit(f"{len(missing)} training files have no label under {art}")
    shas, X = _cached(cache, "ember", lambda: ember_matrix(art, train))
    y = np.array([lab[s] for s in shas], dtype=int)
    counts = {"n": len(y), "benign": int((y == 0).sum()), "malicious": int((y == 1).sum())}
    if counts != {k: EXPECTED[k] for k in ("n", "benign", "malicious")}:
        raise SystemExit(f"recovered pool {counts} != expected {EXPECTED}")

    names = ember_feature_names()
    booster = lgb.Booster(model_file=str(deploy.ensure_ember_model(download=False)))
    r1 = booster.predict(X.astype(np.float64))
    ops = {f"fpr_{f:g}": float(tpr_at_fpr(y, r1, f)["threshold"]) for f in FPRS}
    if abs(ops["fpr_0.01"] - R1_THR_1PCT) > 1e-12 or abs(ops["fpr_0.01"] - float(cand["thr_r1"])) > 1e-12:
        raise SystemExit(f"R1 1% threshold {ops['fpr_0.01']!r} != frozen {R1_THR_1PCT!r}: wrong pool or model")
    op_rates = {}
    for k, t in ops.items():
        f = r1 >= t
        op_rates[k] = {"benign_flagged": int((f & (y == 0)).sum()), "malicious_flagged": int((f & (y == 1)).sum())}

    stats: dict[str, list[float]] = {}
    for j, n in enumerate(names):
        stats[n] = _stats(X[y == 0, j].astype(np.float64), X[y == 1, j].astype(np.float64))
    modes = {}
    for n in CATEGORICAL:
        j = names.index(n)
        bm, bs = _mode(X[y == 0, j])
        mm, ms = _mode(X[y == 1, j])
        modes[n] = [bm, mm, bs, ms]

    parts = [_cached(cache, f"bn_{i:05d}", lambda i=i: bn_frame(art, shas[i:i + 1000])) for i in range(0, len(shas), 1000)]
    bn = pd.concat(parts, ignore_index=True)
    cap_ok = bn["cap6_status"].isin(USABLE).to_numpy()
    hl_ok = bn["hl6_status"].isin(USABLE).to_numpy()
    both = cap_ok & hl_ok
    if int(cap_ok.sum()) != EXPECTED["bn_cap6"] or int(cap_ok.sum()) != int(cand["train_bn_rows"]):
        raise SystemExit(f"{int(cap_ok.sum())} pool rows have usable cap6 features, expected {EXPECTED['bn_cap6']} (train_bn_rows)")
    for c in cand["cols"]:
        rows = cap_ok if c.startswith("cap6_") else hl_ok
        v = bn[c].to_numpy(dtype=float) if c in bn.columns else np.full(len(bn), np.nan)
        stats[c] = _stats(v[rows & (y == 0)], v[rows & (y == 1)])

    col = {n: X[:, j] for j, n in enumerate(names)}
    flagged = r1 >= ops["fpr_0.01"]
    u0, s0 = section_slot("upx0")
    u1, s1 = section_slot("upx1")
    nd, sn = section_slot(".ndata")
    upx = ((np.sign(col[f"em_section_vsize_hash_{u0:02d}"]) == s0) & (col[f"em_section_size_hash_{u0:02d}"] == 0)
           & (np.sign(col[f"em_section_size_hash_{u1:02d}"]) == s1))
    nsis = (np.sign(col[f"em_section_vsize_hash_{nd:02d}"]) == sn) & (col[f"em_section_size_hash_{nd:02d}"] == 0)
    classes = {
        "nsis": _class(nsis, y, flagged, f"approximate: the hashed section slot of '.ndata' (slot {nd}) has memory size with this "
                                         "name's sign and no data on disk, as NSIS's .ndata section does; other names in that slot can match"),
        "upx": _class(upx, y, flagged, f"approximate: hashed section slots of 'upx0' (slot {u0}: memory size, nothing on disk) and "
                                       f"'upx1' (slot {u1}: data on disk) both show those names' signs; other names in those slots can match"),
        "dotnet": _class(col["em_datadirectories_com_descriptor_size"] > 0, y, flagged, ".NET (CLR) data directory has a non-zero size"),
        "signature_block": _class(col["em_datadirectories_security_size"] > 0, y, flagged,
                                  "Authenticode certificate table has a non-zero size (validity not checked)"),
        "high_entropy_overlay": _class(col["em_section_overlay_entropy"] > 7.2, y, flagged, "appended data (overlay) entropy > 7.2 bits/byte"),
    }
    bn_n = {k: {"benign": int((m & (y == 0)).sum()), "malicious": int((m & (y == 1)).sum())}
            for k, m in (("cap6", cap_ok), ("hl6", hl_ok), ("both", both))}
    return {
        "model_tag": "v8",
        "pool": "V8 training pool (candidate.pkl training_sha256); EMBER2024 itself was trained elsewhere",
        "n": {"benign": counts["benign"], "malicious": counts["malicious"]},
        "n_bn": bn_n,
        "columns": ["benign_median", "malicious_median", "benign_nonzero", "malicious_nonzero"],
        "features": stats,
        "modes_columns": ["benign_mode", "malicious_mode", "benign_mode_share", "malicious_mode_share"],
        "modes": modes,
        "classes": classes,
        "classes_flag_note": "benign_flagged_r1 / malicious_flagged_r1: files of the kind with EMBER2024 score >= r1_operating_points['fpr_0.01']",
        "r1_operating_points": ops,
        "r1_operating_points_pool_rates": op_rates,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--artifacts", type=Path, default=Path("artifacts"),
                    help="Research artifacts folder holding v4/, v3.3/, v6/ caches and manifests (read only)")
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--cache", type=Path, help="Folder for intermediate pickles (optional; holds per-file rows, keep it private)")
    args = ap.parse_args(argv)
    ref = build(args.artifacts, args.cache)
    out = _abs(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(ref, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size // 1024} KB): n={ref['n']} n_bn={ref['n_bn']}")
    print(f"R1 operating points: {ref['r1_operating_points']}")
    for k, v in ref["classes"].items():
        print(f"  {k:22} benign={v['benign']:5} (R1-flagged {v['benign_flagged_r1']:4})  malicious={v['malicious']:5}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
