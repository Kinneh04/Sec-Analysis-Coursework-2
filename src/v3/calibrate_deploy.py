"""Pick a deployment threshold from benign-only scores (model frozen).

  python -m src.v3.calibrate_deploy --benign-dir C:\\MyCleanGold --target-fpr 0.01
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from src.v3.score import load_bundle, score_paths


def benign_threshold(scores: np.ndarray, target_fpr: float) -> float:
    """Lowest threshold that flags at most floor(target_fpr * n) benign scores."""
    s = np.sort(np.asarray(scores, dtype=float))[::-1]
    k = int(np.floor(target_fpr * len(s)))
    if k >= len(s):
        return float(s[-1])
    return float(np.nextafter(s[k], np.inf))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--benign-dir", action="append", default=[])
    ap.add_argument("--benign-manifest", type=Path, default=None)
    ap.add_argument("--target-fpr", type=float, default=0.01)
    ap.add_argument("--model-tag", default="v3.2")
    ap.add_argument("--arm", choices=("pe_v3", "pe_v1s"), default="pe_v3")
    ap.add_argument("--recursive", action="store_true")
    ap.add_argument("--output", type=Path, default=Path("artifacts/deploy/calibration.json"))
    args = ap.parse_args(argv)

    bundle = load_bundle(args.model_tag, verify=False)
    if args.benign_manifest:
        import pandas as pd
        m = pd.read_csv(args.benign_manifest) if args.benign_manifest.suffix.lower() == ".csv" else pd.read_parquet(args.benign_manifest)
        col = "path" if "path" in m.columns else "relative_path"
        paths = [Path(str(p)) for p in m[col]]
        from src.v3.score import _feature_row, score_row
        scored = []
        for p in paths:
            row = _feature_row(p)
            scored.append(score_row(row, bundle) if row else None)
        scored = [s for s in scored if s]
    else:
        if not args.benign_dir:
            ap.error("provide --benign-dir or --benign-manifest")
        scored = score_paths([Path(d) for d in args.benign_dir], bundle, recursive=args.recursive)

    prob_key = f"{args.arm}_probability"
    probs = [s[prob_key] for s in scored if prob_key in s]
    if len(probs) < 50:
        print(f"WARNING: only {len(probs)} benign scores; FPR estimates will be coarse.")
    p = np.array(probs, dtype=float)
    thr = benign_threshold(p, args.target_fpr)
    out = {
        "model_tag": args.model_tag,
        "arm": args.arm,
        "n_benign": len(probs),
        "target_fpr": args.target_fpr,
        "recommended_threshold": thr,
        "achieved_fpr_at_threshold": float((p >= thr).mean()),
        "previous_frozen_threshold": float(bundle[args.arm]["threshold"]),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
