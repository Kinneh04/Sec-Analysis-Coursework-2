"""M6: score held-out challenge POCs (not used in training)."""

from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path

import pandas as pd

from src.bn_structured_extract import extract_structured_sample
from src.bn_mcp import BnMcpClient
from src.common.config import artifacts, load_config
from src.common.hashing import sha256_file
from src.pe_features import extract_pe_features


DEFAULT_CHALLENGE = [
    Path("Sample1/client.exe"),
    Path("Sample2/out/loader.exe"),
    Path("Sample2/out/helper.dll"),
    Path("Sample2/out/exec.dll"),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--run-id", default="lightgbm__pe_bn_v2")
    ap.add_argument("--mcp-bn", action="store_true", help="Extract v2 BN via MCP for challenge files")
    args = ap.parse_args()
    cfg = load_config(args.config)
    art = artifacts(cfg)
    model_path = art / "models" / f"{args.run_id}.pkl"
    if not model_path.is_file():
        raise SystemExit(f"Model not found: {model_path}")

    bundle = pickle.loads(model_path.read_bytes())
    cols = bundle["features"]
    pipe = bundle["pipeline"]
    threshold = bundle["threshold"]

    client = None
    if args.mcp_bn:
        client = BnMcpClient(url=cfg["analysis"]["bn_mcp_url"])
        client.connect()

    rows = []
    root = Path.cwd()
    for rel in DEFAULT_CHALLENGE:
        path = root / rel
        if not path.is_file():
            rows.append({"path": str(rel), "error": "missing"})
            continue
        sha = sha256_file(path)
        pe = extract_pe_features(path)
        bn_flat = {}
        if args.mcp_bn and client:
            doc = extract_structured_sample(client, path, sha, max_functions=8)
            bn_flat = {
                k: v
                for k, v in doc.items()
                if k.startswith(("bn_", "quality_")) and isinstance(v, (int, float))
            }
        row = {**pe, **{k: v for k, v in bn_flat.items() if k.startswith(("bn_", "quality_"))}}
        X = pd.DataFrame([{c: row.get(c) for c in cols}])
        score = float(pipe.predict_proba(X[cols])[:, 1][0])
        rows.append(
            {
                "path": str(rel),
                "sha256": sha,
                "score": score,
                "threshold": threshold,
                "predicted": "malicious" if score >= threshold else "benign",
                "ground_truth_note": "course_poc_malware_case_study",
            }
        )

    out = art / "evaluations" / "challenge_v2.json"
    out.write_text(json.dumps({"run_id": args.run_id, "results": rows}, indent=2), encoding="utf-8")
    print(f"Wrote {out}")
    for r in rows:
        print(r.get("path"), r.get("predicted"), r.get("score"))


if __name__ == "__main__":
    main()
