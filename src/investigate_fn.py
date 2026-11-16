"""False-negative audit: BN recovery + feature separation for challenge POCs."""

from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

from src.bn_structured_extract import extract_structured_sample
from src.bn_mcp import BnMcpClient
from src.common.config import artifacts, load_config
from src.common.hashing import sha256_file
from src.pe_features import extract_pe_features

QUALitative_PATHS = [
    Path("Sample1/client.exe"),
    Path("Sample2/out/loader.exe"),
    Path("Sample2/out/helper.dll"),
    Path("Sample2/out/exec.dll"),
    Path("Sample2/out/protect.dll"),
    Path("Sample2/out/read_write.dll"),
    Path("Sample2/out/open.dll"),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--mcp", action="store_true", help="Run live v2 MCP extraction per POC")
    ap.add_argument("--model", default="random_forest__pe_bn_v2")
    args = ap.parse_args()
    cfg = load_config(args.config)
    art = artifacts(cfg)
    root = Path.cwd()

    train = pd.read_parquet(art / "splits" / "train.parquet")
    bn_cols = [c for c in train.columns if c.startswith(("bn_", "quality_")) and pd.api.types.is_numeric_dtype(train[c])]
    pe_cols = [c for c in train.columns if c.startswith("pe_") and pd.api.types.is_numeric_dtype(train[c])]

    benign_train = train[train["label"] == "benign"]
    mal_train = train[train["label"] == "malicious"]
    bn_benign_mean = benign_train[bn_cols].mean(numeric_only=True) if bn_cols else pd.Series(dtype=float)
    pe_benign_mean = benign_train[pe_cols].mean(numeric_only=True) if pe_cols else pd.Series(dtype=float)

    model_path = art / "models" / args.model
    if not model_path.suffix:
        model_path = model_path.with_suffix(".pkl")
    bundle = pickle.loads(model_path.read_bytes()) if model_path.is_file() else None

    bn_feat_path = art / "features" / "bn_features_v2.parquet"
    bn_by_sha: dict[str, dict] = {}
    if bn_feat_path.is_file():
        bndf = pd.read_parquet(bn_feat_path)
        if "sha256" in bndf.columns:
            for _, r in bndf.iterrows():
                bn_by_sha[str(r["sha256"])] = r.to_dict()

    client = None
    if args.mcp:
        client = BnMcpClient(url=cfg["analysis"]["bn_mcp_url"])
        client.connect()

    rows = []
    for rel in QUALitative_PATHS:
        path = root / rel
        if not path.is_file():
            rows.append({"path": str(rel), "error": "missing"})
            continue
        sha = sha256_file(path)
        pe = extract_pe_features(path)
        bn_doc = bn_by_sha.get(sha)
        if args.mcp and client:
            bn_doc = extract_structured_sample(client, path, sha, max_functions=12)
        row = {
            "path": str(rel),
            "sha256": sha,
            "pe_file_size": pe.get("pe_file_size"),
            "pe_import_count": pe.get("pe_import_count"),
            "analysis_status": bn_doc.get("analysis_status") if bn_doc else None,
            "bn_func_analyzed": bn_doc.get("bn_func_count_analyzed") if bn_doc else None,
            "bn_il_ops_total": bn_doc.get("bn_il_ops_total") if bn_doc else None,
            "bn_cfg_blocks_sum": bn_doc.get("bn_cfg_blocks_sum") if bn_doc else None,
            "quality_il_function_ratio": bn_doc.get("quality_il_function_ratio") if bn_doc else None,
            "feature_missing": bn_doc.get("feature_missing_reasons") if bn_doc else None,
        }
        if bundle:
            bn_part = {k: bn_doc.get(k) for k in bn_cols if bn_doc} if bn_doc else {}
            feat_row = {**pe, **bn_part}
            X = pd.DataFrame([{c: feat_row.get(c) for c in bundle["features"]}])
            score = float(bundle["pipeline"].predict_proba(X[bundle["features"]])[:, 1][0])
            row["model_score"] = score
            row["predicted"] = "malicious" if score >= bundle["threshold"] else "benign"
            row["bn_features_from_cache"] = bool(bn_doc and not args.mcp)
            if bn_doc and len(bn_cols):
                diffs = []
                for c in bn_cols:
                    v = feat_row.get(c)
                    bm = bn_benign_mean.get(c)
                    if v is not None and bm is not None and not (isinstance(v, float) and np.isnan(v)):
                        diffs.append(abs(float(v) - float(bm)))
                row["bn_l1_distance_to_benign_centroid"] = float(sum(diffs))
            elif not bn_doc:
                row["bn_l1_distance_to_benign_centroid"] = None
                row["note"] = "no_bn_features_run_with_--mcp_or_add_to_v2_cohort"
        rows.append(row)

    out = art / "evaluations" / "sample2_fn_audit.json"
    out.write_text(json.dumps({"model": args.model, "cases": rows}, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
