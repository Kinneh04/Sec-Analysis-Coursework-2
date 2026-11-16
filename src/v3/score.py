"""Score PE files with a frozen V3 model bundle (default: v3.2 candidate + baseline).

Read-only static analysis; files are never executed.

  python -m src.v3.score path\\to\\file.exe
  python -m src.v3.score --recursive C:\\Suspicious\\bin
  python -m src.v3.score --manifest files.csv --output scores.jsonl
"""

from __future__ import annotations

import argparse
import json
import pickle
import sys
from pathlib import Path
from typing import Any, Iterator

import pandas as pd

from src.common.hashing import sha256_file
from src.v3 import freeze
from src.v3.pe_features_v3 import extract_pe_v3, v3_predictor_columns
from src.v3.pe_v1_stable import extract_pe_v1_stable, v1s_predictor_columns

PE_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ""}


def load_bundle(tag: str = "v3.2", *, verify: bool = True) -> dict[str, Any]:
    layout = freeze.cohort_layout(tag)
    if verify:
        bad = freeze.verify(layout["freeze_path"], tag=tag)
        if bad:
            raise SystemExit(f"Freeze verification failed for {tag}: {bad[:3]}...")
    bundle = {}
    for name in ("pe_v3", "pe_v1s"):
        with layout["models"][name].open("rb") as fh:
            bundle[name] = pickle.load(fh)
    bundle["tag"] = tag
    bundle["freeze_path"] = layout["freeze_path"]
    return bundle


def _iter_paths(paths: list[Path], recursive: bool) -> Iterator[Path]:
    for root in paths:
        if root.is_file():
            yield root
            continue
        if not root.is_dir():
            continue
        it = root.rglob("*") if recursive else root.iterdir()
        for p in it:
            if p.is_file() and p.suffix.lower() in PE_SUFFIXES:
                yield p


def _feature_row(path: Path) -> dict[str, Any] | None:
    try:
        digest = sha256_file(path)
    except OSError:
        return None
    pe3 = extract_pe_v3(path, digest)
    if pe3.get("v3_status") != "ok":
        return None
    v1s = extract_pe_v1_stable(path)
    if v1s.get("v1s_status") != "ok":
        return None
    row = {"path": str(path), "sha256": digest, **pe3, **v1s}
    return row


def score_row(row: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
    frame = pd.DataFrame([row])
    out: dict[str, Any] = {"path": row["path"], "sha256": row["sha256"]}
    for arm, cols_fn in (("pe_v3", v3_predictor_columns), ("pe_v1s", v1s_predictor_columns)):
        spec = bundle[arm]
        cols = [c for c in spec["cols"] if c in frame.columns]
        prob = float(spec["model"].predict_proba(frame[cols])[:, 1][0])
        thr = float(spec["threshold"])
        out[f"{arm}_probability"] = prob
        out[f"{arm}_threshold"] = thr
        out[f"{arm}_flagged"] = prob >= thr
    out["recommended_arm"] = "pe_v3"
    out["flagged"] = out["pe_v3_flagged"]
    out["probability"] = out["pe_v3_probability"]
    out["model_tag"] = bundle["tag"]
    return out


def score_paths(paths: list[Path], bundle: dict[str, Any], *, recursive: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for path in _iter_paths(paths, recursive):
        row = _feature_row(path)
        if row is None:
            results.append({"path": str(path), "error": "pe_parse_failed"})
            continue
        results.append(score_row(row, bundle))
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="Files or directories to score")
    ap.add_argument("--manifest", type=Path, help="CSV with a path column")
    ap.add_argument("--recursive", action="store_true")
    ap.add_argument("--model-tag", default="v3.2")
    ap.add_argument("--verify-freeze", action="store_true", help="Require freeze manifest to match (fails after code updates)")
    ap.add_argument("--output", type=Path, help="Write JSON lines")
    ap.add_argument("--summary", action="store_true", help="Print counts only")
    args = ap.parse_args(argv)

    if not args.paths and args.manifest is None:
        ap.error("provide paths or --manifest")

    bundle = load_bundle(args.model_tag, verify=args.verify_freeze)
    if args.manifest:
        m = pd.read_csv(args.manifest) if args.manifest.suffix.lower() == ".csv" else pd.read_parquet(args.manifest)
        path_col = "path" if "path" in m.columns else "relative_path"
        targets = [Path(str(p)) for p in m[path_col]]
        scored = []
        for p in targets:
            row = _feature_row(p)
            scored.append(score_row(row, bundle) if row else {"path": str(p), "error": "pe_parse_failed"})
    else:
        scored = score_paths([Path(p) for p in args.paths], bundle, recursive=args.recursive)

    if args.summary:
        ok = [s for s in scored if "error" not in s]
        flagged = sum(1 for s in ok if s.get("flagged"))
        print(json.dumps({"model_tag": args.model_tag, "scored": len(ok), "parse_errors": len(scored) - len(ok), "flagged": flagged}, indent=2))
    else:
        for s in scored:
            print(json.dumps(s, default=str))

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as fh:
            for s in scored:
                fh.write(json.dumps(s, default=str) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
