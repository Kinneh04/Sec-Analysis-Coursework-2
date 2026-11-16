"""Binary Ninja structural features: labeler JSON cache + MCP triage for new files."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import pandas as pd

from src.bn_mcp import extract_triage_via_mcp
from src.common.config import artifacts, load_config

# v1 extractor: triage counts + legacy HLIL-regex features (see fix.md — not true MLIL).
EXTRACTOR_VERSION = "bn_v1_triage_hlil"

HLIL_OP_PATTERNS = {
    "mlil_call": re.compile(r"\b(?:call|Call|tailcall)\b"),
    "mlil_branch": re.compile(r"\bif\s*\("),
    "mlil_loop": re.compile(r"\bwhile\s*\("),
    "mlil_load": re.compile(r"\[\w"),
    "mlil_store": re.compile(r"\*\w|\[\w.*\]\s*="),
    "mlil_arith": re.compile(r"[+\-*/%]|<<|>>"),
    "mlil_compare": re.compile(r"==|!=|<=|>=|<|>"),
    "mlil_syscall_hint": re.compile(r"syscall|Nt[A-Z]|Zw[A-Z]", re.I),
}


def _hlil_histogram(excerpts: list[str]) -> dict[str, float]:
    joined = "\n".join(excerpts)
    n = max(len(joined), 1)
    counts = {k: 0 for k in HLIL_OP_PATTERNS}
    for name, pat in HLIL_OP_PATTERNS.items():
        counts[name] = len(pat.findall(joined))
    return {k: v / n for k, v in counts.items()}


def features_from_bn_json(doc: dict[str, Any]) -> dict[str, Any]:
    triage = doc.get("triage") or {}
    funcs = doc.get("functions") or []
    excerpts = [str(f.get("hlil_excerpt") or "") for f in funcs if f.get("hlil_excerpt")]
    hlil_chars = sum(len(x) for x in excerpts)

    out: dict[str, Any] = {
        "bn_status": "ok" if not doc.get("bn_error") else "error",
        "bn_extractor": EXTRACTOR_VERSION,
        "bn_source": doc.get("source"),
        "bn_arch": doc.get("arch"),
        "bn_error": doc.get("bn_error"),
        "cfg_function_count": (
            triage.get("functionCount")
            if triage.get("functionCount") is not None
            else (len(funcs) if funcs else None)
        ),
        "cfg_segment_count": triage.get("segmentCount"),
        "cfg_section_count": triage.get("sectionCount"),
        "cfg_symbol_count": triage.get("symbolCount"),
        "cfg_string_count": triage.get("stringCount"),
        "cfg_data_var_count": triage.get("dataVariableCount"),
        "cfg_hlil_sample_functions": len(funcs),
        "cfg_hlil_sample_chars": hlil_chars,
        "quality_bn_recovered": 1 if not doc.get("bn_error") else 0,
    }
    for k, v in _hlil_histogram(excerpts).items():
        out[f"legacy_hlil_regex_{k.replace('mlil_', '')}"] = v
    return out


def load_cache_json(cache_dir: Path, sha256: str) -> dict[str, Any] | None:
    p = cache_dir / f"{sha256}.json"
    if not p.is_file():
        return None
    with p.open(encoding="utf-8") as f:
        return json.load(f)


def _merge_docs(triage_doc: dict[str, Any], cache_doc: dict[str, Any] | None) -> dict[str, Any]:
    if not cache_doc:
        return triage_doc
    merged = dict(cache_doc)
    merged["triage"] = triage_doc.get("triage") or cache_doc.get("triage") or {}
    merged["arch"] = triage_doc.get("arch") or cache_doc.get("arch")
    merged["bn_error"] = triage_doc.get("bn_error") or cache_doc.get("bn_error")
    merged["source"] = "binaryninja_mcp_triage+cache_hlil"
    if cache_doc.get("functions"):
        merged["functions"] = cache_doc["functions"]
    return merged


def _run_v2(cfg: dict, inv: pd.DataFrame, limit: int | None, max_mcp: int) -> None:
    from src.bn_feature_schema import EXTRACTOR_VERSION
    from src.bn_structured_extract import extract_structured_sample
    from src.common.hashing import sha256_file
    from src.feature_validation import audit_feature_columns

    mcp_url = cfg.get("analysis", {}).get("bn_mcp_url", "http://127.0.0.1:24642/mcp")
    max_funcs = int(cfg.get("analysis", {}).get("bn_v2_max_functions_per_file", 8))
    art = artifacts(cfg)
    cache_dir = art / "features" / "bn_v2_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    from src.ensure_bn_mcp import ensure_bn_mcp

    ensure_bn_mcp(mcp_url)
    client = __import__("src.bn_mcp", fromlist=["BnMcpClient"]).BnMcpClient(url=mcp_url)
    client.connect()

    mal = inv[inv["label"] == "malicious"]
    ben = inv[inv["label"] == "benign"]
    ordered = []
    for i in range(max(len(mal), len(ben))):
        if i < len(mal):
            ordered.append(mal.iloc[i])
        if i < len(ben):
            ordered.append(ben.iloc[i])

    rows: list[dict] = []
    mcp_done = 0
    cache_hits = 0
    for row in ordered:
        sha = row["sha256"]
        path = Path(row["relative_path"])
        cache_path = cache_dir / f"{sha}.{EXTRACTOR_VERSION}.json"
        if cache_path.is_file():
            doc = json.loads(cache_path.read_text(encoding="utf-8"))
            cache_hits += 1
        elif mcp_done < max_mcp:
            if not path.is_file():
                continue
            digest = sha256_file(path)
            if digest != sha:
                continue
            doc = extract_structured_sample(client, path, sha, max_functions=max_funcs)
            cache_path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
            mcp_done += 1
            if mcp_done % 5 == 0:
                print(f"v2 MCP progress: {mcp_done}/{max_mcp}", flush=True)
        else:
            continue
        flat = {k: v for k, v in doc.items() if not isinstance(v, (list, dict))}
        if doc.get("feature_missing_reasons"):
            flat["feature_missing_reasons_json"] = json.dumps(doc["feature_missing_reasons"])
        flat["sha256"] = sha
        flat["label"] = row["label"]
        viol = audit_feature_columns(flat)
        if viol:
            raise RuntimeError(f"Feature leakage audit failed: {viol[:5]}")
        rows.append(flat)

    out = art / "features" / "bn_features_v2.parquet"
    pd.DataFrame(rows).to_parquet(out, index=False)
    durations = [float(r["analysis_duration_seconds"]) for r in rows if r.get("analysis_duration_seconds") is not None]
    cov = {
        "extractor_version": "bn_v2_structured_il",
        "rows": len(rows),
        "mcp_new_extractions": mcp_done,
        "cache_hits": cache_hits,
        "status_counts": pd.Series([r.get("analysis_status") for r in rows]).value_counts().to_dict(),
        "label_counts": pd.Series([r.get("label") for r in rows]).value_counts().to_dict(),
        "latency_seconds": {
            "median": float(pd.Series(durations).median()) if durations else None,
            "p90": float(pd.Series(durations).quantile(0.9)) if durations else None,
            "mean": float(pd.Series(durations).mean()) if durations else None,
        },
    }
    (art / "evaluations" / "bn_coverage_v2.json").write_text(json.dumps(cov, indent=2), encoding="utf-8")
    print(f"BN v2 features: {len(rows)} rows -> {out}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--cache-only", action="store_true", help="Skip MCP; use labeler BN JSON cache only")
    ap.add_argument("--extractor", choices=("v1", "v2"), default="v1")
    ap.add_argument("--fixture", default=None, help="v2: single PE path instead of inventory")
    args = ap.parse_args()
    cfg = load_config(args.config)
    inv = pd.read_parquet(artifacts(cfg) / "manifests" / "corpus_inventory.parquet")
    inv = inv[inv["inventory_status"] == "ok"]
    pilot_lim = cfg.get("experiment", {}).get("pilot_inventory_limit")
    use_pilot = bool(cfg.get("experiment", {}).get("use_pilot_inventory_limit", False))
    if args.extractor == "v2" and use_pilot and pilot_lim and not args.fixture and args.limit is None:
        half = int(pilot_lim) // 2
        inv = pd.concat(
            [
                inv[inv["label"] == "malicious"].head(half),
                inv[inv["label"] == "benign"].head(half),
            ],
            ignore_index=True,
        )
    elif args.limit:
        inv = inv.head(args.limit)

    max_mcp = int(
        cfg.get("analysis", {}).get("max_bn_mcp_calls")
        or cfg.get("experiment", {}).get("max_bn_mcp_benign", 400)
    )
    if args.extractor == "v2":
        if args.fixture:
            from src.common.hashing import sha256_file

            p = Path(args.fixture)
            inv = pd.DataFrame(
                [
                    {
                        "sha256": sha256_file(p),
                        "label": "benign_fixture",
                        "relative_path": str(p),
                        "inventory_status": "ok",
                    }
                ]
            )
        _run_v2(cfg, inv, args.limit, max_mcp if not args.fixture else 1)
        return

    cache_dir = Path(cfg["paths"]["bn_cache_dir"])
    mcp_url = cfg.get("analysis", {}).get("bn_mcp_url")
    out_rows: list[dict] = []
    mcp_done = 0
    mal = inv[inv["label"] == "malicious"]
    ben = inv[inv["label"] == "benign"]
    # Interleave so MCP budget covers both classes (inventory lists benign first).
    ordered = []
    for i in range(max(len(mal), len(ben))):
        if i < len(mal):
            ordered.append(mal.iloc[i])
        if i < len(ben):
            ordered.append(ben.iloc[i])

    for row in ordered:
        sha = row["sha256"]
        label = row["label"]
        path = Path(row["relative_path"])
        cache_doc = load_cache_json(cache_dir, sha)

        doc: dict[str, Any] | None = None
        if args.cache_only:
            doc = cache_doc
        elif mcp_done < max_mcp:
            triage_doc = extract_triage_via_mcp(path, sha, mcp_url=mcp_url)
            doc = _merge_docs(triage_doc, cache_doc)
            mcp_done += 1
            if mcp_done % 10 == 0:
                print(f"MCP triage progress: {mcp_done}/{max_mcp}", flush=True)
        elif cache_doc is not None:
            doc = cache_doc

        if doc is None:
            continue

        feats = features_from_bn_json(doc)
        feats["sha256"] = sha
        feats["label"] = label
        out_rows.append(feats)

    df = pd.DataFrame(out_rows)
    out = artifacts(cfg) / "features" / "bn_features.parquet"
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    print(f"BN features: {len(df)} rows (mcp_calls={mcp_done}) -> {out}")


if __name__ == "__main__":
    main()
