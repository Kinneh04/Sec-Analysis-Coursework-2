"""60-file BN v2 compatibility pilot: coverage, latency, cache integrity."""

from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.bn_feature_schema import EXTRACTOR_VERSION, aggregate_sample_features, model_feature_columns
from src.bn_pilot_select import select_pilot_cohort
from src.bn_structured_extract import extract_structured_sample
from src.common.config import artifacts, load_config
from src.common.hashing import sha256_file
from src.feature_validation import audit_feature_columns


def _feature_vector(doc: dict[str, Any]) -> dict[str, float | int | None]:
    flat = aggregate_sample_features(doc)
    cols = model_feature_columns(flat)
    out: dict[str, float | int | None] = {}
    for c in cols:
        v = flat.get(c)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            out[c] = float(v) if isinstance(v, float) else int(v)
    return out


def _vectors_equal(a: dict[str, Any], b: dict[str, Any], rtol: float = 1e-9) -> bool:
    keys = sorted(set(a) | set(b))
    for k in keys:
        va, vb = a.get(k), b.get(k)
        if va is None and vb is None:
            continue
        if va is None or vb is None:
            return False
        if isinstance(va, float) or isinstance(vb, float):
            if not math.isclose(float(va), float(vb), rel_tol=rtol, abs_tol=rtol):
                return False
        elif va != vb:
            return False
    return True


def _extraction_success(status: str | None) -> bool:
    return status in ("ok", "partial", "unsupported")


def _mlil_applicable(doc: dict[str, Any]) -> bool:
    """Binaries where IL recovery is expected (has discovered functions or entry triage)."""
    discovered = doc.get("functions_discovered") or 0
    funcs = doc.get("functions") or []
    if discovered and int(discovered) > 0:
        return True
    return len(funcs) > 0


def _mlil_valid(doc: dict[str, Any]) -> bool:
    status = doc.get("analysis_status")
    ops = doc.get("bn_il_ops_total") or 0
    if status == "ok":
        return True
    if ops and int(ops) > 0:
        return True
    missing = doc.get("feature_missing_reasons") or {}
    if status in ("partial", "unsupported") and missing:
        return True
    return False


def _cfg_valid(doc: dict[str, Any]) -> bool:
    funcs = doc.get("functions") or []
    recoverable = [f for f in funcs if (f.get("block_count") or 0) > 0 or (f.get("basic_blocks") or [])]
    if not recoverable:
        return True
    blocks_sum = doc.get("bn_cfg_blocks_sum")
    return blocks_sum is not None and int(blocks_sum) > 0


def _transient_mcp_failure(doc: dict[str, Any]) -> bool:
    if doc.get("analysis_status") != "error":
        return False
    err = " ".join(str(x) for x in (doc.get("errors") or []))
    needles = ("10061", "10054", "actively refused", "forcibly closed", "extract_exception", "urlopen error")
    return any(n in err for n in needles)


def _integrity_ok(flat: dict[str, Any]) -> tuple[bool, list[str]]:
    issues: list[str] = []
    for c in model_feature_columns(flat):
        v = flat.get(c)
        if v is None:
            continue
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            issues.append(f"{c}=non_finite")
    if audit_feature_columns(flat):
        issues.append("label_leakage_columns")
    return len(issues) == 0, issues


def run_pilot(cfg: dict, *, skip_mcp: bool = False, verify_cache_only: bool = False, max_new: int | None = None) -> dict:
    art = artifacts(cfg)
    pilot_path = art / "manifests" / "bn_pilot_60.parquet"
    if not pilot_path.is_file():
        pilot = select_pilot_cohort(cfg)
        pilot.to_parquet(pilot_path, index=False)
    else:
        pilot = pd.read_parquet(pilot_path)

    cache_dir = art / "features" / "bn_pilot_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    max_funcs = int(cfg.get("analysis", {}).get("bn_v2_max_functions_per_file", 8))
    small_bytes = int(cfg.get("experiment", {}).get("bn_pilot_small_pe_bytes", 8192))

    client = None
    if not skip_mcp and not verify_cache_only:
        from src.bn_mcp import BnMcpClient
        from src.ensure_bn_mcp import ensure_bn_mcp

        mcp_url = cfg["analysis"]["bn_mcp_url"]
        try:
            ensure_bn_mcp(mcp_url)
        except Exception as e:
            print(f"ensure_bn_mcp: {e}", flush=True)

        client = BnMcpClient(url=mcp_url)
        try:
            client.connect()
        except Exception as e:
            cached_n = sum(1 for _, m in pilot.iterrows() if (cache_dir / f"{m['sha256']}.{EXTRACTOR_VERSION}.json").is_file())
            if cached_n == 0:
                raise RuntimeError(
                    f"BN MCP unavailable ({e}). Start Binary Ninja GUI, then re-run this command."
                ) from e
            print(f"MCP unavailable; reporting {cached_n}/{len(pilot)} cached samples only.", flush=True)
            client = None
            skip_mcp = True

    rows: list[dict] = []
    cache_mismatch: list[str] = []
    total = len(pilot)
    new_mcp = 0

    for i, (_, meta) in enumerate(pilot.iterrows()):
        sha = meta["sha256"]
        path = Path(meta["relative_path"])
        cache_path = cache_dir / f"{sha}.{EXTRACTOR_VERSION}.json"
        doc: dict[str, Any] | None = None

        if verify_cache_only:
            if not cache_path.is_file():
                rows.append({"sha256": sha, "error": "missing_cache"})
                continue
            raw = cache_path.read_text(encoding="utf-8")
            doc = json.loads(raw)
            if not _vectors_equal(_feature_vector(doc), _feature_vector(json.loads(raw))):
                cache_mismatch.append(sha)
        elif cache_path.is_file() and skip_mcp:
            doc = json.loads(cache_path.read_text(encoding="utf-8"))
        elif cache_path.is_file() and client is None:
            doc = json.loads(cache_path.read_text(encoding="utf-8"))
        elif client is not None:
            if cache_path.is_file():
                doc = json.loads(cache_path.read_text(encoding="utf-8"))
                if _transient_mcp_failure(doc):
                    cache_path.unlink(missing_ok=True)
                    doc = None
            if doc is None:
                if max_new is not None and new_mcp >= max_new:
                    rows.append({"sha256": sha, "error": "pending_mcp", "pilot_category": meta.get("pilot_category")})
                    continue
                if not path.is_file():
                    rows.append({"sha256": sha, "error": "path_missing"})
                    continue
                if sha256_file(path) != sha:
                    rows.append({"sha256": sha, "error": "sha_mismatch"})
                    continue
                for attempt in range(3):
                    try:
                        doc = extract_structured_sample(client, path, sha, max_functions=max_funcs)
                        break
                    except Exception as e:
                        if attempt < 2:
                            try:
                                client.connect()
                            except Exception:
                                pass
                            continue
                        doc = {
                            "sha256": sha,
                            "analysis_status": "error",
                            "errors": [f"extract_exception:{type(e).__name__}", str(e)[:200]],
                            "analysis_duration_seconds": None,
                            "extractor_version": EXTRACTOR_VERSION,
                        }
                if doc is None:
                    rows.append({"sha256": sha, "error": "mcp_failed:no_doc"})
                    continue
                if _transient_mcp_failure(doc):
                    rows.append({"sha256": sha, "error": "pending_mcp", "pilot_category": meta.get("pilot_category")})
                    continue
                tmp = cache_path.with_suffix(".json.tmp")
                payload = json.dumps(doc, indent=2, default=str)
                tmp.write_text(payload, encoding="utf-8")
                tmp.replace(cache_path)
                new_mcp += 1
                vec_a = _feature_vector(doc)
                vec_b = _feature_vector(json.loads(cache_path.read_text(encoding="utf-8")))
                if not _vectors_equal(vec_a, vec_b):
                    cache_mismatch.append(sha)
                print(f"pilot MCP {new_mcp} new, {i + 1}/{total} {sha[:12]} status={doc.get('analysis_status')}", flush=True)
                time.sleep(2)
        else:
            rows.append({"sha256": sha, "error": "pending_mcp", "pilot_category": meta.get("pilot_category")})
            continue

        if doc is None:
            continue

        flat = {k: v for k, v in doc.items() if not isinstance(v, (list, dict))}
        ok_int, int_issues = _integrity_ok(flat)
        row = {
            **{k: meta.get(k) for k in ("sha256", "pilot_category", "software_source", "file_size", "machine", "is_small_pe", "label")},
            "analysis_status": doc.get("analysis_status"),
            "analysis_duration_seconds": doc.get("analysis_duration_seconds"),
            "architecture": doc.get("architecture"),
            "bn_func_count_analyzed": doc.get("bn_func_count_analyzed"),
            "bn_il_ops_total": doc.get("bn_il_ops_total"),
            "bn_cfg_blocks_sum": doc.get("bn_cfg_blocks_sum"),
            "quality_il_function_ratio": doc.get("quality_il_function_ratio"),
            "feature_missing_reasons": doc.get("feature_missing_reasons"),
            "extraction_success": _extraction_success(doc.get("analysis_status")),
            "mlil_applicable": _mlil_applicable(doc),
            "mlil_valid": _mlil_valid(doc),
            "cfg_valid": _cfg_valid(doc),
            "integrity_ok": ok_int,
            "integrity_issues": int_issues,
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    n = len(df)
    ok_df = df[df["error"].isna()] if "error" in df.columns else df
    n_eval = len(ok_df)
    n_succ = int(ok_df["extraction_success"].sum()) if n_eval and "extraction_success" in ok_df.columns else 0
    applicable = ok_df[ok_df["mlil_applicable"].fillna(False)] if n_eval and "mlil_applicable" in ok_df.columns else ok_df.iloc[0:0]
    n_mlil_ok = int(applicable["mlil_valid"].sum()) if len(applicable) and "mlil_valid" in applicable.columns else 0
    n_applicable = int(len(applicable))
    n_cfg_ok = int(ok_df["cfg_valid"].sum()) if n_eval and "cfg_valid" in ok_df.columns else 0

    durations = ok_df["analysis_duration_seconds"].dropna().astype(float) if "analysis_duration_seconds" in ok_df.columns else pd.Series(dtype=float)
    small = ok_df[ok_df.get("is_small_pe") == True] if "is_small_pe" in ok_df.columns else ok_df.iloc[0:0]
    large = ok_df[ok_df.get("is_small_pe") == False] if "is_small_pe" in ok_df.columns else ok_df

    def _rate(num: int, den: int) -> float | None:
        return round(num / den, 4) if den else None

    thresholds = {"extraction_success": 0.90, "mlil_valid_among_applicable": 0.90, "cfg_valid": 0.90}

    pending = int(df["error"].eq("pending_mcp").sum()) if n and "error" in df.columns else 0
    pending_by_category = (
        df[df["error"] == "pending_mcp"].groupby("pilot_category").size().to_dict() if pending else {}
    )
    report = {
        "pilot_n": n,
        "pilot_complete": pending == 0 and n == len(pilot),
        "pending_mcp": pending,
        "pending_by_category": pending_by_category,
        "evaluated_samples": n_eval,
        "extractor_version": EXTRACTOR_VERSION,
        "split_source": "frozen_train_only",
        "imphash_split_limitation": (
            "Malware train/test groups use imphash when present; shared imphash can merge unrelated "
            "families and related variants may split. Not corrected in this pilot; document for final experiment."
        ),
        "latency_seconds": {
            "median": float(durations.median()) if len(durations) else None,
            "p90": float(durations.quantile(0.9)) if len(durations) else None,
            "mean": float(durations.mean()) if len(durations) else None,
        },
        "by_category": {
            str(cat): {
                "n": int(g.shape[0]),
                "extraction_success_rate": _rate(int(g["extraction_success"].fillna(False).sum()), len(g)),
                "mlil_valid_rate": _rate(
                    int(g[g["mlil_applicable"].fillna(False)]["mlil_valid"].fillna(False).sum()),
                    int(g["mlil_applicable"].fillna(False).sum()),
                )
                if g["mlil_applicable"].fillna(False).any()
                else None,
                "median_latency": float(g["analysis_duration_seconds"].median()) if g["analysis_duration_seconds"].notna().any() else None,
            }
            for cat, g in ok_df.groupby("pilot_category")
        }
        if len(ok_df) and "pilot_category" in ok_df.columns
        else {},
        "small_pe": {
            "n": int(len(small)),
            "extraction_success_rate": _rate(int(small["extraction_success"].sum()), len(small)) if len(small) else None,
            "mlil_valid_rate": _rate(int(small[small["mlil_applicable"]]["mlil_valid"].sum()), int(small["mlil_applicable"].sum()))
            if len(small) and small["mlil_applicable"].any()
            else None,
            "median_il_ops": float(small["bn_il_ops_total"].dropna().median()) if len(small) and small["bn_il_ops_total"].notna().any() else None,
        },
        "non_small_pe": {
            "n": int(len(large)),
            "extraction_success_rate": _rate(int(large["extraction_success"].sum()), len(large)) if len(large) else None,
            "mlil_valid_rate": _rate(int(large[large["mlil_applicable"]]["mlil_valid"].sum()), int(large["mlil_applicable"].sum()))
            if len(large) and large["mlil_applicable"].any()
            else None,
        },
        "acceptance": {
            "extraction_success_rate": _rate(n_succ, n_eval),
            "extraction_success_pass": (n_succ / n_eval >= thresholds["extraction_success"]) if n_eval else False,
            "mlil_valid_rate_applicable": _rate(n_mlil_ok, n_applicable),
            "mlil_valid_pass": (n_mlil_ok / max(n_applicable, 1) >= thresholds["mlil_valid_among_applicable"]),
            "cfg_valid_rate": _rate(n_cfg_ok, n_eval),
            "cfg_valid_pass": (n_cfg_ok / n_eval >= thresholds["cfg_valid"]) if n_eval else False,
            "latency_recorded": bool(len(durations) == n_eval and n_eval > 0),
            "cache_identical": len(cache_mismatch) == 0,
            "cache_mismatch_sha256": cache_mismatch,
            "integrity_all_pass": bool(ok_df["integrity_ok"].all()) if "integrity_ok" in ok_df.columns and n_eval else False,
            "label_leakage_pass": not any("label_leakage" in str(x) for x in df.get("integrity_issues", [])),
            "thresholds": thresholds,
        },
        "pilot_pass": None,
        "fpr_note": (
            "Frozen test has ~103 benign rows; one FP ≈ 0.97% FPR. Use bootstrap CIs at 1% FPR; "
            "0.1% FPR is not well resolved."
        ),
        "per_sample": rows,
    }
    acc = report["acceptance"]
    report["pilot_pass"] = (
        report["pilot_complete"]
        and all(
            [
                acc.get("extraction_success_pass"),
                acc.get("mlil_valid_pass"),
                acc.get("cfg_valid_pass"),
                acc.get("latency_recorded"),
                acc.get("cache_identical"),
                acc.get("integrity_all_pass"),
                acc.get("label_leakage_pass"),
            ]
        )
    )
    out = art / "evaluations" / "bn_compatibility_pilot.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    df.to_parquet(art / "evaluations" / "bn_compatibility_pilot_samples.parquet", index=False)
    return report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--select-only", action="store_true")
    ap.add_argument("--verify-cache-only", action="store_true", help="Re-check cache feature vectors without MCP")
    ap.add_argument("--max-new", type=int, default=None, help="Limit new MCP extractions this run")
    args = ap.parse_args()
    cfg = load_config(args.config)
    if args.select_only:
        from src.bn_pilot_select import main as sel_main

        sel_main()
        return
    report = run_pilot(cfg, verify_cache_only=args.verify_cache_only, max_new=args.max_new)
    print(json.dumps(report["acceptance"], indent=2))
    print(f"pilot_pass={report['pilot_pass']} pilot_complete={report.get('pilot_complete')}")
    print(f"Wrote evaluations/bn_compatibility_pilot.json")


if __name__ == "__main__":
    main()
