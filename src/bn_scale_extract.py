"""Scaled BN v2 extraction: batched, checkpointed, class-monitored (frozen cohort)."""

from __future__ import annotations

import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import date
from pathlib import Path
from typing import Any

import pandas as pd

from src.bn_compatibility_pilot import _transient_mcp_failure
from src.bn_feature_schema import EXTRACTOR_VERSION, aggregate_sample_features
from src.common.config import artifacts, load_config
from src.common.hashing import sha256_file
from src.feature_validation import audit_feature_columns


def _scale_cfg(cfg: dict, *, accelerated: bool = False) -> dict:
    exp = cfg.get("experiment", {})
    sc = exp.get("bn_scale") or {}
    fast = accelerated or bool(sc.get("accelerated"))
    max_mb = float(sc.get("max_extract_file_mb", 4))
    max_bytes = int(max_mb * 1024 * 1024) if max_mb > 0 else 0
    skip_paths = [str(x).lower() for x in (sc.get("skip_path_contains") or [])]
    common = {
        "max_extract_bytes": max_bytes,
        "skip_path_contains": skip_paths,
        "per_binary_timeout_seconds": int(
            sc.get("per_binary_timeout_seconds", cfg.get("analysis", {}).get("max_seconds_per_file", 120))
        ),
        "mcp_fail_stop_streak": int(sc.get("mcp_fail_stop_streak", 3)),
        "max_bn_reboots_per_batch": int(sc.get("max_bn_reboots_per_batch", 10)),
        "reboot_on_mcp_failure": bool(sc.get("reboot_on_mcp_failure", True)),
    }
    if fast:
        return {
            **common,
            "accelerated": True,
            "batch_size": int(sc.get("accelerated_batch_size", 50)),
            "daily_budget_seconds": None,
            "max_retries": int(sc.get("accelerated_max_retries", 1)),
        }
    return {
        **common,
        "accelerated": False,
        "batch_size": int(sc.get("batch_size", 25)),
        "daily_budget_seconds": int(sc.get("daily_budget_seconds", 7200)),
        "max_retries": int(sc.get("max_retries", 2)),
    }


def _policy_skip_reason(row: pd.Series, path: Path, sc: dict) -> str | None:
    max_b = int(sc.get("max_extract_bytes") or 0)
    size = int(row.get("file_size") or 0)
    if max_b > 0 and size > max_b:
        return f"file_size_bytes={size}_exceeds_limit_{max_b}"
    low = str(path).lower()
    for frag in sc.get("skip_path_contains") or []:
        if frag and frag in low:
            return f"path_matches_skip_fragment:{frag}"
    return None


def _skip_document(sha: str, reason: str, label: str) -> dict[str, Any]:
    return {
        "sha256": sha,
        "extractor_version": EXTRACTOR_VERSION,
        "analysis_status": "skipped",
        "analysis_duration_seconds": 0.0,
        "errors": [],
        "feature_missing_reasons": {"bn_skip_policy": reason},
        "label": label,
    }


def _budget_exhausted(sc: dict, prog: dict, today: str) -> bool:
    cap = sc.get("daily_budget_seconds")
    if cap is None:
        return False
    return _daily_seconds_used(prog, today) >= cap


def _cache_path(cache_dir: Path, sha: str) -> Path:
    return cache_dir / f"{sha}.{EXTRACTOR_VERSION}.json"


def _atomic_write_json(path: Path, doc: dict) -> None:
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def _load_progress(path: Path) -> dict:
    if not path.is_file():
        return {"sessions": {}, "retry_counts": {}, "samples": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def _save_progress(path: Path, prog: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(prog, indent=2, default=str), encoding="utf-8")


def _daily_seconds_used(prog: dict, today: str) -> float:
    return float(prog.get("sessions", {}).get(today, {}).get("seconds_used", 0))


def _interleave_inventory(inv: pd.DataFrame) -> list[pd.Series]:
    mal = inv[inv["label"] == "malicious"].sort_values("sha256")
    ben = inv[inv["label"] == "benign"].sort_values("sha256")
    ordered: list[pd.Series] = []
    for i in range(max(len(mal), len(ben))):
        if i < len(mal):
            ordered.append(mal.iloc[i])
        if i < len(ben):
            ordered.append(ben.iloc[i])
    return ordered


def _needs_extraction(
    cache_path: Path, sha: str, prog: dict, max_retries: int
) -> bool:
    if not cache_path.is_file():
        return True
    doc = json.loads(cache_path.read_text(encoding="utf-8"))
    if _transient_mcp_failure(doc):
        return True
    status = doc.get("analysis_status")
    if status in ("ok", "partial", "unsupported", "skipped"):
        return False
    attempts = int(prog.get("retry_counts", {}).get(sha, 0))
    return attempts <= max_retries and status == "error"


def _bootstrap_progress_from_cache(prog: dict, inv: pd.DataFrame, cache_dir: Path) -> None:
    for _, row in inv.iterrows():
        sha = row["sha256"]
        cp = _cache_path(cache_dir, sha)
        if not cp.is_file() or sha in prog.get("samples", {}):
            continue
        doc = json.loads(cp.read_text(encoding="utf-8"))
        _record_sample(prog, sha, str(row["label"]), doc)
        if doc.get("analysis_status") == "error" and sha not in prog.get("retry_counts", {}):
            prog.setdefault("retry_counts", {})[sha] = 1


def _extract_with_timeout(client, path: Path, sha: str, max_funcs: int, timeout: int) -> dict:
    from src.bn_structured_extract import extract_structured_sample

    with ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(extract_structured_sample, client, path, sha, max_functions=max_funcs)
        try:
            return fut.result(timeout=timeout)
        except FuturesTimeout:
            return {
                "sha256": sha,
                "extractor_version": EXTRACTOR_VERSION,
                "analysis_status": "error",
                "errors": [f"timeout_after_{timeout}s"],
                "analysis_duration_seconds": float(timeout),
                "feature_missing_reasons": {"timeout": f"exceeded_{timeout}s"},
            }


def _record_sample(prog: dict, sha: str, label: str, doc: dict) -> None:
    samples = prog.setdefault("samples", {})
    status = doc.get("analysis_status", "error")
    samples[sha] = {
        "label": label,
        "analysis_status": status,
        "bn_il_ops_total": doc.get("bn_il_ops_total"),
        "bn_func_count_analyzed": doc.get("bn_func_count_analyzed"),
        "quality_il_function_ratio": doc.get("quality_il_function_ratio"),
        "analysis_duration_seconds": doc.get("analysis_duration_seconds"),
        "feature_missing_reasons": doc.get("feature_missing_reasons"),
    }
    if status == "error":
        rc = prog.setdefault("retry_counts", {})
        rc[sha] = int(rc.get(sha, 0)) + 1


def _summarize(prog: dict, inv: pd.DataFrame) -> dict:
    samples = prog.get("samples", {})
    by_label: dict[str, dict[str, int]] = {}
    for sha, row in inv.set_index("sha256").iterrows():
        label = row["label"]
        by_label.setdefault(label, {"ok": 0, "partial": 0, "unsupported": 0, "skipped": 0, "error": 0, "missing": 0})
        if sha not in samples:
            by_label[label]["missing"] += 1
            continue
        st = samples[sha].get("analysis_status", "error")
        by_label[label][st if st in by_label[label] else "error"] += 1

    il_ops: dict[str, list[float]] = {"benign": [], "malicious": []}
    for sha, meta in samples.items():
        lb = meta.get("label")
        ops = meta.get("bn_il_ops_total")
        if lb in il_ops and ops is not None:
            il_ops[lb].append(float(ops))

    def _rate(label: str, key: str) -> float | None:
        d = by_label.get(label, {})
        denom = sum(d.values()) - d.get("missing", 0)
        if not denom:
            return None
        return round((d.get("ok", 0) + d.get("partial", 0) + d.get("unsupported", 0)) / denom, 4)

    return {
        "inventory_n": int(len(inv)),
        "samples_recorded": len(samples),
        "by_label_status": by_label,
        "extraction_success_rate": {
            "benign": _rate("benign", "ok"),
            "malicious": _rate("malicious", "ok"),
            "overall": _rate("benign", "ok"),  # fixed below
        },
        "median_il_ops": {
            k: (float(pd.Series(v).median()) if v else None) for k, v in il_ops.items()
        },
    }


def rebuild_parquet(cfg: dict) -> int:
    from src.bn_feature_schema import EXTRACTOR_VERSION as EV

    art = artifacts(cfg)
    cache_dir = art / "features" / "bn_v2_cache"
    inv = pd.read_parquet(art / "manifests" / "corpus_inventory.parquet")
    inv = inv[inv["inventory_status"] == "ok"]
    rows: list[dict] = []
    for _, row in inv.iterrows():
        sha = row["sha256"]
        cp = _cache_path(cache_dir, sha)
        if not cp.is_file():
            continue
        doc = json.loads(cp.read_text(encoding="utf-8"))
        flat = {k: v for k, v in doc.items() if not isinstance(v, (list, dict))}
        if not flat.get("extractor_version"):
            flat.update(aggregate_sample_features(doc))
        flat["sha256"] = sha
        flat["label"] = row["label"]
        viol = audit_feature_columns(flat)
        if viol:
            continue
        rows.append(flat)
    out = art / "features" / "bn_features_v2.parquet"
    pd.DataFrame(rows).to_parquet(out, index=False)
    return len(rows)


def _is_blocking_mcp_error(doc: dict) -> bool:
    return _transient_mcp_failure(doc) or any(
        x in " ".join(str(e) for e in (doc.get("errors") or []))
        for x in ("extract_exception", "urlopen error", "10061", "10054")
    )


def run_scale_batch(cfg: dict, *, force_batch: int | None = None, accelerated: bool = False) -> dict:
    sc = _scale_cfg(cfg, accelerated=accelerated)
    batch_size = force_batch or sc["batch_size"]
    art = artifacts(cfg)
    cache_dir = art / "features" / "bn_v2_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    prog_path = art / "evaluations" / "bn_scale_progress.json"
    prog = _load_progress(prog_path)

    today = str(date.today())
    sess = prog.setdefault("sessions", {}).setdefault(today, {"seconds_used": 0.0, "batches": 0, "new_extractions": 0})
    if _budget_exhausted(sc, prog, today):
        summary = _summarize(prog, pd.read_parquet(art / "manifests" / "corpus_inventory.parquet"))
        return {"stopped": "daily_budget_exhausted", "summary": summary}

    inv = pd.read_parquet(art / "manifests" / "corpus_inventory.parquet")
    inv = inv[inv["inventory_status"] == "ok"].copy()
    _bootstrap_progress_from_cache(prog, inv, cache_dir)
    assign_path = art / "manifests" / "split_assignments.parquet"
    if assign_path.is_file():
        assign = pd.read_parquet(assign_path)[["sha256", "split"]]
        inv = inv.merge(assign, on="sha256", how="left")

    from src.bn_mcp import BnMcpClient
    from src.ensure_bn_mcp import ensure_bn_mcp, reboot_bn_mcp

    mcp_url = cfg["analysis"]["bn_mcp_url"]
    ensure_bn_mcp(mcp_url)
    client = BnMcpClient(url=mcp_url)
    client.connect()
    max_funcs = int(cfg.get("analysis", {}).get("bn_v2_max_functions_per_file", 8))

    queue = [r for r in _interleave_inventory(inv) if _needs_extraction(_cache_path(cache_dir, r["sha256"]), r["sha256"], prog, sc["max_retries"])]
    batch = queue[:batch_size]

    def _reconnect_client() -> None:
        nonlocal client
        client = BnMcpClient(url=mcp_url)
        client.connect()

    t_batch = time.time()
    new_count = 0
    bn_reboots = 0
    stopped_reason: str | None = None
    bi = 0
    while bi < len(batch):
        row = batch[bi]
        if _budget_exhausted(sc, prog, today):
            stopped_reason = "daily_budget_exhausted"
            break
        sha = row["sha256"]
        path = Path(row["relative_path"])
        cp = _cache_path(cache_dir, sha)
        had_cache = cp.is_file()
        t0 = time.time()
        doc: dict[str, Any] | None = None
        skip_reason = _policy_skip_reason(row, path, sc)
        if skip_reason:
            doc = _skip_document(sha, skip_reason, str(row["label"]))
        elif not path.is_file():
            doc = {"sha256": sha, "analysis_status": "error", "errors": ["path_missing"]}
        elif sha256_file(path) != sha:
            doc = {"sha256": sha, "analysis_status": "error", "errors": ["sha_mismatch"]}
        else:
            for attempt in range(sc["max_retries"] + 1):
                try:
                    doc = _extract_with_timeout(client, path, sha, max_funcs, sc["per_binary_timeout_seconds"])
                    break
                except Exception as e:
                    if sc.get("reboot_on_mcp_failure") and bn_reboots < sc["max_bn_reboots_per_batch"]:
                        try:
                            reboot_bn_mcp(mcp_url)
                            _reconnect_client()
                            bn_reboots += 1
                            continue
                        except Exception:
                            pass
                    if attempt >= sc["max_retries"]:
                        doc = {
                            "sha256": sha,
                            "analysis_status": "error",
                            "errors": [f"extract_exception:{type(e).__name__}", str(e)[:200]],
                        }
                    else:
                        try:
                            _reconnect_client()
                        except Exception:
                            if sc.get("reboot_on_mcp_failure") and bn_reboots < sc["max_bn_reboots_per_batch"]:
                                reboot_bn_mcp(mcp_url)
                                _reconnect_client()
                                bn_reboots += 1
        if doc is None:
            bi += 1
            continue
        if _transient_mcp_failure(doc) or _is_blocking_mcp_error(doc):
            if sc.get("reboot_on_mcp_failure") and bn_reboots < sc["max_bn_reboots_per_batch"]:
                try:
                    reboot_bn_mcp(mcp_url)
                    _reconnect_client()
                    bn_reboots += 1
                    continue
                except Exception as re:
                    print(f"BN reboot failed: {re}", flush=True)
            if _transient_mcp_failure(doc):
                bi += 1
                continue
        if not _transient_mcp_failure(doc):
            _atomic_write_json(cp, doc)
        _record_sample(prog, sha, str(row["label"]), doc)
        if not had_cache:
            new_count += 1
        elapsed = time.time() - t0
        sess["seconds_used"] = float(sess.get("seconds_used", 0)) + elapsed
        sess["new_extractions"] = int(sess.get("new_extractions", 0)) + (0 if had_cache else 1)
        prog["last_sha256"] = sha
        prog["last_status"] = doc.get("analysis_status")
        prog["last_bn_reboots_batch"] = bn_reboots
        _save_progress(prog_path, prog)
        print(
            f"scale {sha[:12]} label={row['label']} status={doc.get('analysis_status')} "
            f"il_ops={doc.get('bn_il_ops_total')} sec={elapsed:.1f}",
            flush=True,
        )
        time.sleep(2)
        bi += 1

    if bn_reboots >= sc["max_bn_reboots_per_batch"] and bi < len(batch):
        stopped_reason = "mcp_reboot_limit"

    sess["batches"] = int(sess.get("batches", 0)) + 1
    _save_progress(prog_path, prog)

    summary = _summarize(prog, inv)
    ben = summary["by_label_status"].get("benign", {})
    mal = summary["by_label_status"].get("malicious", {})
    b_den = sum(ben.values()) - ben.get("missing", 0)
    m_den = sum(mal.values()) - mal.get("missing", 0)
    def _succ(d: dict) -> int:
        return d.get("ok", 0) + d.get("partial", 0) + d.get("unsupported", 0)

    summary["extraction_success_rate"] = {
        "benign": round(_succ(ben) / b_den, 4) if b_den else None,
        "malicious": round(_succ(mal) / m_den, 4) if m_den else None,
    }
    summary["skipped_by_policy"] = {
        "benign": ben.get("skipped", 0),
        "malicious": mal.get("skipped", 0),
    }
    ok_b = summary["extraction_success_rate"]["benign"] or 0
    ok_m = summary["extraction_success_rate"]["malicious"] or 0
    if b_den and m_den:
        summary["extraction_success_rate"]["overall"] = round((_succ(ben) + _succ(mal)) / (b_den + m_den), 4)

    parquet_rows = rebuild_parquet(cfg)
    cov_path = art / "evaluations" / "bn_coverage_v2.json"
    remaining = len([r for r in _interleave_inventory(inv) if _needs_extraction(_cache_path(cache_dir, r["sha256"]), r["sha256"], prog, sc["max_retries"])])
    cov = {
        "extractor_version": EXTRACTOR_VERSION,
        "scale_mode": True,
        "accelerated": sc.get("accelerated", False),
        "parquet_rows": parquet_rows,
        "batch_new_extractions": new_count,
        "batch_elapsed_seconds": round(time.time() - t_batch, 2),
        "daily_seconds_used": sess["seconds_used"],
        "daily_budget_seconds": sc["daily_budget_seconds"],
        "pending_queue": remaining,
        "stopped_reason": stopped_reason,
        "monitoring": summary,
        "max_extract_bytes": sc.get("max_extract_bytes"),
        "note": "partial/unsupported/error/skipped rows retained in cache for bias analysis; not dropped.",
    }
    cov_path.write_text(json.dumps(cov, indent=2, default=str), encoding="utf-8")
    cov["queue_exhausted"] = remaining == 0 and stopped_reason is None
    return cov


def run_scale_until_complete(cfg: dict, *, accelerated: bool = True) -> dict:
    """Run sequential batches until queue empty, daily cap, or MCP instability."""
    from src.ensure_bn_mcp import ensure_bn_mcp

    reports: list[dict] = []
    batch_idx = 0
    while True:
        batch_idx += 1
        if accelerated and batch_idx > 1:
            time.sleep(5)
        try:
            ensure_bn_mcp(cfg["analysis"]["bn_mcp_url"])
        except Exception as e:
            return {
                "extraction_halted": True,
                "stopped_reason": "mcp_unavailable",
                "error": str(e)[:300],
            }
        rep = run_scale_batch(cfg, accelerated=accelerated)
        reports.append({"pending_queue": rep.get("pending_queue"), "stopped_reason": rep.get("stopped_reason")})
        if rep.get("stopped_reason") in ("mcp_unstable", "mcp_reboot_limit"):
            from src.ensure_bn_mcp import reboot_bn_mcp

            try:
                reboot_bn_mcp(cfg["analysis"]["bn_mcp_url"])
                time.sleep(5)
                continue
            except Exception as e:
                rep["extraction_halted"] = True
                rep["reboot_error"] = str(e)[:300]
                rep["batch_history_tail"] = reports[-5:]
                return rep
        if rep.get("queue_exhausted") or rep.get("pending_queue", 1) == 0:
            rep["extraction_complete"] = True
            return rep
        if rep.get("stopped_reason") == "daily_budget_exhausted":
            rep["extraction_complete"] = False
            return rep
        time.sleep(3)


def main() -> None:
    ap = argparse.ArgumentParser(description="Scaled BN v2 extraction (batched + daily budget).")
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--batch-size", type=int, default=None)
    ap.add_argument("--accelerated", action="store_true", help="No daily cap, batch 50, 1 retry")
    ap.add_argument("--until-complete", action="store_true", help="Loop batches until queue done or MCP stop")
    ap.add_argument("--run-pipeline", action="store_true", help="After extraction, train/eval/paired_eval")
    ap.add_argument("--rebuild-parquet-only", action="store_true")
    args = ap.parse_args()
    cfg = load_config(args.config)
    if args.rebuild_parquet_only:
        n = rebuild_parquet(cfg)
        print(f"Rebuilt bn_features_v2.parquet rows={n}")
        return
    fast = args.accelerated or bool(cfg.get("experiment", {}).get("bn_scale", {}).get("accelerated"))
    if args.until_complete:
        report = run_scale_until_complete(cfg, accelerated=fast)
    else:
        report = run_scale_batch(cfg, force_batch=args.batch_size, accelerated=fast)
    print(json.dumps({k: report[k] for k in report if k != "monitoring"}, indent=2, default=str))
    if report.get("extraction_complete") and (args.run_pipeline or args.until_complete):
        from src.run_controlled_experiment import run_pipeline

        run_pipeline(args.config)
    elif report.get("extraction_halted"):
        print("Extraction halted safely; cached records preserved. Re-run with --until-complete to resume.", flush=True)


if __name__ == "__main__":
    main()
