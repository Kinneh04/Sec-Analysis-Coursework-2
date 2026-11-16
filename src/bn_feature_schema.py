"""Versioned BN v2 feature schema and aggregation (structured MCP records)."""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any

MLIL_OP_KEYS = (
    "mlil_call",
    "mlil_tailcall",
    "mlil_branch_cond",
    "mlil_branch_uncond",
    "mlil_return",
    "mlil_load",
    "mlil_store",
    "mlil_arith",
    "mlil_bitwise",
    "mlil_compare",
    "mlil_other",
)

EXTRACTOR_VERSION = "bn_v2_structured_il"
ANALYZER = "binaryninja"
EXTRACTOR_TRANSPORT = "mcp_structured"

# Model-input numeric prefixes (metadata excluded).
BN_V2_FEATURE_PREFIXES = ("bn_", "quality_")

METADATA_KEYS = frozenset(
    {
        "sha256",
        "label",
        "extractor_version",
        "analyzer",
        "analyzer_version",
        "extractor_transport",
        "architecture",
        "analysis_status",
        "analysis_duration_seconds",
        "coverage_policy",
        "feature_missing_reasons",
        "errors",
        "bn_source",
        "relative_path",
    }
)


def classify_mlil_line(line: str) -> dict[str, int]:
    """One MLIL text instruction line -> operation family counts (single primary + tags)."""
    counts = {k: 0 for k in MLIL_OP_KEYS}
    low = line.lower()
    if low.startswith("return "):
        counts["mlil_return"] = 1
        if "__tailcall" in low:
            counts["mlil_tailcall"] = 1
        return counts
    if low.startswith("if ") or " then " in low or " else " in low:
        counts["mlil_branch_cond"] = 1
        return counts
    if "__tailcall" in low:
        counts["mlil_tailcall"] = 1
        counts["mlil_call"] = 1
        return counts
    if re_call_like(line):
        counts["mlil_call"] = 1
        return counts
    if "=" in line:
        lhs, _, rhs = line.partition("=")
        if "[" in rhs:
            counts["mlil_load"] = 1
        if "[" in lhs:
            counts["mlil_store"] = 1
        if any(op in line for op in ("+", "-", "*", "/", "%", "<<", ">>")):
            counts["mlil_arith"] = 1
        if any(op in line for op in ("&", "|", "^", "~")):
            counts["mlil_bitwise"] = 1
        if any(op in line for op in ("==", "!=", "<=", ">=")):
            counts["mlil_compare"] = 1
        if sum(counts.values()) == 0:
            counts["mlil_other"] = 1
        return counts
    counts["mlil_other"] = 1
    return counts


def re_call_like(line: str) -> bool:
    if "(" not in line or ")" not in line:
        return False
    if line.strip().endswith(")"):
        return True
    return bool(re.search(r"\w+\([^)]*\)\s*$", line))


def cyclomatic_from_blocks(block_rows: list[dict[str, Any]]) -> int | None:
    if not block_rows:
        return None
    n = len(block_rows)
    e = sum(int(r.get("outgoing_edges") or 0) for r in block_rows)
    p = 1
    return e - n + 2 * p


def aggregate_function_record(
    func_addr: str,
    bb_rows: list[dict[str, Any]],
    complexity: dict[str, int | None],
    mlil_lines: list[str],
    errors: list[str],
) -> dict[str, Any]:
    block_count = len(bb_rows) if bb_rows else complexity.get("blocks")
    edge_count = sum(int(r.get("outgoing_edges") or 0) for r in bb_rows) if bb_rows else complexity.get("edges")
    mlil_counts = {k: 0 for k in MLIL_OP_KEYS}
    for ln in mlil_lines:
        for k, v in classify_mlil_line(ln).items():
            mlil_counts[k] += v
    il_total = sum(mlil_counts.values())
    cyc = cyclomatic_from_blocks(bb_rows)
    return {
        "address": func_addr,
        "block_count": block_count,
        "edge_count": edge_count,
        "cyclomatic": cyc,
        "mlil_instruction_lines": len(mlil_lines),
        "mlil_op_counts": mlil_counts,
        "mlil_ops_total": il_total,
        "errors": errors,
        "has_mlil": il_total > 0,
    }


def select_functions_deterministic(all_addrs: list[str], sha256: str, max_funcs: int) -> list[str]:
    if max_funcs <= 0 or not all_addrs:
        return []
    scored = sorted(
        all_addrs,
        key=lambda a: hashlib.sha256(f"{sha256}:{a}".encode()).hexdigest(),
    )
    return scored[: min(max_funcs, len(scored))]


def aggregate_sample_features(record: dict[str, Any]) -> dict[str, Any]:
    """Flatten structured sample record to model features + coverage metadata."""
    funcs: list[dict[str, Any]] = record.get("functions") or []
    discovered = record.get("functions_discovered")
    analyzed = len(funcs)
    blocks_sum = 0
    edges_sum = 0
    back_edges = 0
    branch_blocks = 0
    blocks_inspected = 0
    cyclomatics: list[int] = []
    func_block_counts: list[int] = []
    mlil_totals = {k: 0 for k in MLIL_OP_KEYS}
    il_lines_total = 0
    funcs_with_mlil = 0
    calls = 0
    tailcalls = 0
    for fn in funcs:
        bc = fn.get("block_count")
        if bc is not None:
            blocks_sum += int(bc)
            func_block_counts.append(int(bc))
        ec = fn.get("edge_count")
        if ec is not None:
            edges_sum += int(ec)
        cyc = fn.get("cyclomatic")
        if cyc is not None:
            cyclomatics.append(int(cyc))
        bb_rows = fn.get("basic_blocks") or []
        blocks_inspected += len(bb_rows)
        for r in bb_rows:
            if r.get("branch_outgoing"):
                branch_blocks += 1
            if r.get("has_back_edge"):
                back_edges += 1
        ops = fn.get("mlil_op_counts") or {}
        for k, v in ops.items():
            mlil_totals[k] += int(v)
        iln = int(fn.get("mlil_instruction_lines") or 0)
        il_lines_total += iln
        if fn.get("has_mlil"):
            funcs_with_mlil += 1
        calls += int(ops.get("mlil_call") or 0)
        tailcalls += int(ops.get("mlil_tailcall") or 0)

    il_ops_total = sum(mlil_totals.values())
    out: dict[str, Any] = {
        "extractor_version": record.get("extractor_version", EXTRACTOR_VERSION),
        "analyzer": record.get("analyzer", ANALYZER),
        "analyzer_version": record.get("analyzer_version"),
        "extractor_transport": record.get("extractor_transport", EXTRACTOR_TRANSPORT),
        "architecture": record.get("architecture"),
        "analysis_status": record.get("analysis_status"),
        "analysis_duration_seconds": record.get("analysis_duration_seconds"),
        "coverage_policy": record.get("coverage_policy"),
        "bn_func_count_discovered": discovered,
        "bn_func_count_analyzed": analyzed,
        "bn_cfg_blocks_sum": blocks_sum if blocks_inspected or func_block_counts else None,
        "bn_cfg_edges_sum": edges_sum if edges_sum else None,
        "bn_cfg_backedge_count": back_edges if blocks_inspected else None,
        "bn_cfg_branch_block_count": branch_blocks if blocks_inspected else None,
        "bn_cfg_blocks_mean": _mean(func_block_counts),
        "bn_cfg_blocks_p90": _p90(func_block_counts),
        "bn_cfg_cyclomatic_mean": _mean(cyclomatics),
        "bn_cfg_cyclomatic_p90": _p90(cyclomatics),
        "bn_il_instruction_lines_total": il_lines_total if il_lines_total else None,
        "bn_il_functions_with_mlil": funcs_with_mlil,
        "bn_il_ops_total": il_ops_total if il_ops_total else None,
        "quality_func_analyzed_ratio": (analyzed / discovered) if discovered else None,
        "quality_il_function_ratio": (funcs_with_mlil / analyzed) if analyzed else None,
        "quality_il_instruction_coverage": (il_ops_total / il_lines_total) if il_lines_total else None,
        "bn_indirect_call_ratio": None,
        "bn_unresolved_call_ratio": None,
    }
    meta = record.get("bn_meta") or {}
    for k, v in meta.items():
        out[f"bn_meta_{k}"] = v

    for op, cnt in mlil_totals.items():
        fname = op.replace("mlil_", "bn_mlil_")
        out[f"{fname}_count"] = cnt if il_ops_total else None
        out[f"{fname}_rate"] = (cnt / il_ops_total) if il_ops_total else None

    if calls + tailcalls > 0:
        out["bn_indirect_call_ratio"] = tailcalls / (calls + tailcalls)

    missing = record.get("feature_missing_reasons") or {}
    if not il_ops_total and analyzed:
        missing.setdefault("bn_il_ops_total", "no_mlil_lines_recovered")
    out["feature_missing_reasons"] = missing
    return out


def model_feature_columns(row: dict[str, Any]) -> list[str]:
    cols = []
    for k, v in row.items():
        if k in METADATA_KEYS:
            continue
        if k.startswith(BN_V2_FEATURE_PREFIXES) and isinstance(v, (int, float)) and not isinstance(v, bool):
            cols.append(k)
        if k.startswith("quality_") and isinstance(v, (int, float)) and not isinstance(v, bool):
            cols.append(k)
    return sorted(set(cols))


def _mean(vals: list[int | float]) -> float | None:
    if not vals:
        return None
    return float(sum(vals)) / len(vals)


def _p90(vals: list[int | float]) -> float | None:
    if not vals:
        return None
    s = sorted(vals)
    idx = max(0, min(len(s) - 1, math.ceil(0.9 * len(s)) - 1))
    return float(s[idx])
