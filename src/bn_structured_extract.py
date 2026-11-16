"""M2: structured BN extraction via GUI MCP (CFG tables + MLIL text)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from src.bn_feature_schema import (
    ANALYZER,
    EXTRACTOR_TRANSPORT,
    EXTRACTOR_VERSION,
    aggregate_function_record,
    aggregate_sample_features,
    select_functions_deterministic,
)
from src.bn_mcp import BnMcpClient, parse_tool_result
from src.bn_mcp_parse import (
    parse_basic_block_rows,
    parse_complexity_metrics,
    parse_fenced_body,
    parse_function_list_addresses,
    parse_mlil_instruction_lines,
)


def _tool_text(parsed: Any) -> str:
    if isinstance(parsed, str):
        return parsed
    if isinstance(parsed, dict):
        return parsed.get("_raw_markdown") or json.dumps(parsed)
    return ""


def _paginate_il(client: BnMcpClient, func: str, level: str = "mlil", page: int = 1000) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    errors: list[str] = []
    offset = 0
    while True:
        raw = parse_tool_result(
            client.call_tool_raw(
                "bn_function_il",
                {"function": func, "level": level, "offset": offset, "limit": page},
            )
        )
        if not raw.ok:
            errors.append(raw.error or "il_failed")
            break
        text = _tool_text(raw.data)
        meta = raw.data if isinstance(raw.data, dict) else {}
        body = parse_fenced_body(text, fence=level)
        lines.extend(parse_mlil_instruction_lines(body))
        truncated = str(meta.get("truncated", "")).lower() == "true"
        next_off = meta.get("nextOffset")
        if truncated and next_off is not None:
            try:
                offset = int(next_off)
                continue
            except (TypeError, ValueError):
                pass
        break
    return lines, errors


def extract_structured_sample(
    client: BnMcpClient,
    sample_path: Path,
    sha256: str,
    *,
    max_functions: int = 8,
    analyzer_version: str | None = None,
) -> dict[str, Any]:
    t0 = time.time()
    record: dict[str, Any] = {
        "sha256": sha256,
        "extractor_version": EXTRACTOR_VERSION,
        "analyzer": ANALYZER,
        "analyzer_version": analyzer_version,
        "extractor_transport": EXTRACTOR_TRANSPORT,
        "architecture": None,
        "analysis_status": "error",
        "analysis_duration_seconds": None,
        "functions_discovered": None,
        "functions": [],
        "coverage_policy": "deterministic_hash_subset",
        "bn_meta": {},
        "feature_missing_reasons": {},
        "errors": [],
    }
    open_handle = None
    try:
        opened = parse_tool_result(
            client.call_tool_raw("bn_open_item_open", {"path": sample_path.as_posix(), "setActive": True})
        )
        if not opened.ok or not isinstance(opened.data, dict):
            record["errors"].append(opened.error or "open_failed")
            return record
        oi = opened.data.get("openItem") or {}
        open_handle = oi.get("handle")
        views = opened.data.get("binaryViews") or []
        bv = next((v for v in views if v.get("recommended") or v.get("active")), views[0] if views else None)
        if bv:
            record["architecture"] = bv.get("architecture")
            client.call_tool_raw("bn_binary_view_set_active", {"binaryView": bv["handle"]})
        client.call_tool_raw("bn_analysis_update_and_wait", {})

        triage = parse_tool_result(client.call_tool_raw("bn_binary_view_triage", {}))
        if triage.ok and isinstance(triage.data, dict):
            fc = triage.data.get("functionCount")
            if fc is not None:
                try:
                    record["functions_discovered"] = int(fc)
                except (TypeError, ValueError):
                    pass
            record["bn_meta"] = {
                k: triage.data.get(k)
                for k in (
                    "segmentCount",
                    "sectionCount",
                    "symbolCount",
                    "stringCount",
                    "dataVariableCount",
                )
                if triage.data.get(k) is not None
            }

        all_addrs: list[str] = []
        off = 0
        while len(all_addrs) < 5000:
            fl = parse_tool_result(client.call_tool_raw("bn_function_list", {"offset": off, "limit": 200}))
            if not fl.ok:
                record["errors"].append(fl.error or "function_list_failed")
                break
            text = _tool_text(fl.data)
            chunk = parse_function_list_addresses(text)
            if not chunk:
                break
            all_addrs.extend(chunk)
            all_addrs = list(dict.fromkeys(all_addrs))
            meta = fl.data if isinstance(fl.data, dict) else {}
            if str(meta.get("truncated", "")).lower() != "true":
                break
            try:
                off = int(meta.get("nextOffset") or (off + len(chunk)))
            except (TypeError, ValueError):
                break

        if record["functions_discovered"] is None and all_addrs:
            record["functions_discovered"] = len(all_addrs)

        selected = select_functions_deterministic(all_addrs, sha256, max_functions)
        if not selected and triage.ok and isinstance(triage.data, dict) and triage.data.get("entryPoint"):
            selected = [str(triage.data["entryPoint"])]

        for func in selected:
            fn_errors: list[str] = []
            bb_raw = parse_tool_result(
                client.call_tool_raw("bn_function_basic_blocks", {"function": func, "limit": 1000})
            )
            bb_text = _tool_text(bb_raw.data) if bb_raw.ok else ""
            if not bb_raw.ok:
                fn_errors.append(bb_raw.error or "bb_failed")
            bb_rows = parse_basic_block_rows(bb_text)

            cx_raw = parse_tool_result(client.call_tool_raw("bn_function_complexity", {"function": func}))
            cx = parse_complexity_metrics(_tool_text(cx_raw.data)) if cx_raw.ok else {}

            mlil_lines, il_errs = _paginate_il(client, func, level="mlil")
            fn_errors.extend(il_errs)

            fn_rec = aggregate_function_record(func, bb_rows, cx, mlil_lines, fn_errors)
            fn_rec["basic_blocks"] = bb_rows
            record["functions"].append(fn_rec)

        if record["functions"]:
            record["analysis_status"] = "ok" if any(f.get("has_mlil") for f in record["functions"]) else "partial"
        elif record["errors"]:
            record["analysis_status"] = "error"
        else:
            record["analysis_status"] = "unsupported"
    except Exception as e:
        record["errors"].append(str(e)[:500])
        record["analysis_status"] = "error"
    finally:
        record["analysis_duration_seconds"] = round(time.time() - t0, 3)
        if open_handle:
            try:
                client.call_tool_raw("bn_open_item_close", {"openItem": open_handle})
            except Exception as e:
                record["errors"].append(f"close_failed:{type(e).__name__}:{str(e)[:120]}")

    flat = aggregate_sample_features(record)
    record["feature_values"] = {k: v for k, v in flat.items() if k.startswith(("bn_", "quality_"))}
    return {**record, **flat}
