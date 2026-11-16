"""Build bn4_* feature columns from the Binary Ninja V4 JSON cache (see docs/v4_preregistration.md)."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.v3.pe_features_v3 import stable_bucket
from src.v4.bn_extract import CACHE_DIR

API_BUCKETS = 256
NAME_BUCKETS = 128
KEYWORDS = ("http", ".exe", ".dll", "cmd", "powershell", "hkey", "\\\\")
CX_KEYS = ("Blocks", "Edges", "Calls", "Variables", "Total Bytes", "MLIL SSA Edge Count")
USABLE = ("ok", "partial")


def _stats(prefix: str, vals: list[float], out: dict[str, float]) -> None:
    a = np.asarray(vals, dtype=float)
    if a.size == 0:
        return
    out[f"{prefix}_mean"] = float(a.mean())
    out[f"{prefix}_max"] = float(a.max())


def features_from_doc(doc: dict[str, Any]) -> dict[str, float]:
    f: dict[str, float] = {}
    if doc.get("analysis_status") not in USABLE:
        return f
    for k in ("function_total", "string_total", "import_total", "symbolCount", "segmentCount", "sectionCount", "dataVariableCount"):
        v = doc.get(k)
        if v is not None:
            f[f"bn4_{k}"] = float(v)
    span = float(doc.get("image_span") or 0)
    f["bn4_image_span"] = span
    f["bn4_analysis_complete"] = float(bool(doc.get("analysis_complete")))

    funcs = doc.get("functions") or []
    n = len(funcs)
    f["bn4_fn_n"] = float(n)
    if n:
        bb = np.array([x["bb"] for x in funcs], dtype=float)
        size = np.array([x["size"] for x in funcs], dtype=float)
        f.update({
            "bn4_fn_bb_mean": bb.mean(), "bn4_fn_bb_median": float(np.median(bb)), "bn4_fn_bb_p90": float(np.quantile(bb, 0.9)),
            "bn4_fn_bb_max": bb.max(), "bn4_fn_bb_sum": bb.sum(),
            "bn4_fn_size_mean": size.mean(), "bn4_fn_size_p90": float(np.quantile(size, 0.9)), "bn4_fn_size_max": size.max(),
            "bn4_fn_size_sum": size.sum(),
            "bn4_fn_frac_sub": float(np.mean([x["name"].startswith("sub_") for x in funcs])),
            "bn4_fn_frac_auto": float(np.mean([x["auto"] for x in funcs])),
            "bn4_fn_frac_exported": float(np.mean([x["exported"] for x in funcs])),
            "bn4_fn_frac_bb1": float(np.mean(bb == 1)),
            "bn4_code_coverage": float(size.sum() / span) if span > 0 else np.nan,
        })
    names = np.zeros(NAME_BUCKETS)
    for x in funcs:
        if x["name"] and not x["name"].startswith("sub_"):
            names[stable_bucket(x["name"], NAME_BUCKETS)] += 1
    for i, c in enumerate(names):
        f[f"bn4_fname_h{i:03d}"] = math.log1p(c)

    top = doc.get("top_functions") or []
    for key in CX_KEYS:
        vals = [t["complexity"].get(key) for t in top]
        _stats(f"bn4_cx_{key.lower().replace(' ', '_')}", [v for v in vals if v is not None], f)
    _stats("bn4_cx_cyclomatic", [t["complexity"]["Edges"] - t["complexity"]["Blocks"] + 2 for t in top
                                 if t["complexity"].get("Edges") is not None and t["complexity"].get("Blocks") is not None], f)
    calls = [tuple(c) for t in top for c in t.get("callees", [])]
    f["bn4_calls_n"] = float(len(calls))
    api = np.zeros(API_BUCKETS)
    called = set()
    if calls:
        kinds = [c[0] for c in calls]
        f["bn4_calls_frac_import"] = kinds.count("import") / len(calls)
        f["bn4_calls_frac_func"] = kinds.count("func") / len(calls)
        f["bn4_calls_frac_unresolved"] = kinds.count("unresolved") / len(calls)
        for kind, name in calls:
            if kind == "import" and name:
                api[stable_bucket(name, API_BUCKETS)] += 1
                called.add(name)
    f["bn4_api_called_distinct"] = float(len(called))
    imp_total = float(doc.get("import_total") or 0)
    f["bn4_api_called_ratio"] = len(called) / imp_total if imp_total > 0 else np.nan
    for i, c in enumerate(api):
        f[f"bn4_api_h{i:03d}"] = math.log1p(c)

    strings = doc.get("strings") or []
    f["bn4_str_n"] = float(len(strings))
    if strings:
        types = [s["type"] for s in strings]
        lens = np.array([s["len"] for s in strings], dtype=float)
        f["bn4_str_ascii"] = float(types.count("AsciiString"))
        f["bn4_str_utf16"] = float(types.count("Utf16String"))
        f["bn4_str_utf32"] = float(types.count("Utf32String"))
        f["bn4_str_frac_utf16"] = f["bn4_str_utf16"] / len(strings)
        f["bn4_str_len_mean"] = float(lens.mean())
        f["bn4_str_len_max"] = float(lens.max())
        low = [s["text"].lower() for s in strings]
        for kw in KEYWORDS:
            f[f"bn4_str_kw_{kw.strip('.').replace(chr(92), 'bs')}"] = float(sum(kw in t for t in low))
    return f


def build(shas: list[str], cache_dir: Path = CACHE_DIR) -> pd.DataFrame:
    rows = []
    for sha in shas:
        p = cache_dir / f"{sha}.json"
        doc = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {"analysis_status": "missing"}
        rows.append({"sha256": sha, "bn4_status": doc.get("analysis_status", "missing"), **features_from_doc(doc)})
    return pd.DataFrame(rows)


def bn4_columns(df: pd.DataFrame) -> list[str]:
    return sorted(c for c in df.columns if c.startswith("bn4_") and c != "bn4_status")
