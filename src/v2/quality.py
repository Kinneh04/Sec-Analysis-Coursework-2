"""Label-independent BN analysis quality and eligibility (not predictors)."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd


QUALITY_NUMERIC = (
    "quality_func_analyzed_ratio",
    "quality_il_function_ratio",
    "quality_il_instruction_coverage",
    "bn_il_ops_total",
    "bn_il_functions_with_mlil",
    "bn_il_instruction_lines_total",
)


def _num(row: pd.Series, key: str, default: float = 0.0) -> float:
    v = row.get(key, default)
    if v is None or (isinstance(v, float) and np.isnan(v)) or pd.isna(v):
        return default
    return float(v)


def compute_eligibility(row: pd.Series) -> dict[str, float]:
    """Deterministic eligibility from documented quality fields (no analysis_status)."""
    ops = _num(row, "bn_il_ops_total", 0.0)
    funcs_mlil = _num(row, "bn_il_functions_with_mlil", 0.0)
    func_ratio = _num(row, "quality_func_analyzed_ratio", 0.0)
    il_cov = _num(row, "quality_il_instruction_coverage", 0.0)
    ops_per_func = ops / max(funcs_mlil, 1.0)
    # Zero IL ops => unknown/low coverage per V2 plan (not treated as benign signal).
    low_il = 1.0 if ops <= 0 else 0.0
    score = 0.4 * func_ratio + 0.3 * il_cov + 0.2 * min(ops_per_func / 50.0, 1.0) + 0.1 * (1.0 - low_il)
    return {
        "eligibility_score": float(np.clip(score, 0, 1)),
        "ops_per_analyzed_function": float(ops_per_func),
        "zero_il_flag": float(low_il),
    }


def summarize_coverage_by_class(
    frame: pd.DataFrame,
    *,
    split_col: str | None = None,
) -> pd.DataFrame:
    rows = []
    df = frame.copy()
    if split_col and split_col in df.columns:
        groups = [("all", df)] + [(f"split={s}", df[df[split_col] == s]) for s in sorted(df[split_col].unique())]
    else:
        groups = [("all", df)]
    for gname, sub in groups:
        for lab in (0, 1):
            part = sub[sub["label"] == lab]
            n = len(part)
            if n == 0:
                continue
            st = part.get("bn_record_status", pd.Series(dtype=object))
            for status in ("ok", "partial", "skipped", "error", "missing"):
                if status == "missing":
                    cnt = int(st.isna().sum()) if len(st) else n
                else:
                    cnt = int((st == status).sum()) if len(st) else 0
                rows.append({"group": gname, "label": lab, "bn_status": status, "count": cnt, "denominator": n})
            elig = part.apply(compute_eligibility, axis=1, result_type="expand")
            rows.append(
                {
                    "group": gname,
                    "label": lab,
                    "bn_status": "_eligibility_median",
                    "count": float(elig["eligibility_score"].median()) if len(elig) else float("nan"),
                    "denominator": n,
                }
            )
    return pd.DataFrame(rows)


def coverage_by_source_size(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    df = frame.copy()
    df["size_mb"] = pd.to_numeric(df.get("file_size"), errors="coerce") / (1024 * 1024)
    df["size_band"] = pd.cut(
        df["size_mb"],
        bins=[0, 1, 4, 16, 1e9],
        labels=["<=1MB", "1-4MB", "4-16MB", ">16MB"],
        include_lowest=True,
    )
    by_source = []
    for src, g in df.groupby(df["source"].fillna("unknown")):
        ok = (g["bn_record_status"].isin(("ok", "partial"))).mean() if "bn_record_status" in g.columns else float("nan")
        by_source.append({"source": str(src), "n": len(g), "bn_ok_or_partial_rate": float(ok)})
    by_size = []
    for band, g in df.groupby("size_band", observed=True):
        ok = (g["bn_record_status"].isin(("ok", "partial"))).mean() if "bn_record_status" in g.columns else float("nan")
        by_size.append({"size_band": str(band), "n": len(g), "bn_ok_or_partial_rate": float(ok)})
    return pd.DataFrame(by_source), pd.DataFrame(by_size)


def quality_feature_table(frame: pd.DataFrame) -> pd.DataFrame:
    cols = [c for c in QUALITY_NUMERIC if c in frame.columns]
    rows = []
    for c in cols:
        s = pd.to_numeric(frame[c], errors="coerce")
        for lab in (0, 1):
            sub = s[frame["label"] == lab]
            rows.append(
                {
                    "field": c,
                    "label": lab,
                    "n": int(sub.notna().sum()),
                    "median": float(sub.median()) if sub.notna().any() else float("nan"),
                    "p10": float(sub.quantile(0.1)) if sub.notna().sum() > 5 else float("nan"),
                    "p90": float(sub.quantile(0.9)) if sub.notna().sum() > 5 else float("nan"),
                    "zero_rate": float((sub.fillna(-1) == 0).mean()) if len(sub) else float("nan"),
                }
            )
    return pd.DataFrame(rows)
