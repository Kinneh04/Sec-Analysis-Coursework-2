"""Summarize BN analysis duration from existing feature tables (no new extraction)."""

from __future__ import annotations

import pandas as pd


def duration_summary(bn: pd.DataFrame, sha_set: set[str] | None = None) -> dict:
    sub = bn
    if sha_set is not None:
        sub = bn[bn["sha256"].isin(sha_set)]
    col = "analysis_duration_seconds"
    if col not in sub.columns:
        return {"note": "analysis_duration_seconds not in BN parquet"}
    s = pd.to_numeric(sub[col], errors="coerce").dropna()
    if s.empty:
        return {"n": 0}
    return {
        "n": int(len(s)),
        "median_seconds": float(s.median()),
        "p90_seconds": float(s.quantile(0.9)),
        "p99_seconds": float(s.quantile(0.99)),
        "mean_seconds": float(s.mean()),
    }
