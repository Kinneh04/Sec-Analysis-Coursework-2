"""Coverage, feature quality, and redundancy (train-primary)."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from scipy.stats import spearmanr

from src.audit.schema import bn_predictor_columns, feature_family, pe_predictor_columns


def coverage_tables(
    train: pd.DataFrame,
    val: pd.DataFrame,
    inventory: pd.DataFrame,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    frames = []
    for split_name, df in (("train", train), ("val", val)):
        sub = df.copy()
        sub["split"] = split_name
        frames.append(sub)
    all_df = pd.concat(frames, ignore_index=True)
    status_col = "bn_extraction_status" if "bn_extraction_status" in all_df.columns else None
    rows = []
    for split_name in ("train", "val"):
        for lab in (0, 1):
            sub = all_df[(all_df["split"] == split_name) & (all_df["label"] == lab)]
            n = len(sub)
            if status_col:
                for st, cnt in sub[status_col].fillna("missing_record").value_counts().items():
                    rows.append(
                        {
                            "split": split_name,
                            "label": lab,
                            "bn_status": st,
                            "count": int(cnt),
                            "denominator": n,
                        }
                    )
            else:
                rows.append(
                    {
                        "split": split_name,
                        "label": lab,
                        "bn_status": "unknown",
                        "count": n,
                        "denominator": n,
                    }
                )
    cov_df = pd.DataFrame(rows)
    summary: dict[str, Any] = {"by_split_label": rows}
    if "file_size" in all_df.columns and status_col:
        all_df["size_mb"] = pd.to_numeric(all_df["file_size"], errors="coerce") / (1024 * 1024)
        all_df["size_band"] = pd.cut(
            all_df["size_mb"],
            bins=[0, 1, 4, 16, 1e9],
            labels=["<=1MB", "1-4MB", ">4MB", ">16MB"],
            include_lowest=True,
        )
        band_rows = []
        for band, g in all_df.groupby("size_band", observed=True):
            ok = g[status_col].isin(("ok", "partial")).mean() if len(g) else float("nan")
            band_rows.append({"size_band": str(band), "n": len(g), "bn_ok_or_partial_rate": float(ok)})
        summary["size_band_coverage"] = band_rows
    return cov_df, summary


def feature_quality_table(train: pd.DataFrame) -> pd.DataFrame:
    cols = pe_predictor_columns(train) + bn_predictor_columns(train)
    rows = []
    for c in cols:
        s = train[c]
        miss = float(s.isna().mean())
        finite = s.dropna()
        zero_rate = float((finite == 0).mean()) if len(finite) else float("nan")
        rows.append(
            {
                "feature": c,
                "family": feature_family(c),
                "missing_pct_train": round(miss * 100, 4),
                "zero_rate_train": round(zero_rate, 4) if not np.isnan(zero_rate) else "",
                "nunique_train": int(finite.nunique()) if len(finite) else 0,
                "median_train": float(finite.median()) if len(finite) else float("nan"),
                "p01_train": float(finite.quantile(0.01)) if len(finite) > 10 else float("nan"),
                "p99_train": float(finite.quantile(0.99)) if len(finite) > 10 else float("nan"),
                "flag_gt95_missing": miss > 0.95,
                "flag_constant": int(finite.nunique()) <= 1 if len(finite) else True,
            }
        )
    return pd.DataFrame(rows)


def redundancy_groups(train: pd.DataFrame, *, rho_threshold: float = 0.95) -> pd.DataFrame:
    bn_cols = bn_predictor_columns(train)
    if len(bn_cols) < 2:
        return pd.DataFrame(columns=["feature_a", "feature_b", "spearman_rho"])
    mat = train[bn_cols].copy()
    for c in bn_cols:
        mat[c] = pd.to_numeric(mat[c], errors="coerce")
    pairs = []
    cols = bn_cols
    for i in range(len(cols)):
        for j in range(i + 1, len(cols)):
            a, b = cols[i], cols[j]
            sub = mat[[a, b]].dropna()
            if len(sub) < 20:
                continue
            if sub[a].nunique() <= 1 or sub[b].nunique() <= 1:
                continue
            rho, _ = spearmanr(sub[a], sub[b])
            if rho is not None and not np.isnan(rho) and abs(rho) >= rho_threshold:
                pairs.append({"feature_a": a, "feature_b": b, "spearman_rho": float(rho)})
    return pd.DataFrame(pairs)


def train_filter_bn_cols(train: pd.DataFrame, bn_cols: list[str]) -> list[str]:
    kept = []
    for c in bn_cols:
        s = train[c]
        if s.isna().mean() > 0.95:
            continue
        if s.nunique(dropna=True) <= 1:
            continue
        kept.append(c)
    return kept


def train_drop_redundant_bn(train: pd.DataFrame, bn_cols: list[str], pairs: pd.DataFrame) -> list[str]:
    drop: set[str] = set()
    for _, row in pairs.iterrows():
        a, b = row["feature_a"], row["feature_b"]
        if a not in bn_cols or b not in bn_cols:
            continue
        if a in drop or b in drop:
            continue
        drop.add(b)
    return [c for c in bn_cols if c not in drop]


def bn_missingness_by_class(train: pd.DataFrame, val: pd.DataFrame) -> dict[str, Any]:
    frames = pd.concat([train, val], ignore_index=True)
    status_col = "bn_extraction_status"
    out = {}
    if status_col not in frames.columns:
        return out
    ok = frames[status_col].isin(("ok", "partial"))
    for lab in (0, 1):
        sub = frames[frames["label"] == lab]
        n = len(sub)
        out[str(lab)] = {
            "n": n,
            "bn_ok_or_partial": int(ok.loc[sub.index].sum()),
            "rate": float(ok.loc[sub.index].mean()) if n else float("nan"),
        }
    return out
