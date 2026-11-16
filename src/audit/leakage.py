"""Leakage and confounding checks (train + validation descriptive stats)."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from src.audit.schema import bn_predictor_columns, pe_predictor_columns, validate_predictor_list


def schema_report(train: pd.DataFrame, val: pd.DataFrame, *, strict: bool) -> dict[str, Any]:
    pe = pe_predictor_columns(train)
    bn = bn_predictor_columns(train)
    validate_predictor_list(pe + bn, strict=strict)
    overlap = set(pe) & set(bn)
    const_train = [c for c in pe + bn if train[c].nunique(dropna=False) <= 1]
    const_val = [c for c in pe + bn if val[c].nunique(dropna=False) <= 1]
    all_missing_train = [c for c in pe + bn if train[c].isna().all()]
    return {
        "pe_predictor_count": len(pe),
        "bn_predictor_count": len(bn),
        "pe_bn_name_overlap": sorted(overlap),
        "constant_on_train": const_train,
        "constant_on_val": const_val,
        "all_missing_on_train": all_missing_train,
        "pe_columns_sample": pe[:15],
        "bn_columns_sample": bn[:15],
    }


def source_label_confounding(
    train: pd.DataFrame,
    val: pd.DataFrame,
    *,
    min_cell: int = 5,
) -> dict[str, Any]:
    frames = pd.concat([train.assign(_split="train"), val.assign(_split="val")], ignore_index=True)
    out: dict[str, Any] = {"by_source": {}, "by_software_source": {}, "note": "descriptive_only"}
    for col in ("source", "software_source"):
        if col not in frames.columns:
            continue
        tab = pd.crosstab(frames[col].fillna("unknown"), frames["label"])
        rates = {}
        for idx in tab.index:
            row = tab.loc[idx]
            n = int(row.sum())
            if n < min_cell:
                rates[str(idx)] = {"n": n, "suppressed": True}
                continue
            mal_n = int(row.get("malicious", row.get(1, 0)))
            rates[str(idx)] = {
                "n": n,
                "malicious_rate": float(mal_n / n) if n else float("nan"),
            }
        out[f"by_{col}"] = rates
    if "bn_extraction_status" in frames.columns:
        cov = pd.crosstab(frames["label"], frames["bn_extraction_status"])
        out["bn_status_by_label"] = {str(k): cov.loc[k].to_dict() for k in cov.index}
    return out


