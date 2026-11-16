"""Predictor allow/deny lists and feature family tagging for the read-only audit."""

from __future__ import annotations

import re

import pandas as pd

from src.bn_feature_schema import METADATA_KEYS

FORBIDDEN_EXACT = frozenset(
    {
        "sha256",
        "label",
        "group_id",
        "split",
        "relative_path",
        "benign_root",
        "software_source",
        "source",
        "label_source",
        "batch_date",
        "imphash",
        "analysis_status",
        "analysis_duration_seconds",
        "extractor_version",
        "analyzer",
        "analyzer_version",
        "extractor_transport",
        "architecture",
        "coverage_policy",
        "feature_missing_reasons",
        "errors",
        "feature_missing_reasons_json",
        "pe_status",
        "pe_extractor",
        "bn_status",
        "bn_extractor",
        "bn_source",
        "bn_arch",
        "bn_error",
    }
)

FORBIDDEN_SUBSTRINGS = (
    "relative_path",
    "file_path",
    "malwarebazaar",
    "legacy_hlil",
    "label",
    "sha256",
    "group_id",
    "imphash",
)


# Hashed import-API count buckets, not the imphash identifier.
ALLOWED_PATTERNS = (
    re.compile(r"^pe_imphash_h\d{3}$"),
    re.compile(r"^pe_imp_bucket_\d+$"),
)


def is_forbidden_predictor(name: str) -> bool:
    if name in FORBIDDEN_EXACT:
        return True
    if any(p.match(name) for p in ALLOWED_PATTERNS):
        return False
    low = name.lower()
    return any(s in low for s in FORBIDDEN_SUBSTRINGS)


def pe_predictor_columns(df: pd.DataFrame) -> list[str]:
    cols = []
    for c in df.columns:
        if not c.startswith("pe_"):
            continue
        if is_forbidden_predictor(c):
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            cols.append(c)
    return sorted(cols)


def bn_predictor_columns(df: pd.DataFrame) -> list[str]:
    cols = []
    for c in df.columns:
        if not (c.startswith("bn_") or c.startswith("quality_")):
            continue
        if c in METADATA_KEYS or is_forbidden_predictor(c):
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            cols.append(c)
    return sorted(cols)


def feature_family(name: str) -> str:
    if name.startswith("pe_import") or "import" in name or name.startswith(("pe_imphash_h", "pe_imp_bucket_")):
        return "pe_imports"
    if name.startswith("pe_section") or name.startswith("pe_entropy"):
        return "pe_sections"
    if name.startswith("pe_"):
        return "pe_metadata"
    if name.startswith("quality_"):
        return "bn_quality"
    if "cfg" in name or "cyclomatic" in name or "blocks" in name:
        return "bn_cfg"
    if "mlil" in name or "il_" in name:
        return "bn_mlil"
    if name.startswith("bn_meta"):
        return "bn_meta"
    if name.startswith("bn_"):
        return "bn_other"
    return "other"


def validate_predictor_list(cols: list[str], *, strict: bool) -> list[str]:
    bad = [c for c in cols if is_forbidden_predictor(c)]
    if bad and strict:
        raise ValueError(f"Forbidden predictors in candidate list: {bad[:10]}")
    return bad
