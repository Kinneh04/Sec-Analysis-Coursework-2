"""Feature matrix audits (leakage, label exclusion)."""

from __future__ import annotations

from typing import Any

from src.bn_feature_schema import METADATA_KEYS, model_feature_columns


FORBIDDEN_FEATURE_SUBSTRINGS = (
    "label",
    "malwarebazaar",
    "relative_path",
    "file_path",
    "bn_source",
    "sha256",
    "group_id",
    "legacy_hlil",
)


def audit_feature_columns(row: dict[str, Any]) -> list[str]:
    cols = model_feature_columns(row)
    violations = []
    for c in cols:
        low = c.lower()
        if c in METADATA_KEYS:
            violations.append(c)
            continue
        for bad in FORBIDDEN_FEATURE_SUBSTRINGS:
            if bad in low:
                violations.append(c)
    return violations
