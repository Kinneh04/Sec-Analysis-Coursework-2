from __future__ import annotations

from src.feature_validation import audit_feature_columns


def test_no_label_leakage_in_v2_features():
    row = {
        "bn_func_count_analyzed": 3,
        "bn_mlil_call_count": 10,
        "quality_il_function_ratio": 0.5,
        "label": "malicious",
        "sha256": "deadbeef",
    }
    assert audit_feature_columns(row) == []
