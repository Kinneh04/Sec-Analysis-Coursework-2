from __future__ import annotations

from src.bn_feature_schema import aggregate_sample_features, cyclomatic_from_blocks


def test_cyclomatic_simple_chain():
    rows = [
        {"outgoing_edges": 1},
        {"outgoing_edges": 0},
    ]
    assert cyclomatic_from_blocks(rows) == 1


def test_aggregate_preserves_zero_function_count():
    record = {
        "functions_discovered": 0,
        "functions": [],
        "analysis_status": "partial",
        "bn_meta": {},
        "feature_missing_reasons": {},
    }
    out = aggregate_sample_features(record)
    assert out["bn_func_count_discovered"] == 0
    assert out["bn_il_ops_total"] is None


def test_aggregate_mlil_counts():
    record = {
        "functions_discovered": 1,
        "functions": [
            {
                "block_count": 2,
                "edge_count": 1,
                "cyclomatic": 1,
                "basic_blocks": [{"branch_outgoing": True, "has_back_edge": False, "outgoing_edges": 1}],
                "mlil_op_counts": {"mlil_call": 2, "mlil_return": 1, "mlil_tailcall": 0, "mlil_branch_cond": 0,
                    "mlil_branch_uncond": 0, "mlil_load": 0, "mlil_store": 0, "mlil_arith": 1,
                    "mlil_bitwise": 0, "mlil_compare": 0, "mlil_other": 0},
                "mlil_instruction_lines": 3,
                "has_mlil": True,
            }
        ],
        "bn_meta": {},
        "feature_missing_reasons": {},
    }
    out = aggregate_sample_features(record)
    assert out["bn_mlil_call_count"] == 2
    assert out["bn_mlil_call_rate"] is not None
    assert out["bn_cfg_blocks_sum"] == 2
