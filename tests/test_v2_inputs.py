import pytest
from pathlib import Path
from src.audit.schema import is_forbidden_predictor
from src.v2.inputs import load_v2_inputs, run_input_audit, predictor_schema_lock, build_development_frame
from src.v2.quality import compute_eligibility


def test_v2_inputs_load_and_gate():
    if not Path("artifacts/manifests/split_assignments.parquet").is_file():
        pytest.skip("local research artifact artifacts/manifests/split_assignments.parquet not present (artifacts/ is not in git)")
    data = load_v2_inputs("configs/v2_experiment.yaml")
    audit = run_input_audit(data)
    assert audit["split_integrity"]["pass"]
    assert audit["development_rows"] > 600
    dev = build_development_frame(data)
    schema = predictor_schema_lock(dev, strict=False)
    assert schema["pe_predictor_count"] >= 10
    assert schema["bn_predictor_count"] >= 10
    assert not schema["forbidden_in_predictors"]


def test_eligibility_uses_no_status():
    row = {
        "bn_il_ops_total": 0,
        "bn_il_functions_with_mlil": 0,
        "quality_func_analyzed_ratio": 0.5,
        "quality_il_instruction_coverage": 0.5,
    }
    e = compute_eligibility(row)
    assert e["zero_il_flag"] == 1.0
    assert "analysis_status" not in row
    assert is_forbidden_predictor("analysis_status")
