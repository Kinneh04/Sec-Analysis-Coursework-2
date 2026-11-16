import json
from pathlib import Path

import pytest

from src.v2.baseline import load_v1_comparator_manifest
from src.v2.config import load_v2_config


def test_v1_baseline_reproduction():
    if not Path("artifacts/evaluations/test_results_v2.csv").is_file():
        pytest.skip("local research artifact artifacts/evaluations/test_results_v2.csv not present (artifacts/ is not in git)")
    cfg = load_v2_config("configs/v2_experiment.yaml")
    manifest = load_v1_comparator_manifest(cfg["_v1_artifacts"])
    assert manifest["reproduction"]["pass"], manifest["reproduction"]["checks"]


def test_week1_gate_artifact_after_inspect():
    gate = Path("artifacts/v2/development/week1_gate.json")
    if not gate.is_file():
        pytest.skip("Run python -m src.v2.cli inspect first")
    g = json.loads(gate.read_text(encoding="utf-8"))
    assert g.get("gate") == "week1"
    assert g["claims"]["sota_claim_supported"] is False
    assert g["claims"]["v2_improvement_confirmed"] is False
