import pytest
from pathlib import Path

from src.v2.v1_guard import assert_v2_write_allowed, is_protected_v1_path


def test_blocks_write_to_v1_models(tmp_path):
    v1_art = tmp_path / "artifacts"
    (v1_art / "models").mkdir(parents=True)
    target = v1_art / "models" / "random_forest__pe_v2.pkl"
    assert is_protected_v1_path(target, v1_art)
    with pytest.raises(PermissionError):
        assert_v2_write_allowed(target, v1_art)


def test_allows_v2_subdirectory(tmp_path):
    v1_art = tmp_path / "artifacts"
    v1_art.mkdir()
    v2_path = tmp_path / "artifacts_v2" / "development" / "week1_gate.json"
    assert not is_protected_v1_path(v2_path, v1_art)
    assert assert_v2_write_allowed(v2_path, v1_art) == v2_path.resolve()
