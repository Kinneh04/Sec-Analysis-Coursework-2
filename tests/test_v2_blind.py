from pathlib import Path

import pytest

from src.v2.blind import assert_run_once, validate_manifest_disjoint, write_run_lock


def test_disjoint_rejects_train_overlap(tmp_path):
    r = validate_manifest_disjoint(
        {"a", "b"},
        train_sha={"a"},
        val_sha=set(),
        test_sha=set(),
        challenge_sha=set(),
    )
    assert not r["pass"]


def test_allows_test_overlap_when_flagged():
    r = validate_manifest_disjoint(
        {"t1", "t2"},
        train_sha=set(),
        val_sha=set(),
        test_sha={"t1", "t2"},
        challenge_sha=set(),
        allow_test_overlap=True,
    )
    assert r["pass"]


def test_run_once_lock(tmp_path):
    lock = tmp_path / "evaluation_run.lock"
    write_run_lock(lock, {"n": 1})
    with pytest.raises(RuntimeError):
        assert_run_once(lock)
