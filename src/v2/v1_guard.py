"""Prevent accidental writes to V1 artifact paths from V2 code."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Iterable

DEFAULT_PROTECTED = (
    "manifests/split_assignments.parquet",
    "manifests/cohort_frozen.json",
    "manifests/frozen_train_sha256.txt",
    "manifests/frozen_val_sha256.txt",
    "manifests/frozen_test_sha256.txt",
    "features/pe_features.parquet",
    "features/bn_features_v2.parquet",
    "evaluations/*",
    "models/*",
    "splits/*",
)


def _rel_under_v1_artifacts(path: Path, v1_art: Path) -> str | None:
    try:
        rel = path.resolve().relative_to(v1_art.resolve())
    except ValueError:
        return None
    return rel.as_posix()


def is_protected_v1_path(path: Path, v1_artifacts_root: Path, patterns: Iterable[str] = DEFAULT_PROTECTED) -> bool:
    rel = _rel_under_v1_artifacts(path, v1_artifacts_root)
    if rel is None:
        return False
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat):
            return True
    return False


def assert_v2_write_allowed(path: Path, v1_artifacts_root: Path, patterns: Iterable[str] = DEFAULT_PROTECTED) -> Path:
    """Resolve path and raise if it would overwrite a protected V1 artifact."""
    p = Path(path).resolve()
    if is_protected_v1_path(p, v1_artifacts_root, patterns):
        raise PermissionError(f"V2 write blocked: path is protected V1 artifact: {p}")
    return p
