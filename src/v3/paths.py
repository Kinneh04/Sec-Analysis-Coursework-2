"""Artifact paths for cohort tags under artifacts/ (e.g. v3, v3.1)."""

from __future__ import annotations

from pathlib import Path

from src.common.config import artifacts, load_config


def cohort_paths(config: str, tag: str) -> dict[str, Path]:
    root = artifacts(load_config(config)) / tag
    return {
        "root": root,
        "manifests": root / "manifests",
        "features": root / "features",
        "models": root / "models",
        "retrain": root / "retrain",
        "freeze": root / "freeze",
        "blind": root / "blind",
        "development": root / "development",
    }
