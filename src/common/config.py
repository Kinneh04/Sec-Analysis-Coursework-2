from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_config(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    with p.open(encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    root = p.parent.parent
    art = Path(cfg["paths"]["artifacts_dir"])
    if not art.is_absolute():
        cfg["paths"]["artifacts_dir"] = str((root / art).resolve())
    return cfg


def artifacts(cfg: dict[str, Any]) -> Path:
    return Path(cfg["paths"]["artifacts_dir"])
