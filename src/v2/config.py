from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from src.common.config import artifacts as v1_artifacts
from src.common.config import load_config


def load_v2_config(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    with p.open(encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    root = p.parent.parent
    v1_cfg = load_config(cfg["v2"]["v1_config"])
    art_v2 = Path(cfg["paths"]["artifacts_v2"])
    if not art_v2.is_absolute():
        art_v2 = (root / art_v2).resolve()
    fa = Path(cfg["paths"]["feature_audit_dir"])
    if not fa.is_absolute():
        fa = (root / fa).resolve()
    cfg["_root"] = root
    cfg["_v1_cfg"] = v1_cfg
    cfg["_v1_artifacts"] = v1_artifacts(v1_cfg)
    cfg["_v2_artifacts"] = art_v2
    cfg["_feature_audit"] = fa
    cfg["_protected_patterns"] = tuple(cfg.get("protected_v1_globs", []))
    return cfg
