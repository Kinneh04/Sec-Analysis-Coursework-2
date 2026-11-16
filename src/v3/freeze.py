"""Freeze models, schema, thresholds, preregistration, cohort manifests and code by SHA-256."""

from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def cohort_layout(tag: str) -> dict[str, Any]:
    prereg = Path("docs/v3_preregistration.md") if tag == "v3" else Path(f"docs/{tag}_preregistration.md")
    manifests = [
        Path(f"artifacts/{tag}/manifests/new_split_assignments.parquet"),
        Path(f"artifacts/{tag}/manifests/new_corpus_inventory.parquet"),
        Path(f"artifacts/{tag}/manifests/new_corpus_freeze.json"),
        Path(f"artifacts/{tag}/features/pe_features_v3_new.parquet"),
        Path("artifacts/v3/features/pe_v1_stable.parquet"),
        Path(f"artifacts/{tag}/retrain/retrain_summary.json"),
    ]
    if tag == "v3.2":
        manifests.append(Path("artifacts/v3.2/retrain/tuning_selected.json"))
    return {
        "tag": tag,
        "freeze_path": Path(f"artifacts/{tag}/freeze/freeze_manifest.json"),
        "models": {
            "pe_v3": Path(f"artifacts/{tag}/models/final_pe_v3.pkl"),
            "pe_v1s": Path(f"artifacts/{tag}/models/final_pe_v1s.pkl"),
        },
        "prereg": prereg,
        "manifests": manifests,
    }


# Back-compat for blind.py imports
FREEZE_PATH = Path("artifacts/v3/freeze/freeze_manifest.json")
MODELS = cohort_layout("v3")["models"]


def sha256_path(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_commit() -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return None


def tracked_files(layout: dict[str, Any]) -> list[Path]:
    return [*layout["models"].values(), layout["prereg"], *layout["manifests"], *sorted(Path("src/v3").glob("*.py"))]


def build_manifest(layout: dict[str, Any]) -> dict[str, Any]:
    models = {}
    for name, p in layout["models"].items():
        with p.open("rb") as fh:
            b = pickle.load(fh)
        models[name] = {
            "path": p.as_posix(), "config": b["config"], "rule": b.get("rule"), "threshold": b["threshold"],
            "target_fpr": b["target_fpr"], "n_estimators": b.get("n_estimators"),
            "calibrate": b.get("calibrate"), "use_weights": b.get("use_weights"),
            "threshold_mode": b.get("threshold_mode"),
            "feature_columns_sha256": hashlib.sha256("\n".join(b["cols"]).encode()).hexdigest(),
            "n_features": len(b["cols"]),
        }
    files = tracked_files(layout)
    return {
        "cohort_tag": layout["tag"],
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "python": sys.version.split()[0],
        "candidate": "pe_v3", "baseline": "pe_v1s",
        "models": models,
        "decision_rule": "Claim improvement only if blind TPR gain >= 0.02, paired group-bootstrap 95% CI lower bound > 0, and FPR_candidate <= FPR_baseline.",
        "files": {p.as_posix(): sha256_path(p) for p in files},
        "preregistration_sha256": sha256_path(layout["prereg"]) if layout["prereg"].is_file() else None,
    }


def verify(path: Path | None = None, *, tag: str = "v3") -> list[str]:
    freeze_path = path or cohort_layout(tag)["freeze_path"]
    if not freeze_path.is_file():
        return [str(freeze_path)]
    frozen = json.loads(freeze_path.read_text(encoding="utf-8"))
    bad = []
    for f, digest in frozen["files"].items():
        p = Path(f)
        if not p.is_file() or sha256_path(p) != digest:
            bad.append(f)
    current_code = {p.as_posix() for p in Path("src/v3").glob("*.py")}
    bad += sorted(current_code - set(frozen["files"]))
    return bad


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--cohort-tag", default="v3")
    args = ap.parse_args(argv)
    layout = cohort_layout(args.cohort_tag)
    if args.verify:
        bad = verify(layout["freeze_path"], tag=args.cohort_tag)
        print("freeze OK" if not bad else f"freeze VIOLATED: {bad}")
        return 0 if not bad else 1
    fp = layout["freeze_path"]
    if fp.exists():
        print(f"{fp} exists; refusing to overwrite")
        return 1
    fp.parent.mkdir(parents=True, exist_ok=True)
    m = build_manifest(layout)
    fp.write_text(json.dumps(m, indent=2), encoding="utf-8")
    print(json.dumps({k: m[k] for k in ("cohort_tag", "frozen_at", "models")}, indent=2))
    print(f"{len(m['files'])} files hashed -> {fp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
