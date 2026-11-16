"""Post-extraction pipeline: frozen splits, no test tuning, no SOTA claims."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.common.config import artifacts, load_config


def run_pipeline(config_path: str = "configs/local.yaml") -> dict:
    cfg = load_config(config_path)
    art = artifacts(cfg)
    py = sys.executable
    root = Path.cwd()
    steps = [
        [py, "-m", "src.build_dataset", "--bn-version", "v2"],
        [py, "-m", "src.train", "--config", config_path, "--output-suffix", "_v2"],
        [
            py,
            "-m",
            "src.evaluate",
            "--config",
            config_path,
            "--output-suffix",
            "_v2",
            "--results-name",
            "test_results_v2.csv",
        ],
        [py, "-m", "src.paired_eval", "--config", config_path],
    ]
    for cmd in steps:
        print("RUN", " ".join(cmd), flush=True)
        subprocess.run(cmd, cwd=root, check=True)

    summary = {
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "config": config_path,
        "artifacts": {
            "splits_meta": str(art / "splits" / "split_meta.json"),
            "test_results": str(art / "evaluations" / "test_results_v2.csv"),
            "paired_eval": str(art / "evaluations" / "paired_pe_vs_pebn_v2.json"),
            "bn_coverage": str(art / "evaluations" / "bn_coverage_v2.json"),
        },
        "interpretation": (
            "Controlled experiment on frozen MalwareBazaar + multi-source benign cohort. "
            "Not benchmark-matched to EMBER2024; do not claim SOTA superiority from these numbers."
        ),
    }
    out = art / "evaluations" / "controlled_experiment_summary.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    args = ap.parse_args()
    run_pipeline(args.config)


if __name__ == "__main__":
    main()
