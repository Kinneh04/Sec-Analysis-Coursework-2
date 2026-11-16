"""Orchestrate M4–M6: v2 BN pilot, ablation train/eval, challenge audit."""

from __future__ import annotations

import argparse
import subprocess
import sys


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.check_call(cmd)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--skip-bn-extract", action="store_true")
    args = ap.parse_args()
    py = sys.executable
    if not args.skip_bn_extract:
        run([py, "-m", "src.bn_features", "--extractor", "v2", "--config", args.config])
    run([py, "-m", "src.build_dataset", "--config", args.config, "--bn-version", "v2"])
    run([py, "-m", "src.train", "--config", args.config, "--output-suffix", "_v2"])
    run(
        [
            py,
            "-m",
            "src.evaluate",
            "--config",
            args.config,
            "--output-suffix",
            "_v2",
            "--results-name",
            "test_results_v2.csv",
        ]
    )
    run([py, "-m", "src.challenge_eval", "--config", args.config, "--run-id", "lightgbm__pe_bn_v2", "--mcp-bn"])


if __name__ == "__main__":
    main()
