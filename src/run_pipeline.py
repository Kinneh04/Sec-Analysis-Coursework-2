"""Run inventory -> features -> dataset -> train -> evaluate."""

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
    ap.add_argument("--skip-bn", action="store_true")
    args = ap.parse_args()
    py = sys.executable
    run([py, "-m", "src.inventory", "--config", args.config])
    run([py, "-m", "src.pe_features", "--config", args.config])
    if not args.skip_bn:
        run([py, "-m", "src.bn_features", "--config", args.config])
    run([py, "-m", "src.build_dataset", "--config", args.config])
    run([py, "-m", "src.train", "--config", args.config])
    run([py, "-m", "src.evaluate", "--config", args.config])


if __name__ == "__main__":
    main()
