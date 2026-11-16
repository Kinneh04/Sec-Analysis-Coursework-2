"""V2 Markdown/JSON/CSV outputs under artifacts/v2/."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd

from src.v2.v1_guard import assert_v2_write_allowed


def write_json(path: Path, obj: Any, *, v1_art: Path) -> None:
    p = assert_v2_write_allowed(path, v1_art)
    p.parent.mkdir(parents=True, exist_ok=True)
    def _clean(o):
        if isinstance(o, dict):
            return {k: _clean(v) for k, v in o.items()}
        if isinstance(o, list):
            return [_clean(v) for v in o]
        if isinstance(o, float) and (o != o):
            return None
        return o

    p.write_text(json.dumps(_clean(obj), indent=2, default=str), encoding="utf-8")


def write_csv(path: Path, df: pd.DataFrame, *, v1_art: Path) -> None:
    p = assert_v2_write_allowed(path, v1_art)
    p.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(p, index=False)


def try_coverage_plots(out_dir: Path, by_class: pd.DataFrame, by_size: pd.DataFrame, *, v1_art: Path) -> list[str]:
    written: list[str] = []
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        out_dir = assert_v2_write_allowed(out_dir, v1_art)
        out_dir.mkdir(parents=True, exist_ok=True)
        sub = by_class[(by_class["group"] == "all") & (by_class["bn_status"].isin(("ok", "partial", "skipped", "error")))]
        if len(sub):
            fig, ax = plt.subplots(figsize=(6, 4))
            for lab, color in ((0, "tab:blue"), (1, "tab:orange")):
                s = sub[sub["label"] == lab]
                ax.bar([f"{lab}:{r['bn_status']}" for _, r in s.iterrows()], s["count"], label=f"label={lab}", alpha=0.8)
            ax.set_title("BN extraction status by class (development)")
            ax.tick_params(axis="x", rotation=45)
            fig.tight_layout()
            p = out_dir / "coverage_by_class.png"
            fig.savefig(p, dpi=120)
            plt.close(fig)
            written.append(str(p))
        if len(by_size):
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.bar(by_size["size_band"].astype(str), by_size["bn_ok_or_partial_rate"])
            ax.set_ylim(0, 1)
            ax.set_title("BN ok/partial rate by file size band")
            fig.tight_layout()
            p = out_dir / "coverage_by_size_band.png"
            fig.savefig(p, dpi=120)
            plt.close(fig)
            written.append(str(p))
    except Exception as exc:
        written.append(f"plot_skipped:{type(exc).__name__}")
    return written
