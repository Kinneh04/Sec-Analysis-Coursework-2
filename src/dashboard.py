"""Minimal Streamlit dashboard over saved evaluation artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

ART = Path(__file__).resolve().parents[1] / "artifacts"
V2 = ART / "v2"


def main() -> None:
    st.title("SA2 Malware ML — Evaluation Dashboard")
    st.caption("Reads local artifacts only; no sample execution.")

    eval_dir = ART / "evaluations"
    if (eval_dir / "test_results_v2.csv").is_file():
        st.subheader("v2 ablation (BN-matched cohort)")
        st.dataframe(pd.read_csv(eval_dir / "test_results_v2.csv"))
    if (eval_dir / "test_results_pe_full.csv").is_file():
        st.subheader("Full PE cohort")
        st.dataframe(pd.read_csv(eval_dir / "test_results_pe_full.csv"))
    if (eval_dir / "challenge_v2.json").is_file():
        st.subheader("Challenge POCs")
        st.json(json.loads((eval_dir / "challenge_v2.json").read_text(encoding="utf-8")))
    if (eval_dir / "bn_coverage_v2.json").is_file():
        st.subheader("BN v2 coverage")
        st.json(json.loads((eval_dir / "bn_coverage_v2.json").read_text(encoding="utf-8")))

    if (V2 / "development" / "validation_arms_summary.csv").is_file():
        st.subheader("V2 development arms (validation)")
        st.caption("Non-confirmatory; from frozen train/val only.")
        st.dataframe(pd.read_csv(V2 / "development" / "validation_arms_summary.csv"))
    if (V2 / "blind" / "paired_results.json").is_file():
        st.subheader("V2 frozen protocol evaluation")
        rep = json.loads((V2 / "blind" / "paired_results.json").read_text(encoding="utf-8"))
        st.warning(
            f"Type: {rep.get('evaluation_type')} | confirmatory={rep.get('confirmatory')} | "
            "Not a SOTA claim."
        )
        st.json(rep)
    if (V2 / "development" / "coverage_by_class.csv").is_file():
        st.subheader("V2 BN coverage by class")
        st.dataframe(pd.read_csv(V2 / "development" / "coverage_by_class.csv"))


if __name__ == "__main__":
    main()
