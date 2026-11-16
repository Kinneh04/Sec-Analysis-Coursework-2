"""Authorized PE/BN predictor columns for V2 (aligned with audit allow-list)."""

from __future__ import annotations

import pandas as pd

from src.audit.schema import bn_predictor_columns, pe_predictor_columns


def pe_cols(df: pd.DataFrame) -> list[str]:
    return pe_predictor_columns(df)


def bn_cols(df: pd.DataFrame) -> list[str]:
    return bn_predictor_columns(df)


def pe_bn_cols(df: pd.DataFrame) -> list[str]:
    return pe_cols(df) + bn_cols(df)
