"""Tests for read-only feature audit (synthetic data)."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from src.audit.contribution import ARMS, run_validation_ablation
from src.audit.inputs import verify_split_integrity
from src.audit.schema import FORBIDDEN_EXACT, bn_predictor_columns, is_forbidden_predictor, pe_predictor_columns


def _mini_inventory():
    return pd.DataFrame(
        {
            "sha256": [f"{'a' * 62}{i:02d}" for i in range(12)],
            "label": [0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1],
            "group_id": [f"g{i // 2}" for i in range(12)],
            "file_size": [1000] * 12,
            "source": ["s"] * 12,
            "software_source": ["x"] * 12,
            "machine": [0x14C] * 12,
        }
    )


def _mini_pe(inv):
    rows = []
    for _, r in inv.iterrows():
        rows.append({"sha256": r["sha256"], "label": r["label"], "pe_feat_a": float(r["label"]), "pe_feat_b": 1.0})
    return pd.DataFrame(rows)


def _mini_bn(inv):
    rows = []
    for i, r in inv.iterrows():
        rows.append(
            {
                "sha256": r["sha256"],
                "bn_x": float(i),
                "quality_y": 0.5,
                "analysis_status": "ok",
            }
        )
    return pd.DataFrame(rows)


def _assignments(inv):
    splits = ["train"] * 6 + ["val"] * 3 + ["test"] * 3
    return pd.DataFrame({"sha256": inv["sha256"], "split": splits, "group_id": inv["group_id"], "label": inv["label"]})


def test_split_integrity_rejects_duplicate_sha():
    inv = _mini_inventory()
    assign = _assignments(inv)
    assign = pd.concat([assign, assign.iloc[[0]]], ignore_index=True)
    data = {
        "inventory": inv,
        "assignments": assign,
        "pe": _mini_pe(inv),
        "bn": _mini_bn(inv),
        "train": _mini_pe(inv).iloc[:6],
        "val": _mini_pe(inv).iloc[6:9],
        "challenge_sha": set(),
    }
    rep = verify_split_integrity(data)
    assert rep["pass"] is False
    assert any("duplicate" in i for i in rep["issues"])


def test_forbidden_predictors_excluded():
    df = pd.DataFrame(
        {
            "sha256": ["x"],
            "label": [0],
            "pe_ok": [1.0],
            "pe_status": [1],
            "bn_ok": [2.0],
            "analysis_status": [0],
        }
    )
    assert is_forbidden_predictor("sha256")
    assert is_forbidden_predictor("pe_status")
    pe = pe_predictor_columns(df)
    assert "pe_ok" in pe
    assert "pe_status" not in pe
    bn = bn_predictor_columns(df)
    assert "bn_ok" in bn


def test_train_only_filtering_in_ablation():
    inv = _mini_inventory().iloc[:8]
    pe = _mini_pe(inv)
    bn = _mini_bn(inv)
    bn["bn_always_missing"] = float("nan")
    feat = pe.drop(columns=["label"]).merge(bn.drop(columns=["analysis_status"]), on="sha256")
    feat = feat.merge(inv[["sha256", "label", "group_id", "file_size", "source", "software_source", "machine"]], on="sha256")
    feat["bn_extraction_status"] = "ok"
    train = feat.iloc[:6].copy()
    val = feat.iloc[6:8].copy()
    ablation, _, _ = run_validation_ablation(
        train,
        val,
        seed=0,
        fpr_target=0.5,
        models=("random_forest",),
        n_boot=50,
    )
    assert len(ablation) >= len(ARMS)
    assert "P0_pe_baseline" in set(ablation["arm"])


def test_contribution_module_has_no_test_loader():
    src = Path("src/audit/contribution.py").read_text(encoding="utf-8")
    assert "test_split" not in src
    assert "test.parquet" not in src


def test_gate_a_label_mismatch():
    inv = _mini_inventory()
    assign = _assignments(inv)
    train = _mini_pe(inv).iloc[:6]
    train.loc[0, "label"] = 99
    data = {
        "inventory": inv,
        "assignments": assign,
        "pe": _mini_pe(inv),
        "bn": _mini_bn(inv),
        "train": train,
        "val": _mini_pe(inv).iloc[6:9],
        "challenge_sha": set(),
    }
    rep = verify_split_integrity(data)
    assert any("label_mismatch" in i for i in rep["issues"])
