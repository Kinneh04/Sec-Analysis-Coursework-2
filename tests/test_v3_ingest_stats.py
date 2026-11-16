import numpy as np
import pandas as pd
import pytest

from src.v3.ingest import assign_split, freeze
from src.v3.stats import paired_group_bootstrap_fixed, rates_at_threshold, wilson_interval


def _rows(n_groups=60, per=5):
    rows = []
    for g in range(n_groups):
        label = "malicious" if g % 2 else "benign"
        for i in range(per):
            rows.append({"sha256": f"{g:04d}{i:02d}", "path": f"x{g}_{i}", "label": label,
                         "group_id": f"grp{g}", "imphash": f"imp{g}" if label == "malicious" else "", "file_size": 1})
    return pd.DataFrame(rows)


def test_split_is_group_disjoint_and_respects_v1_overlap():
    df = _rows()
    ref = {"sha256": {"000000"}, "group_id": {"grp2"}, "imphash": {"imp3"}}
    out = assign_split(df, ref, seed=1)
    assert "000000" not in set(out["sha256"])
    assert out.groupby("group_id")["split"].nunique().max() == 1
    assert set(out[out["group_id"].isin(["grp2", "grp3"])]["split"]) == {"new_train"}
    for label in ("benign", "malicious"):
        frac = (out[out["label"] == label]["split"] == "blind").mean()
        assert 0.4 <= frac <= 0.65


def test_freeze_refuses_overwrite(tmp_path):
    out = assign_split(_rows(), {"sha256": set(), "group_id": set(), "imphash": set()}, seed=1)
    freeze(out, tmp_path, seed=1, extra={})
    with pytest.raises(FileExistsError):
        freeze(out, tmp_path, seed=1, extra={})


def test_wilson_and_fixed_rates():
    lo, hi = wilson_interval(0, 100)
    assert lo == 0.0 and 0.03 < hi < 0.04
    y = np.array([0, 0, 1, 1])
    r = rates_at_threshold(y, np.array([0.1, 0.9, 0.8, 0.2]), 0.5)
    assert r["tpr"] == 0.5 and r["fpr"] == 0.5


def test_paired_bootstrap_identical_models_zero_delta():
    rng = np.random.default_rng(0)
    y = rng.integers(0, 2, 200)
    s = rng.random(200)
    res = paired_group_bootstrap_fixed(y, s, 0.5, s, 0.5, np.arange(200) // 4, n_boot=200)
    assert res["delta_tpr_b_minus_a"] == 0 and res["delta_tpr_ci95"] == [0.0, 0.0]
