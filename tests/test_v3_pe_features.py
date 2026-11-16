import hashlib

import numpy as np
import pandas as pd

from src.v3.pe_features_v3 import (
    byte_entropy_histogram,
    byte_histogram,
    extract_pe_v3,
    stable_bucket,
    v3_predictor_columns,
)


def test_stable_bucket_is_deterministic_and_case_insensitive():
    assert stable_bucket("kernel32.dll:CreateFileW", 1024) == stable_bucket("KERNEL32.DLL:createfilew", 1024)
    expected = int.from_bytes(hashlib.md5(b"x").digest()[:8], "little") % 1024
    assert stable_bucket("x", 1024) == expected


def test_histograms_normalized():
    a = np.random.default_rng(0).integers(0, 256, size=50_000, dtype=np.uint8)
    assert abs(byte_histogram(a).sum() - 1) < 1e-9
    beh = byte_entropy_histogram(a)
    assert beh.shape == (256,)
    assert abs(beh.sum() - 1) < 1e-9
    small = a[:100]
    assert abs(byte_entropy_histogram(small).sum() - 1) < 1e-9


def test_sha_mismatch_and_non_pe(tmp_path):
    p = tmp_path / "notpe.bin"
    data = b"hello world, not a PE file" * 100
    p.write_bytes(data)
    bad = extract_pe_v3(p, "0" * 64)
    assert bad["v3_status"] == "sha_mismatch"
    good = extract_pe_v3(p, hashlib.sha256(data).hexdigest())
    assert good["v3_status"].startswith("pe_error")
    assert "pe3_bytehist_000" in good


def test_predictor_columns_exclude_metadata_and_timestamp():
    df = pd.DataFrame({
        "pe3_imp_bucket_0001": [1.0], "pe3_hdr_timestamp": [1.0], "v3_status": ["ok"],
        "v3_extract_seconds": [0.1], "sha256": ["x"],
    })
    cols = v3_predictor_columns(df)
    assert cols == ["pe3_imp_bucket_0001"]
    assert "pe3_hdr_timestamp" in v3_predictor_columns(df, include_timestamp=True)
