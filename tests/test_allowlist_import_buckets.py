import pandas as pd

from src.audit.schema import is_forbidden_predictor, pe_predictor_columns


def test_import_buckets_allowed():
    assert not is_forbidden_predictor("pe_imphash_h000")
    assert not is_forbidden_predictor("pe_imphash_h255")
    assert not is_forbidden_predictor("pe_imp_bucket_1023")


def test_identifiers_still_blocked():
    for name in ("imphash", "pe_imphash", "pe_imphash_value", "group_id", "sha256", "label", "pe_status"):
        assert is_forbidden_predictor(name), name


def test_pe_columns_include_buckets():
    df = pd.DataFrame({"pe_imphash_h001": [1], "pe_file_size": [10], "pe_imphash": [3], "sha256": ["x"]})
    cols = pe_predictor_columns(df)
    assert "pe_imphash_h001" in cols
    assert "pe_imphash" not in cols
