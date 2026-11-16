from src.v4.bn_extract import parse_table
from src.v4.bn_features import bn4_columns, features_from_doc
import pandas as pd


def test_parse_table_reads_rows_and_skips_separator():
    md = "---\ntool: x\n---\n\n| a | b |\n| --- | --- |\n| 1 | x |\n| 2 | y |\n"
    assert parse_table(md) == [{"a": "1", "b": "x"}, {"a": "2", "b": "y"}]


def test_features_missing_for_failed_analysis():
    assert features_from_doc({"analysis_status": "error"}) == {}


def test_features_from_minimal_doc():
    doc = {
        "analysis_status": "ok", "analysis_complete": True, "image_span": 1000, "import_total": 2,
        "functions": [{"name": "sub_1", "bb": 1, "size": 10, "exported": False, "auto": True},
                      {"name": "main", "bb": 5, "size": 90, "exported": True, "auto": False}],
        "top_functions": [{"complexity": {"Blocks": 5, "Edges": 6}, "callees": [["import", "kernel32!virtualalloc"], ["unresolved", ""]]}],
        "strings": [{"type": "AsciiString", "len": 10, "text": "http://x"}],
    }
    f = features_from_doc(doc)
    assert f["bn4_fn_frac_sub"] == 0.5
    assert f["bn4_code_coverage"] == 0.1
    assert f["bn4_calls_frac_unresolved"] == 0.5
    assert f["bn4_cx_cyclomatic_max"] == 3
    assert f["bn4_api_called_ratio"] == 0.5
    assert f["bn4_str_kw_http"] == 1
    cols = bn4_columns(pd.DataFrame([f]))
    assert "bn4_status" not in cols and len(cols) > 400
