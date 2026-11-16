from pathlib import Path

from src.v3.score import load_bundle, score_row
from src.v3.pe_features_v3 import extract_pe_v3
from src.v3.pe_v1_stable import extract_pe_v1_stable
from src.common.hashing import sha256_file


def test_load_v32_bundle_and_score_cmd():
    bundle = load_bundle("v3.2", verify=False)
    p = Path(r"C:\Windows\System32\cmd.exe")
    if not p.is_file():
        return
    digest = sha256_file(p)
    row = {"path": str(p), "sha256": digest, **extract_pe_v3(p, digest), **extract_pe_v1_stable(p)}
    out = score_row(row, bundle)
    assert "pe_v3_probability" in out
    assert out["pe_v3_flagged"] in (True, False)
