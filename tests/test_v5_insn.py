from src.v5.bn_insn import features_from_doc, mnemonics


def test_mnemonics_parses_address_lines_only():
    md = "```asm\n  int32_t f()\n// comment\n0x140013154  push    rbp {x}\n0x140013156  call    sub_1\n0x14001315a  xor     eax, eax\n```"
    assert mnemonics(md) == ["push", "call", "xor"]


def test_features_fractions_and_missing():
    assert features_from_doc({"analysis_status": "error"}) == {}
    f = features_from_doc({"analysis_status": "ok", "uni": {"push": 2, "call": 1, "xor": 1}, "bi": {"push>call": 1}})
    assert f["in5_frac_call"] == 0.25 and f["in5_frac_stack"] == 0.5
    assert abs(sum(v for k, v in f.items() if k.startswith("in5_uni_h")) - 1.0) < 1e-9
