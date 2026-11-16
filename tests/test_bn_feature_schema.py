from __future__ import annotations

from src.bn_feature_schema import classify_mlil_line, select_functions_deterministic


def test_mlil_branch_line():
    c = classify_mlil_line("if (cond:0) then 31 @ 0x140010276 else 35 @ 0x140010258")
    assert c["mlil_branch_cond"] == 1
    assert c["mlil_call"] == 0


def test_mlil_call_line():
    c = classify_mlil_line("__security_init_cookie()")
    assert c["mlil_call"] == 1


def test_mlil_tailcall():
    c = classify_mlil_line("return __scrt_common_main_seh(rbx) __tailcall")
    assert c["mlil_return"] == 1
    assert c["mlil_tailcall"] == 1


def test_deterministic_function_selection():
    addrs = ["0x1000", "0x2000", "0x3000", "0x4000"]
    a = select_functions_deterministic(addrs, "abc" * 20 + "0" * 4, 2)
    b = select_functions_deterministic(addrs, "abc" * 20 + "0" * 4, 2)
    assert a == b
    assert len(a) == 2
