from src.v6.bn_hlil import features_from_doc, summarize_hlil

HLIL = """
0x401000  HMODULE eax = LoadLibraryA("kernel32.dll")
0x401010  data_404000 = GetProcAddress(eax, "VirtualAllocEx")
0x401020  int32_t (* ecx)() = GetProcAddress(eax, "WriteProcessMemory")
0x401030  GetProcAddress(eax, arg2)
0x401040  __builtin_strcpy(dest: &var_28, src: "CreateRemoteThread")
0x401050  RegSetValueExW(hKey, u"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", 0, 1, &buf, 0x20)
"""


def test_summarize_hlil():
    s = summarize_hlil(HLIL)
    assert s["resolved"] == ["virtualallocex", "writeprocessmemory"]
    assert s["ind"]["gpa_const"] == 2 and s["ind"]["gpa_nonconst"] == 1 and s["ind"]["gpa_global_store"] == 1
    assert s["modules"] == ["kernel32.dll"]
    assert s["stack_strings"] == ["CreateRemoteThread"]
    assert "regsetvalueex" in s["calls"]


def test_hlil_features():
    doc = {"analysis_status": "ok", "function_total": 10, "n_library_named": 4, "n_sub": 6, "functions": [summarize_hlil(HLIL)]}
    f = features_from_doc(doc)
    assert f["hl6_frac_library_named"] == 0.4
    assert f["hl6_n_resolved_sensitive"] >= 2
    assert f["hl6_r_injection"] == 1
    assert f["hl6_stack_api_names"] == 1
    assert f["hl6_r_persist_run"] == 1
