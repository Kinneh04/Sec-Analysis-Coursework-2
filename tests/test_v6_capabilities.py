from src.v6.bn_capabilities import (features_from_doc, norm_api, parse_disassembly, ror13, summarize_function,
                                    thunk_target)

IAT = {0x402000: "getprocaddress", 0x402004: "loadlibrary", 0x402008: "writeprocessmemory"}

RESOLVER = """
0x401000  push    0x403000  {"kernel32.dll"}
0x401005  call    dword [0x402004]
0x40100b  push    0x403010  {"CreateRemoteThread"}
0x401010  push    eax
0x401011  mov     esi, dword [0x402000]
0x401017  call    esi
0x401019  call    eax
0x40101b  call    dword [0x402008]
"""

PEB_HASH = """
0x401100  mov     eax, dword [fs:0x30]
0x401106  mov     eax, dword [eax+0x3c]
0x401109  mov     edx, dword [eax+0x78]
0x40110c  ror     edi, 0xd
0x40110f  add     edi, ecx
0x401111  cmp     edi, 0x%08x
0x401117  jne     0x40110c
0x401119  mov     byte [esp+0x10], 0x6b
0x40111e  mov     byte [esp+0x11], 0x65
0x401123  mov     byte [esp+0x12], 0x72
0x401128  mov     byte [esp+0x13], 0x6e
0x40112d  xor     byte [esi], al
0x40112f  syscall
""" % ror13("VirtualAlloc")


def test_norm_api():
    assert norm_api("KERNEL32!CreateProcessW") == "createprocess"
    assert norm_api("__imp_GetProcAddress") == "getprocaddress"
    assert norm_api("send") == "send"


def test_resolver_function():
    s = summarize_function(parse_disassembly(RESOLVER), IAT, {}, {})
    assert s["apis"] == ["getprocaddress", "loadlibrary", "writeprocessmemory"]
    assert "CreateRemoteThread" in s["strings"]
    assert s["ind"]["call_after_resolve"] == 1
    assert s["ind"]["call_import"] == 3


def test_peb_hash_stack_string():
    ind = summarize_function(parse_disassembly(PEB_HASH), IAT, {}, {})["ind"]
    assert ind["peb"] == 1 and ind["export_parse"] == 1
    assert ind["known_hash"] == 1 and ind["rot_imm"] == 1 and ind["backward_jumps"] == 1
    assert ind["stack_str_runs"] == 1 and ind["stack_str_bytes"] == 4
    assert ind["xor_byte"] == 1 and ind["syscall"] == 1


def test_thunk():
    assert thunk_target(parse_disassembly("0x401200  jmp     dword [0x402000]"), IAT) == "getprocaddress"


def test_file_features():
    fns = [summarize_function(parse_disassembly(t), IAT, {}, {}) for t in (RESOLVER, PEB_HASH)]
    doc = {"analysis_status": "ok", "functions": fns, "function_total": 2, "functions_disassembled": 2,
           "imports": ["getprocaddress", "loadlibrary", "writeprocessmemory"], "strings": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run"]}
    f = features_from_doc(doc)
    assert f["cap6_n_dyn_sensitive"] == 1
    assert f["cap6_r_injection"] == 1
    assert f["cap6_fn_peb_export"] == 1 and f["cap6_fn_hash_loop"] == 1
    assert f["cap6_strong_any"] == 1
    assert f["cap6_file_s_runkey"] == 1
    assert features_from_doc({"analysis_status": "error"}) == {}
