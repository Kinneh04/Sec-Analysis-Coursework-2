"""Binary Ninja capability indicators over all functions (static analysis only).

Disassembles every function (largest first, within a time budget) through the Binary Ninja GUI MCP
server and records, per function, the APIs it calls (resolved through the IAT, thunks and
registers loaded from the IAT), the strings it references, and instruction-level evasion
indicators. File features (cap6_*) are derived from the cached per-function summaries, so rules can
change without re-analysis. UPX-packed files are unpacked statically before analysis.

  python -m src.v6.bn_capabilities extract --manifest artifacts/v6/manifests/gate_queue.csv
"""

from __future__ import annotations

import argparse
import json
import re
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from pathlib import Path
from typing import Any

import pandas as pd

from src.bn_mcp import BnMcpClient
from src.common.hashing import sha256_file
from src.ensure_bn_mcp import ensure_bn_mcp, reboot_bn_mcp
from src.v4.bn_extract import MAX_BYTES, MCP_URL, SKIP_PATH_CONTAINS, FileTimeout, _md, _paged, parse_table
from src.v6.unpack import prepare

EXTRACTOR_VERSION = "bn_cap_v6"
CACHE_DIR = Path("artifacts/v6/cap_cache")
ANALYSIS_TIMEOUT = 90
DISASM_BUDGET_S = 120
FILE_TIMEOUT = 330
MAX_FUNCS = 5000
MAX_LINES = 4000
MAX_STRINGS = 5000
MAX_FUNC_STRINGS = 40

LINE_RE = re.compile(r"^(0x[0-9a-f]+)\s+([a-z][a-z0-9.]*)\s*(.*)$", re.IGNORECASE)
STR_ANNOT_RE = re.compile(r'\{u?"((?:[^"\\]|\\.)*)"\}')
MEM_ABS_RE = re.compile(r"\[(?:rel )?(0x[0-9a-f]+)\]")
REG_RE = re.compile(r"^(?:[re]?[abcd]x|[re]?[sd]i|[re]?bp|[re]?sp|r(?:[89]|1[0-5])[dwb]?)$")
IMM_RE = re.compile(r"(?<![\w\[+\-])0x([0-9a-f]+)\b")
STACK_MEM_RE = re.compile(r"^(byte|word|dword|qword) \[[re]?(?:sp|bp)[^\]]*\],\s*0x([0-9a-f]+)$")
API_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{3,60}$")


def norm_api(name: str) -> str:
    n = name.split("!")[-1]
    for p in ("__imp__", "__imp_", "_imp_"):
        if n.startswith(p):
            n = n[len(p):]
    n = n.lstrip("_").split("@")[0]
    if len(n) > 3 and n[-1] in "AW" and n[-2].islower():
        n = n[:-1]
    return n.lower()


def _ror32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def ror13(name: str) -> int:
    h = 0
    for ch in name.encode():
        h = (_ror32(h, 13) + ch) & 0xFFFFFFFF
    return h


HASHED_APIS = (
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "WriteProcessMemory", "CreateRemoteThread", "CreateProcessA", "CreateProcessW", "WinExec", "ExitProcess", "CreateThread",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx", "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection", "RtlMoveMemory", "InternetOpenA", "InternetOpenUrlA", "InternetReadFile", "URLDownloadToFileA",
    "WSAStartup", "socket", "connect", "send", "recv", "ShellExecuteA", "GetModuleHandleA", "LdrLoadDll", "LdrGetProcedureAddress",
    "kernel32.dll", "ntdll.dll", "KERNEL32.DLL", "NTDLL.DLL", "SetThreadContext", "ResumeThread", "QueueUserAPC", "OpenProcess",
)
KNOWN_HASHES = {ror13(n) for n in HASHED_APIS} | {zlib.crc32(n.encode()) & 0xFFFFFFFF for n in HASHED_APIS}


def parse_disassembly(markdown: str) -> list[tuple[int, str, str, list[str]]]:
    out = []
    for line in markdown.splitlines():
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        addr, mn, rest = m.groups()
        strs = STR_ANNOT_RE.findall(rest)
        ops = re.sub(r"\s*\{.*\}\s*$", "", rest).strip()
        out.append((int(addr, 16), mn.lower(), ops, strs))
    return out


def _printable_imm(v: int) -> bool:
    bs = v.to_bytes(8, "little").rstrip(b"\x00")
    return bool(bs) and all(0x20 <= b < 0x7F for b in bs)


def summarize_function(insns: list[tuple[int, str, str, list[str]]], iat: dict[int, str], thunks: dict[int, str],
                       names: dict[str, str]) -> dict[str, Any]:
    """Per-function summary: called APIs, referenced strings and evasion indicators."""
    apis: list[str] = []
    strings: list[str] = []
    ind = dict(n_insn=len(insns), calls=0, call_import=0, call_func=0, call_reg_unresolved=0, call_mem_indirect=0,
               backward_jumps=0, peb=0, export_parse=0, rot_imm=0, xor_nonself=0, xor_byte=0, cmp_imm32=0, known_hash=0,
               stack_str_runs=0, stack_str_bytes=0, syscall=0, rdtsc=0, cpuid=0, call_after_resolve=0)
    if not insns:
        return {"apis": [], "strings": [], "ind": ind}
    start = insns[0][0]
    reg_api: dict[str, str] = {}
    resolved_seen = False
    run_moves, run_bytes = 0, 0
    has_3c = has_78 = False
    for addr, mn, ops, strs in insns:
        strings.extend(s[:80] for s in strs)
        low = ops.lower()
        sm = STACK_MEM_RE.match(low) if mn == "mov" else None
        if sm and _printable_imm(int(sm.group(2), 16)):
            run_moves += 1
            run_bytes += len(int(sm.group(2), 16).to_bytes(8, "little").rstrip(b"\x00"))
        else:
            if run_moves >= 4:
                ind["stack_str_runs"] += 1
                ind["stack_str_bytes"] += run_bytes
            run_moves, run_bytes = 0, 0
        if re.search(r"fs:\[?(?:0x)?(?:30|18)\]?", low) or re.search(r"gs:\[?(?:0x)?(?:60|30)\]?", low):
            ind["peb"] += 1
        if "+0x3c]" in low:
            has_3c = True
        if "+0x78]" in low or "+0x88]" in low:
            has_78 = True
        for h in IMM_RE.findall(low):
            v = int(h, 16)
            if v > 0xFFFF and v in KNOWN_HASHES:
                ind["known_hash"] += 1
        if mn in ("rol", "ror") and IMM_RE.search(low.split(",")[-1]):
            ind["rot_imm"] += 1
        elif mn == "xor":
            parts = [p.strip() for p in low.split(",")]
            if len(parts) == 2 and parts[0] != parts[1]:
                ind["xor_nonself"] += 1
                if parts[0].startswith("byte") or parts[0] in ("al", "bl", "cl", "dl"):
                    ind["xor_byte"] += 1
        elif mn == "cmp":
            m = IMM_RE.search(low.split(",")[-1])
            if m and int(m.group(1), 16) > 0xFFFF:
                ind["cmp_imm32"] += 1
        elif mn in ("syscall", "sysenter") or (mn == "int" and "0x2e" in low):
            ind["syscall"] += 1
        elif mn == "rdtsc":
            ind["rdtsc"] += 1
        elif mn == "cpuid":
            ind["cpuid"] += 1
        elif mn.startswith("j"):
            m = re.match(r"^0x([0-9a-f]+)$", low)
            if m and start <= int(m.group(1), 16) < addr:
                ind["backward_jumps"] += 1
        if mn == "mov":
            parts = [p.strip() for p in low.split(",", 1)]
            if len(parts) == 2 and REG_RE.match(parts[0]):
                m = MEM_ABS_RE.search(parts[1])
                if m and int(m.group(1), 16) in iat:
                    reg_api[parts[0]] = iat[int(m.group(1), 16)]
                else:
                    reg_api.pop(parts[0], None)
        if mn == "call":
            ind["calls"] += 1
            api = None
            m = MEM_ABS_RE.search(low)
            if m and int(m.group(1), 16) in iat:
                api = iat[int(m.group(1), 16)]
            elif REG_RE.match(low):
                api = reg_api.get(low)
                if api is None:
                    ind["call_reg_unresolved"] += 1
                    if resolved_seen:
                        ind["call_after_resolve"] += 1
            elif "[" in low:
                ind["call_mem_indirect"] += 1
                if resolved_seen:
                    ind["call_after_resolve"] += 1
            else:
                tgt = low.split()[-1]
                if tgt.startswith("0x") or tgt.startswith("sub_"):
                    try:
                        a = int(tgt.replace("sub_", "0x"), 16)
                    except ValueError:
                        a = -1
                    api = thunks.get(a)
                else:
                    api = names.get(norm_api(tgt))
                if api is None:
                    ind["call_func"] += 1
            if api:
                ind["call_import"] += 1
                apis.append(api)
                if api in ("getprocaddress", "ldrgetprocedureaddress", "ldrgetprocaddress"):
                    resolved_seen = True
    if run_moves >= 4:
        ind["stack_str_runs"] += 1
        ind["stack_str_bytes"] += run_bytes
    ind["export_parse"] = int(has_3c and has_78)
    return {"apis": sorted(set(apis)), "strings": list(dict.fromkeys(strings))[:MAX_FUNC_STRINGS], "ind": ind}


def thunk_target(insns: list[tuple[int, str, str, list[str]]], iat: dict[int, str]) -> str | None:
    if 1 <= len(insns) <= 2 and insns[0][1] == "jmp":
        m = MEM_ABS_RE.search(insns[0][2].lower())
        if m:
            return iat.get(int(m.group(1), 16))
    return None


def _run_analysis(client: BnMcpClient) -> bool:
    pool = ThreadPoolExecutor(max_workers=1)
    fut = pool.submit(client.call_tool, "bn_analysis_update_and_wait", {})
    try:
        fut.result(timeout=ANALYSIS_TIMEOUT)
        return True
    except FuturesTimeout:
        try:
            abort = BnMcpClient(client.url)
            abort.connect()
            abort.call_tool("bn_analysis_abort", {})
        except Exception:
            pass
        try:
            fut.result(timeout=60)
        except FuturesTimeout:
            raise FileTimeout("analysis did not stop after abort")
        return False
    finally:
        pool.shutdown(wait=False)


def analyze(client: BnMcpClient, path: Path) -> dict[str, Any]:
    doc: dict[str, Any] = {}
    opened = client.call_tool("bn_open_item_open", {"path": path.resolve().as_posix(), "setActive": True})
    handle = (opened.get("openItem") or {}).get("handle")
    try:
        views = opened.get("binaryViews") or []
        bv = next((v for v in views if v.get("recommended")), None) or next((v for v in views if v.get("viewType") != "Raw"), None)
        if bv is None:
            return {"analysis_status": "unsupported"}
        client.call_tool("bn_binary_view_set_active", {"binaryView": bv["handle"]})
        t0 = time.time()
        doc["analysis_complete"] = _run_analysis(client)
        doc["analysis_seconds"] = round(time.time() - t0, 2)
        imports, _ = _paged(client, "bn_import_list", 5000)
        iat: dict[int, str] = {}
        names: dict[str, str] = {}
        for i in imports:
            api = norm_api(i.get("name", ""))
            if not api:
                continue
            names[api] = api
            try:
                iat[int(i.get("symbol", ""), 16)] = api
            except ValueError:
                pass
        doc["imports"] = sorted(names)
        strings, doc["string_total"] = _paged(client, "bn_string_list", MAX_STRINGS, {"previewBytes": 120})
        doc["strings"] = [s.get("previewEscaped", "")[:120] for s in strings]
        funcs, doc["function_total"] = _paged(client, "bn_function_list", MAX_FUNCS)
        funcs.sort(key=lambda f: int(f.get("basicBlockCount", "0") or 0), reverse=True)
        t1 = time.time()
        raw: list[tuple[int, list]] = []
        for f in funcs:
            if time.time() - t1 > DISASM_BUDGET_S:
                break
            insns = parse_disassembly(_md(client.call_tool("bn_function_disassembly", {"function": f["function"], "limit": MAX_LINES})))
            raw.append((int(f["function"], 16), insns))
        thunks = {a: t for a, ins in raw if (t := thunk_target(ins, iat))}
        doc["functions"] = []
        for a, ins in raw:
            if a in thunks:
                continue
            s = summarize_function(ins, iat, thunks, names)
            s["addr"] = hex(a)
            doc["functions"].append(s)
        doc["functions_disassembled"] = len(raw)
        doc["thunks"] = len(thunks)
        doc["disasm_seconds"] = round(time.time() - t1, 2)
        complete = doc["analysis_complete"] and len(raw) == len(funcs) and len(funcs) >= int(doc["function_total"] or 0)
        doc["analysis_status"] = "ok" if complete else "partial"
        return doc
    finally:
        if handle:
            client.close_item(handle)


def extract(queue: pd.DataFrame) -> dict[str, int]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    ensure_bn_mcp(MCP_URL)
    client = BnMcpClient(MCP_URL)
    client.connect()
    todo = [r for r in queue.itertuples(index=False) if not (CACHE_DIR / f"{r.sha256}.json").is_file()]
    print(f"BN cap v6: {len(queue) - len(todo)} cached, {len(todo)} to analyze", flush=True)
    counts: dict[str, int] = {}
    for i, r in enumerate(todo, 1):
        path, t0 = Path(r.path), time.time()
        try:
            size = path.stat().st_size
        except OSError:
            size = -1
        prep: list[str] = []
        if size < 0:
            doc = {"analysis_status": "error", "errors": ["path_missing"]}
        elif any(frag in str(path).lower() for frag in SKIP_PATH_CONTAINS):
            doc = {"analysis_status": "skipped"}
        elif sha256_file(path) != r.sha256:
            doc = {"analysis_status": "error", "errors": ["sha_mismatch"]}
        elif (target_prep := prepare(path, r.sha256, MAX_BYTES))[1] == ["too_large"]:
            doc = {"analysis_status": "skipped", "errors": [f"size_{size}_image_over_{MAX_BYTES}"]}
        else:
            target, prep = target_prep
            pool = ThreadPoolExecutor(max_workers=1)
            fut = pool.submit(analyze, client, target)
            try:
                doc = fut.result(timeout=FILE_TIMEOUT)
            except (FuturesTimeout, FileTimeout) as e:
                doc = {"analysis_status": "error", "errors": [f"timeout:{type(e).__name__}"]}
                print(f"  timeout on {r.sha256[:12]}; rebooting Binary Ninja", flush=True)
                reboot_bn_mcp(MCP_URL)
                client = BnMcpClient(MCP_URL)
                client.connect()
            except Exception as e:
                print(f"  error on {r.sha256[:12]}: {type(e).__name__}: {str(e)[:200]}; rebooting", flush=True)
                try:
                    reboot_bn_mcp(MCP_URL)
                    client = BnMcpClient(MCP_URL)
                    client.connect()
                except Exception:
                    pass
                continue  # transient: retry on a later run
            finally:
                pool.shutdown(wait=False)
        doc.update({"sha256": r.sha256, "prep": prep, "unpack": "upx" if "upx" in prep else "none", "extractor_version": EXTRACTOR_VERSION,
                    "wall_seconds": round(time.time() - t0, 2)})
        tmp = CACHE_DIR / f"{r.sha256}.json.tmp"
        tmp.write_text(json.dumps(doc), encoding="utf-8")
        tmp.replace(CACHE_DIR / f"{r.sha256}.json")
        counts[doc["analysis_status"]] = counts.get(doc["analysis_status"], 0) + 1
        if i % 10 == 0 or doc["analysis_status"] not in ("ok", "partial"):
            print(f"  {i}/{len(todo)} {counts} last {doc['wall_seconds']}s", flush=True)
    return counts


# ---------------------------------------------------------------------------------------------
# File features from cached per-function summaries.

DYN_RESOLVERS = {"getprocaddress", "ldrgetprocedureaddress", "ldrgetprocaddress"}
LOADERS = {"loadlibrary", "loadlibraryex", "ldrloaddll", "getmodulehandle", "getmodulehandleex"}
API_GROUPS = {
    "inject_write": {"writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory"},
    "inject_alloc": {"virtualallocex", "ntallocatevirtualmemory", "zwallocatevirtualmemory", "ntmapviewofsection", "zwmapviewofsection"},
    "inject_exec": {"createremotethread", "createremotethreadex", "ntcreatethreadex", "queueuserapc", "ntqueueapcthread", "setthreadcontext", "rtlcreateuserthread"},
    "hollow": {"ntunmapviewofsection", "zwunmapviewofsection", "setthreadcontext", "getthreadcontext", "wow64setthreadcontext"},
    "proc_open": {"openprocess", "ntopenprocess"},
    "proc_enum": {"createtoolhelp32snapshot", "process32first", "process32next", "enumprocesses"},
    "keylog": {"setwindowshookex", "getasynckeystate", "getkeystate", "getkeyboardstate", "registerrawinputdevices"},
    "screen": {"bitblt", "getdc", "createcompatiblebitmap", "getdesktopwindow"},
    "clipboard": {"openclipboard", "getclipboarddata", "setclipboarddata"},
    "crypto": {"cryptencrypt", "cryptdecrypt", "cryptgenkey", "cryptimportkey", "bcryptencrypt", "bcryptdecrypt", "bcryptgeneratesymmetrickey", "cryptacquirecontext"},
    "credential": {"cryptunprotectdata", "credenumerate", "credread", "lsaretrieveprivatedata"},
    "file_enum": {"findfirstfile", "findnextfile", "findfirstfileex"},
    "net": {"internetopen", "internetopenurl", "internetconnect", "httpopenrequest", "httpsendrequest", "internetreadfile", "winhttpopen",
            "winhttpconnect", "winhttpsendrequest", "winhttpreaddata", "urldownloadtofile", "socket", "connect", "send", "recv", "wsastartup", "wsasocket", "gethostbyname", "getaddrinfo"},
    "exec": {"createprocess", "shellexecute", "shellexecuteex", "winexec", "createprocessasuser", "createprocesswithtokenw"},
    "persist": {"regsetvalueex", "regcreatekeyex", "createservice", "changeserviceconfig", "regsetkeyvalue"},
    "antidebug": {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstring", "ntsetinformationthread", "zwqueryinformationprocess"},
    "privilege": {"adjusttokenprivileges", "lookupprivilegevalue", "openprocesstoken"},
    "memprotect": {"virtualprotect", "virtualalloc", "ntprotectvirtualmemory", "virtualprotectex"},
    "dyn": DYN_RESOLVERS | LOADERS,
}
STRING_GROUPS = {
    "s_runkey": re.compile(r"currentversion\\\\?run|\\\\winlogon|image file execution options", re.I),
    "s_browser": re.compile(r"login data|logins\.json|cookies\.sqlite|web data|key4\.db|\\\\user data\\\\|signons", re.I),
    "s_wallet": re.compile(r"wallet\.dat|electrum|exodus|metamask|\\\\ethereum", re.I),
    "s_shadow": re.compile(r"vssadmin|delete shadows|wbadmin|bcdedit|shadowcopy", re.I),
    "s_shell": re.compile(r"cmd(\.exe)? */c|powershell|schtasks|/create /|reg add", re.I),
    "s_vm": re.compile(r"vmware|virtualbox|vbox|qemu|sandboxie|sbiedll|wireshark|procmon|ollydbg|x64dbg", re.I),
    "s_url": re.compile(r"https?://|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\.onion", re.I),
    "s_ransom": re.compile(r"your files|decrypt|bitcoin|ransom|\.locked", re.I),
    "s_selfdel": re.compile(r"ping 127\.0\.0\.1|del /f|/c del |choice /c", re.I),
    "s_debugpriv": re.compile(r"sedebugprivilege", re.I),
}
SENSITIVE = set().union(*(v for k, v in API_GROUPS.items() if k not in ("dyn", "file_enum", "net", "exec", "memprotect", "privilege", "proc_open")))
ALL_KNOWN = set().union(*API_GROUPS.values())
RULES = {
    "r_injection": lambda g: g["inject_write"] and (g["inject_exec"] or g["inject_alloc"]),
    "r_hollowing": lambda g: g["exec"] and g["inject_write"] and g["hollow"],
    "r_keylog": lambda g: bool(g["keylog"]),
    "r_screen": lambda g: len(g["screen"]) >= 2,
    "r_clipboard": lambda g: len(g["clipboard"]) >= 2,
    "r_crypt_files": lambda g: g["crypto"] and g["file_enum"],
    "r_net_exec": lambda g: g["net"] and g["exec"],
    "r_persist_run": lambda g: g["persist"] and g["s_runkey"],
    "r_credential": lambda g: bool(g["credential"]) or bool(g["s_browser"]) or bool(g["s_wallet"]),
    "r_antidebug": lambda g: bool(g["antidebug"]),
    "r_privilege": lambda g: len(g["privilege"]) >= 2 or (g["privilege"] and g["s_debugpriv"]),
    "r_proc_scan_open": lambda g: g["proc_enum"] and g["proc_open"],
    "r_shadow": lambda g: bool(g["s_shadow"]),
    "r_dyn_sensitive": lambda g: g["dyn_resolver"] and bool(g["dyn_names_sensitive"]),
}


def _groups(apis: set[str], strings: list[str], dyn_names: set[str], resolver: bool) -> dict[str, Any]:
    full = apis | dyn_names
    g: dict[str, Any] = {k: full & v for k, v in API_GROUPS.items()}
    for k, rx in STRING_GROUPS.items():
        g[k] = any(rx.search(s) for s in strings)
    g["dyn_resolver"] = resolver
    g["dyn_names_sensitive"] = dyn_names & SENSITIVE
    return g


def features_from_doc(doc: dict[str, Any]) -> dict[str, float]:
    if doc.get("analysis_status") not in ("ok", "partial"):
        return {}
    funcs = doc.get("functions") or []
    imports = set(doc.get("imports") or [])
    f: dict[str, float] = {
        "cap6_n_functions": float(doc.get("function_total") or 0),
        "cap6_frac_disassembled": (doc.get("functions_disassembled") or 0) / max(1.0, float(doc.get("function_total") or 0)),
        "cap6_n_imports": float(len(imports)),
        "cap6_unpacked_upx": float(doc.get("unpack") == "upx"),
        "cap6_overlay_stripped": float("overlay_stripped" in (doc.get("prep") or [])),
    }
    tot: dict[str, float] = {}
    rule_funcs = {k: 0 for k in RULES}
    dyn_all: set[str] = set()
    used_apis: set[str] = set()
    for fn in funcs:
        ind = fn.get("ind") or {}
        for k, v in ind.items():
            tot[k] = tot.get(k, 0.0) + float(v)
        apis = set(fn.get("apis") or [])
        used_apis |= apis
        resolver = bool(apis & DYN_RESOLVERS)
        dyn = {norm_api(s) for s in fn.get("strings") or [] if API_NAME_RE.match(s)} & ALL_KNOWN if resolver else set()
        dyn_all |= dyn
        g = _groups(apis, fn.get("strings") or [], dyn, resolver)
        for k, rule in RULES.items():
            if rule(g):
                rule_funcs[k] += 1
        # PEB walk plus export-directory parsing, or a hashing loop in one function.
        hash_loop = ind.get("rot_imm", 0) > 0 and ind.get("backward_jumps", 0) > 0 and ind.get("cmp_imm32", 0) > 0
        tot["fn_peb_export"] = tot.get("fn_peb_export", 0.0) + float(ind.get("peb", 0) > 0 and ind.get("export_parse", 0) > 0)
        tot["fn_hash_loop"] = tot.get("fn_hash_loop", 0.0) + float(hash_loop)
        tot["fn_xor_loop"] = tot.get("fn_xor_loop", 0.0) + float(ind.get("xor_byte", 0) > 0 and ind.get("backward_jumps", 0) > 0)
        tot["fn_dyn_call"] = tot.get("fn_dyn_call", 0.0) + float(ind.get("call_after_resolve", 0) > 0)
    n_insn = max(1.0, tot.get("n_insn", 0.0))
    n_calls = max(1.0, tot.get("calls", 0.0))
    for k in ("peb", "export_parse", "known_hash", "stack_str_runs", "stack_str_bytes", "syscall", "rdtsc", "cpuid",
              "fn_peb_export", "fn_hash_loop", "fn_xor_loop", "fn_dyn_call", "call_after_resolve"):
        f[f"cap6_{k}"] = tot.get(k, 0.0)
    for k in ("rot_imm", "xor_nonself", "xor_byte", "cmp_imm32", "backward_jumps"):
        f[f"cap6_per_kinsn_{k}"] = 1000.0 * tot.get(k, 0.0) / n_insn
    for k in ("call_import", "call_func", "call_reg_unresolved", "call_mem_indirect"):
        f[f"cap6_frac_{k}"] = tot.get(k, 0.0) / n_calls
    f["cap6_n_insn"] = tot.get("n_insn", 0.0)
    for k, v in rule_funcs.items():
        f[f"cap6_{k}"] = float(v)
    f["cap6_n_rules_fired"] = float(sum(v > 0 for v in rule_funcs.values()))
    f["cap6_n_dyn_sensitive"] = float(len(dyn_all & SENSITIVE))
    f["cap6_n_dyn_names"] = float(len(dyn_all))
    f["cap6_imported_unused_frac"] = len(imports - used_apis) / max(1.0, float(len(imports)))
    file_strings = doc.get("strings") or []
    for k, rx in STRING_GROUPS.items():
        f[f"cap6_file_{k}"] = float(sum(1 for s in file_strings if rx.search(s)))
    names_in_strings = {norm_api(s) for s in file_strings if API_NAME_RE.match(s)}
    f["cap6_str_sensitive_api_not_imported"] = float(len((names_in_strings & SENSITIVE) - imports))
    f["cap6_strong_any"] = float(f["cap6_fn_peb_export"] > 0 or (f["cap6_fn_hash_loop"] > 0 and f["cap6_known_hash"] > 0)
                                 or f["cap6_n_dyn_sensitive"] > 0 or f["cap6_syscall"] > 0)
    return f


def build(shas: list[str]) -> pd.DataFrame:
    rows = []
    for sha in shas:
        p = CACHE_DIR / f"{sha}.json"
        doc = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {"analysis_status": "missing"}
        rows.append({"sha256": sha, "cap6_status": doc.get("analysis_status", "missing"), **features_from_doc(doc)})
    return pd.DataFrame(rows)


def cap6_columns(df: pd.DataFrame) -> list[str]:
    return sorted(c for c in df.columns if c.startswith("cap6_") and c != "cap6_status")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["extract"])
    ap.add_argument("--manifest", type=Path, required=True)
    args = ap.parse_args(argv)
    q = pd.read_csv(args.manifest)
    print(json.dumps(extract(q[["sha256", "path"]])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
