"""Plain-English explanations for SA2 Scan reports.

Three layers, all derived from the scanned file (nothing is executed):
  1. reasons()     - the model's own drivers: LightGBM SHAP contributions translated into sentences, with the
                     file's value compared to typical benign / malware values from the V3.2 training pool.
  2. signals()     - context the model does NOT see directly: signer, installer/packer family, API capabilities,
                     structural anomalies. Each signal says what it means and how often it is benign.
  3. assessment()  - correlates 1 and 2 into an analyst note (heuristic, clearly separate from the model verdict).
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from src.v3.pe_features_v3 import DLL_BUCKETS, EXPORT_BUCKETS, IMPORT_BUCKETS, RESOURCE_TYPES, SECTION_BUCKETS, stable_bucket

REFERENCE = Path("artifacts/v3.2/feature_reference.json")

# ---------------------------------------------------------------- feature catalogue

GROUPS = {
    "entropy": ("Compression & encryption", "How random the bytes look. Compressed or encrypted content (installers, packers, "
                "encrypted payloads) is close to 8 bits/byte; normal code and text is lower."),
    "overlay": ("Appended data (overlay)", "Bytes stored after the last PE section. Installers, self-extracting archives, "
                "signatures and droppers keep data here."),
    "headers": ("Headers & build toolchain", "PE header fields set by the compiler/linker: architecture, subsystem, versions, "
                "checksum and exploit-mitigation flags. They fingerprint how the file was built."),
    "directories": ("Data directories", "Which standard PE tables exist and how big they are (imports, resources, signature, "
                    "relocations, debug info, .NET, TLS...)."),
    "sections": ("Sections & layout", "How the file is divided into sections, their names, sizes and permissions, and where "
                 "execution starts."),
    "imports": ("Imported APIs", "Windows functions the file asks the loader for. They hint at capabilities, though most "
                "APIs are used by legitimate software too."),
    "exports": ("Exported functions", "Functions the file offers to other programs (mostly DLLs)."),
    "strings": ("Text strings", "Printable text inside the file: character mix, URLs, file paths, registry keys."),
    "resources": ("Resources", "Embedded icons, dialogs, version information, manifests and raw data blobs."),
    "size": ("File size", "Overall size of the file."),
}

DIRS = ["export table", "import table", "resource table", "exception data", "Authenticode signature table",
        "relocation table", "debug information", "architecture data", "global pointer", "TLS callbacks table",
        "load configuration", "bound imports", "import address table", "delay-load imports", ".NET (CLR) header", "reserved"]
DLLCHAR = {
    "high_entropy_va": "64-bit high-entropy ASLR", "dynamic_base": "ASLR (randomised load address)",
    "force_integrity": "mandatory signature check (force integrity)", "nx_compat": "DEP / no-execute support",
    "no_isolation": "no side-by-side isolation", "no_seh": "no structured exception handling",
    "no_bind": "binding disabled", "appcontainer": "AppContainer sandbox", "wdm_driver": "WDM driver flag",
    "guard_cf": "Control Flow Guard", "terminal_server_aware": "Terminal Server aware",
}
HDR = {
    "machine": ("Target CPU architecture", "arch"), "characteristics": ("PE characteristics flags", "hex"),
    "is_dll": ("File is a DLL (library), not a program", "bool"), "is_exe": ("Marked as an executable image", "bool"),
    "large_address_aware": ("Large-address-aware flag", "bool"), "is_64bit": ("64-bit file", "bool"),
    "subsystem": ("Windows subsystem (GUI / console / driver)", "subsystem"),
    "dll_characteristics": ("Exploit-mitigation flags (combined value)", "hex"),
    "linker_major": ("Linker major version (build toolchain)", "num"), "linker_minor": ("Linker minor version (build toolchain)", "num"),
    "os_major": ("Minimum Windows version field", "num"), "image_major": ("Image version field", "num"),
    "subsystem_major": ("Subsystem version field", "num"), "size_of_code": ("Declared size of code", "bytes"),
    "size_of_init_data": ("Declared size of initialised data", "bytes"),
    "size_of_uninit_data": ("Declared size of uninitialised data", "bytes"), "entry_point": ("Entry-point address", "hex"),
    "image_base_low32": ("Preferred load address", "hex"), "section_alignment": ("Section alignment in memory", "bytes"),
    "file_alignment": ("Section alignment on disk", "bytes"), "size_of_image": ("Size once loaded in memory", "bytes"),
    "size_of_headers": ("Size of the headers", "bytes"), "checksum_nonzero": ("Header checksum is filled in", "bool"),
    "checksum_valid": ("Header checksum matches the file", "bool"), "stack_reserve": ("Reserved stack size", "bytes"),
    "heap_reserve": ("Reserved heap size", "bytes"), "num_rva_and_sizes": ("Number of data-directory slots", "num"),
    "image_to_file_ratio": ("Size in memory vs size on disk", "ratio"),
}
SEC = {
    "count": ("Number of sections", "num"), "zero_raw": ("Sections with no data on disk", "num"),
    "empty_name": ("Sections with no name", "num"), "rwx": ("Sections that are writable AND executable", "num"),
    "exec": ("Executable sections", "num"), "write": ("Writable sections", "num"),
    "entropy_mean": ("Average section entropy", "entropy"), "entropy_max": ("Highest section entropy", "entropy"),
    "entropy_min": ("Lowest section entropy", "entropy"), "vsize_raw_ratio_max": ("Largest memory/disk size ratio of a section", "ratio"),
    "high_entropy_count": ("Sections with entropy above 7 bits/byte", "num"),
}
STR = {
    "count": ("Number of text strings", "num"), "avg_len": ("Average string length", "num"),
    "max_len": ("Longest string", "num"), "char_entropy": ("Variety of characters in strings", "entropy"),
    "printable_ratio": ("Share of the file that is readable text", "pct"), "urls": ("URLs in the file", "num"),
    "paths": ("Windows file paths in the file", "num"), "registry": ("Registry key references", "num"),
    "mz": ("'MZ' markers (possible embedded executables)", "num"),
}
OTHER = {
    "pe3_file_size_log": ("File size", "logbytes", "size"), "pe3_file_entropy": ("Overall byte entropy", "entropy", "entropy"),
    "pe3_rich_present": ("Rich header present (Microsoft toolchain fingerprint)", "bool", "headers"),
    "pe3_rich_entries": ("Rich header entries (build tools recorded)", "num", "headers"),
    "pe3_ep_in_exec_section": ("Entry point is in an executable section", "bool", "sections"),
    "pe3_ep_section_entropy": ("Entropy of the section where execution starts", "entropy", "entropy"),
    "pe3_ep_outside_sections": ("Entry point lies outside every section", "bool", "sections"),
    "pe3_imp_count": ("Number of imported functions", "num", "imports"),
    "pe3_imp_ordinal_count": ("Functions imported by number instead of name", "num", "imports"),
    "pe3_imp_dll_count": ("Number of imported DLLs", "num", "imports"),
    "pe3_exp_count": ("Number of exported functions", "num", "exports"),
    "pe3_delay_imp_present": ("Uses delay-loaded imports", "bool", "imports"),
    "pe3_overlay_size": ("Size of appended data (overlay)", "bytes", "overlay"),
    "pe3_overlay_ratio": ("Share of the file that is appended data", "pct", "overlay"),
    "pe3_overlay_entropy": ("Entropy of the appended data", "entropy", "overlay"),
    "pe3_res_total": ("Total resources", "num", "resources"), "pe3_res_other": ("Resources of non-standard types", "num", "resources"),
}
ARCH = {0x14C: "x86 (32-bit)", 0x8664: "x64", 0xAA64: "ARM64", 0x1C4: "ARM"}
SUBSYS = {1: "native / driver", 2: "Windows GUI", 3: "console", 9: "Windows CE", 10: "EFI application", 16: "boot application"}


def _char_name(i: int) -> str:
    c = chr(i + 0x20)
    return "space" if c == " " else f"'{c}'"


def describe(name: str, ctx: dict[str, Any]) -> tuple[str, str, str]:
    """feature -> (group, plain title, value format). ctx resolves hashed buckets back to this file's names."""
    f = name[4:] if name.startswith("pe3_") else name
    if name in OTHER:
        t, fmt, g = OTHER[name]
        return g, t, fmt
    if f.startswith("hdr_") and f[4:] in HDR:
        t, fmt = HDR[f[4:]]
        return "headers", t, fmt
    if f.startswith("dllchar_"):
        return "headers", f"Mitigation flag: {DLLCHAR.get(f[8:], f[8:])}", "bool"
    if f.startswith("dir_"):
        i, kind = int(f[4:6]), f[7:]
        return "directories", (f"Has a {DIRS[i]}" if kind == "present" else f"Size of the {DIRS[i]}"), ("bool" if kind == "present" else "bytes")
    if f.startswith("sec_") and f[4:] in SEC:
        t, fmt = SEC[f[4:]]
        return ("entropy" if "entropy" in f else "sections"), t, fmt
    if f.startswith("secname_"):
        kind, k = f[8:].rsplit("_", 1)
        names = ctx["sections_by_bucket"].get(int(k)) or []
        who = ", ".join(names) if names else "a section name this file does not have"
        label = {"size": "Size on disk", "entropy": "Entropy", "vsize": "Size in memory"}[kind]
        return ("entropy" if kind == "entropy" else "sections"), f"{label} of section {who}", ("entropy" if kind == "entropy" else "bytes")
    if f.startswith("imp_bucket_"):
        toks = ctx["imports_by_bucket"].get(int(f[11:])) or []
        if toks:
            shown = ", ".join(t.split(":", 1)[1] for t in toks[:3]) + (" ..." if len(toks) > 3 else "")
            return "imports", f"Imports {shown}", "num"
        return "imports", "Absence of a group of commonly imported APIs (hashed import feature)", "num"
    if f.startswith("impdll_bucket_"):
        dlls = ctx["dlls_by_bucket"].get(int(f[14:])) or []
        return "imports", (f"Imports from {', '.join(dlls)}" if dlls else "Absence of a commonly imported DLL (hashed feature)"), "num"
    if f.startswith("exp_bucket_"):
        ex = ctx["exports_by_bucket"].get(int(f[11:])) or []
        return "exports", (f"Exports {', '.join(ex[:3])}" if ex else "Absence of a common export name (hashed feature)"), "num"
    if f.startswith("str_") and f[4:] in STR:
        t, fmt = STR[f[4:]]
        return "strings", t, fmt
    if f.startswith("str_char_") and f[9:].isdigit():
        return "strings", f"How often the character {_char_name(int(f[9:]))} appears in text strings", "pct"
    if f.startswith("bytehist_"):
        return "entropy", f"Frequency of byte value 0x{int(f[9:]):02X}", "pct"
    if f.startswith("byteent_"):
        i = int(f[8:])
        lo, hi, nib = (i // 16) / 2, (i // 16 + 1) / 2, i % 16
        kind = "near-random (compressed/encrypted)" if lo >= 7 else ("structured" if lo >= 4 else "repetitive or sparse")
        return "entropy", f"Share of the file that is {kind} data ({lo:.1f}-{hi:.1f} bits/byte, byte values 0x{nib:X}0-0x{nib:X}F)", "pct"
    if f.startswith("res_"):
        return "resources", f"Number of '{f[4:]}' resources", "num"
    return "headers", name, "num"


def fmt_value(v: float | None, fmt: str) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "n/a"
    if fmt == "bool":
        return "yes" if v else "no"
    if fmt in ("bytes", "logbytes"):
        n = math.expm1(v) if fmt == "logbytes" else v
        for unit in ("B", "KB", "MB", "GB"):
            if abs(n) < 1024 or unit == "GB":
                return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
            n /= 1024
    if fmt == "entropy":
        return f"{v:.2f} bits/byte"
    if fmt == "pct":
        return f"{v * 100:.2f}%" if v < 0.1 else f"{v * 100:.1f}%"
    if fmt == "ratio":
        return f"{v:.2f}x"
    if fmt == "hex":
        return f"0x{int(v):X}"
    if fmt == "arch":
        return ARCH.get(int(v), f"0x{int(v):X}")
    if fmt == "subsystem":
        return SUBSYS.get(int(v), str(int(v)))
    return f"{v:,.0f}" if float(v).is_integer() else f"{v:,.3f}"


@lru_cache(maxsize=1)
def reference() -> dict[str, Any]:
    try:
        return json.loads(REFERENCE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def build_context(sections: list[str], imports: dict[str, list[str]], exports: list[str]) -> dict[str, Any]:
    sb, ib, db, eb = {}, {}, {}, {}
    for s in sections:
        sb.setdefault(stable_bucket(s or "<empty>", SECTION_BUCKETS), []).append(s or "<empty>")
    for dll, fns in imports.items():
        db.setdefault(stable_bucket(dll, DLL_BUCKETS), []).append(dll)
        for fn in fns:
            ib.setdefault(stable_bucket(f"{dll}:{fn}" if not fn.startswith("ord_") else f"{dll}:ord{fn[4:]}", IMPORT_BUCKETS), []).append(f"{dll}:{fn}")
    for e in exports:
        eb.setdefault(stable_bucket(e if not e.startswith("ord_") else f"ord{e[4:]}", EXPORT_BUCKETS), []).append(e)
    return {"sections_by_bucket": sb, "imports_by_bucket": ib, "dlls_by_bucket": db, "exports_by_bucket": eb}


def strength(c: float) -> str:
    a = abs(c)
    return "strong" if a >= 0.5 else ("moderate" if a >= 0.2 else "minor")


def reasons(contrib: list[tuple[str, float, float]], base: float, ctx: dict[str, Any], top_k: int = 12) -> dict[str, Any]:
    """contrib: [(feature, value, shap_log_odds)] for every model feature. Returns groups + top reasons."""
    ref = reference().get("features", {})
    groups: dict[str, float] = {}
    rows = []
    for name, value, c in contrib:
        g, title, fmt = describe(name, ctx)
        groups[g] = groups.get(g, 0.0) + c
        rows.append((name, value, c, g, title, fmt))
    rows.sort(key=lambda r: -abs(r[2]))
    top = []
    for name, value, c, g, title, fmt in rows[:top_k]:
        r = ref.get(name)
        typical = None
        if r:
            bmed, mmed, bnz, mnz = r
            if bmed == 0 and mmed == 0 and (bnz or mnz):
                typical = f"present in {bnz * 100:.0f}% of benign and {mnz * 100:.0f}% of malware training files"
            else:
                typical = f"typical benign {fmt_value(bmed, fmt)}, typical malware {fmt_value(mmed, fmt)}"
                if (bmed == 0) != (mmed == 0) and fmt != "bool":  # a zero median just means "usually absent"; say how often it is present
                    typical += f" (non-zero in {bnz * 100:.0f}% of benign and {mnz * 100:.0f}% of malware files)"
        top.append({"feature": name, "group": g, "title": title, "value": fmt_value(value, fmt), "raw_value": value,
                    "contribution": round(c, 4), "direction": "malicious" if c > 0 else "benign",
                    "strength": strength(c), "typical": typical})
    gl = [{"group": g, "label": GROUPS[g][0], "contribution": round(v, 4)} for g, v in groups.items()]
    gl.sort(key=lambda x: -abs(x["contribution"]))
    raw = base + sum(c for _, _, c in contrib)
    return {"base_log_odds": round(base, 4), "base_probability": round(_sig(base), 4),
            "final_probability": round(_sig(raw), 6), "groups": gl, "top": top}


def _sig(x: float) -> float:
    return 1 / (1 + math.exp(-x))


# ---------------------------------------------------------------- context signals

API_GROUPS = {
    "injection": ("high", "Process injection APIs",
                  {"virtualallocex", "writeprocessmemory", "createremotethread", "createremotethreadex", "ntcreatethreadex",
                   "queueuserapc", "setthreadcontext", "ntunmapviewofsection", "zwunmapviewofsection", "rtlcreateuserthread",
                   "ntwritevirtualmemory"},
                  "Lets a program write code into another process and run it there. Used by malware to hide inside "
                  "trusted processes; also used by debuggers, game overlays and some security tools."),
    "keylogging": ("medium", "Keyboard / input capture APIs",
                   {"setwindowshookexa", "setwindowshookexw", "getasynckeystate", "registerrawinputdevices"},
                   "Can observe keystrokes system-wide. Keyloggers use these; so do hotkey tools, games and accessibility software."),
    "anti_debug": ("low", "Debugger detection APIs",
                   {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"},
                   "Checks whether it is being debugged. Common in malware that resists analysis, but also in DRM, "
                   "anti-cheat and the C runtime itself."),
    "privilege": ("low", "Privilege adjustment APIs", {"adjusttokenprivileges", "lookupprivilegevaluea", "lookupprivilegevaluew"},
                  "Enables extra privileges (e.g. debug or shutdown rights). Installers and system tools do this routinely."),
    "persistence": ("low", "Registry / service write APIs",
                    {"regsetvalueexa", "regsetvalueexw", "createservicea", "createservicew", "regcreatekeyexa", "regcreatekeyexw"},
                    "Can write registry values or install services, which is how programs (and malware) start automatically."),
    "download": ("medium", "Download-to-file APIs", {"urldownloadtofilea", "urldownloadtofilew", "urldownloadtocachefilea", "urldownloadtocachefilew"},
                 "Downloads a URL straight to disk. Typical of droppers/downloaders; also of updaters."),
    "execution": ("info", "Process launch APIs", {"createprocessa", "createprocessw", "shellexecutea", "shellexecutew",
                                                  "shellexecuteexa", "shellexecuteexw", "winexec"},
                  "Starts other programs. Normal for installers, launchers and shells."),
    "dynamic": ("info", "Runtime API resolution", {"getprocaddress"},
                "Looks up functions by name at run time. Very common; malware uses it to hide which APIs it calls."),
}
NET_DLLS = {"ws2_32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll", "dnsapi.dll", "wsock32.dll"}
CRYPTO_DLLS = {"bcrypt.dll", "ncrypt.dll", "crypt32.dll"}
PACKERS = [  # (id, title, detector(sections set, raw bytes) -> bool, meaning)
    ("nsis", "NSIS installer / uninstaller", lambda s, r: ".ndata" in s or b"NullsoftInst" in r or b"Nullsoft.NSIS" in r,
     "Built with the Nullsoft Scriptable Install System. Every NSIS file shares the same small loader plus a compressed "
     "data block, so static features mostly describe the NSIS framework, not this specific product."),
    ("inno", "Inno Setup installer", lambda s, r: b"Inno Setup" in r or b"InnoSetupLdrWindow" in r,
     "Built with Inno Setup: a standard loader followed by compressed setup data."),
    ("upx", "UPX-packed", lambda s, r: bool({"UPX0", "UPX1"} & s) or b"UPX!" in r[:4096],
     "Compressed with the UPX packer; the real code is unpacked in memory at run time. Common for both small tools and malware."),
    ("mpress", "MPRESS-packed", lambda s, r: ".MPRESS1" in s, "Compressed with the MPRESS packer."),
    ("themida", "Themida / WinLicense protected", lambda s, r: bool({".themida", ".winlice"} & s),
     "Commercial protector that encrypts and virtualises code to resist analysis."),
    ("vmprotect", "VMProtect protected", lambda s, r: bool({".vmp0", ".vmp1", ".vmp2"} & s),
     "Commercial protector that turns code into a custom virtual machine to resist analysis."),
    ("aspack", "ASPack-packed", lambda s, r: bool({".aspack", ".adata"} & s), "Compressed with the ASPack packer."),
    ("pyinstaller", "PyInstaller bundle", lambda s, r: b"MEI\x0c\x0b\x0a\x0b\x0e" in r or b"pyi-runtime-tmpdir" in r,
     "A Python program bundled with its interpreter; the Python code sits compressed in the appended data."),
    ("autoit", "AutoIt compiled script", lambda s, r: b"AU3!EA06" in r or b"AutoIt v3" in r,
     "A compiled AutoIt script. AutoIt is popular for automation and also abused by commodity malware."),
]
GENERIC_TITLES = {
    "signed_valid": "Validly signed", "signature_bad": "Signature does not verify", "large_overlay": "Large appended data block",
    "urls": "URLs in strings", "embedded_pe": "Embedded executable headers", "high_entropy_sections": "High-entropy sections",
    "few_imports": "Very small import table", "no_mitigations": "Missing exploit mitigations",
}


def generic_title(sig: dict[str, Any]) -> str:
    """File-independent signal name for aggregate views (titles of some signals embed this file's numbers)."""
    return GENERIC_TITLES.get(sig["id"], sig["title"])


SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "positive": 4}


def _sig_signal(sig: dict[str, Any], embedded: bool = True) -> dict[str, Any]:
    st = sig.get("status", "Unknown")
    who = sig.get("signer") or "unknown signer"
    if st == "Valid":
        return {"id": "signed_valid", "severity": "positive", "title": f"Validly signed by {who}",
                "evidence": f"Authenticode status Valid; issued by {sig.get('issuer') or 'unknown CA'}"
                            + ("; timestamped" if sig.get("timestamped") else "")
                            + ("" if embedded else "; catalog-signed (no signature embedded in the file, so the model's "
                               "'signature table' features read it as unsigned)"),
                "meaning": "The publisher's code-signing certificate checks out and the file has not changed since it was signed. "
                           "Strong evidence of origin, though stolen or abused certificates do occur. The model does not use signatures."}
    if st == "NotSigned":
        return {"id": "unsigned", "severity": "info", "title": "Not digitally signed",
                "evidence": "No Authenticode signature", "meaning": "There is no publisher signature to confirm who made the file. "
                "Many legitimate tools are unsigned; most commercial software is signed."}
    if st in ("HashMismatch", "NotTrusted", "UnknownError"):
        return {"id": "signature_bad", "severity": "high" if st == "HashMismatch" else "medium",
                "title": f"Signature present but {st}", "evidence": f"Authenticode status {st}; signer {who}",
                "meaning": "A signature exists but does not verify: the file was modified after signing (HashMismatch) "
                           "or the certificate is not trusted. Treat the claimed publisher as unconfirmed."}
    return {"id": "signature_unknown", "severity": "info", "title": "Signature status unknown",
            "evidence": f"Authenticode status {st}", "meaning": "The signature check could not be completed."}


def signals(pe: dict[str, Any], raw: bytes) -> list[dict[str, Any]]:
    """File-level context signals. pe = scanner.pe_details() output."""
    out: list[dict[str, Any]] = []
    if pe.get("error"):
        return [{"id": "parse_error", "severity": "medium", "title": "PE structure could not be fully parsed",
                 "evidence": pe["error"], "meaning": "Malformed headers are common in malware and in deliberately broken samples."}]
    sec_names = {s["name"] for s in pe.get("sections", [])}
    classes = reference().get("classes", {})
    out.append(_sig_signal(pe.get("signature") or {}, pe.get("embedded_signature", True)))

    for pid, title, det, meaning in PACKERS:
        try:
            hit = det(sec_names, raw)
        except Exception:
            hit = False
        if hit:
            note = ""
            c = classes.get(pid)
            if c and c["benign"] + c["malicious"]:
                share = c["malicious"] / (c["benign"] + c["malicious"])
                note = (f" In the V3.2 training data, {c['malicious']} of {c['benign'] + c['malicious']} files of this kind were "
                        f"malware ({share:.0%}), so the model associates this format with malware.")
                if pid == "nsis":
                    note += " This is a known false-positive class: benign NSIS installers/uninstallers are often flagged."
            out.append({"id": f"format_{pid}", "severity": "medium" if pid in ("themida", "vmprotect") else "low",
                        "title": title, "evidence": f"sections: {', '.join(sorted(sec_names)) or 'none'}", "meaning": meaning + note,
                        "model_bias": pid in ("nsis", "upx")})

    if pe.get("dotnet"):
        c = classes.get("dotnet", {})
        out.append({"id": "format_dotnet", "severity": "info", "title": ".NET assembly",
                    "evidence": ".NET (CLR) header present",
                    "meaning": "Managed .NET code. Most logic is IL bytecode, which these native-PE features describe only coarsely."
                               + (f" Training data: {c.get('benign', 0)} benign / {c.get('malicious', 0)} malware .NET files." if c else "")})

    imports = pe.get("imports", {})
    names = {fn.lower() for fns in imports.values() for fn in fns}
    for gid, (sev, title, apis, meaning) in API_GROUPS.items():
        hit = sorted(n for n in names if n in apis)
        if gid == "dynamic" and not ({"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"} & names):
            hit = []
        if hit:
            out.append({"id": f"api_{gid}", "severity": sev, "title": title, "evidence": ", ".join(hit[:8]), "meaning": meaning})
    net = sorted(d for d in imports if d.lower() in NET_DLLS)
    if net:
        out.append({"id": "api_network", "severity": "info", "title": "Network capability", "evidence": ", ".join(net),
                    "meaning": "Links networking libraries, so it can talk to the internet or local network. Normal for most modern apps."})
    crypto = sorted(d for d in imports if d.lower() in CRYPTO_DLLS) + sorted(n for n in names if n.startswith("crypt") and n.endswith(("encrypt", "decrypt")))
    if crypto:
        out.append({"id": "api_crypto", "severity": "info", "title": "Cryptography capability", "evidence": ", ".join(crypto[:6]),
                    "meaning": "Uses Windows cryptography. Normal for HTTPS, licensing and updates; ransomware also relies on it."})

    n_imp = sum(len(v) for v in imports.values())
    secs = pe.get("sections", [])
    hi = [s for s in secs if s["entropy"] > 7.2 and s["raw_size"] > 1024]
    ep_sec = next((s for s in secs if s.get("has_entry_point")), None)
    if n_imp <= 10:
        out.append({"id": "few_imports", "severity": "medium" if hi else "low", "title": f"Very small import table ({n_imp} functions)",
                    "evidence": f"{n_imp} imported functions from {len(imports)} DLLs",
                    "meaning": "Packed or loader-style programs import almost nothing and resolve APIs after unpacking. "
                               "Tiny legitimate utilities can also look like this."})
    if any(s["rwx"] for s in secs):
        out.append({"id": "rwx", "severity": "medium", "title": "Writable and executable section",
                    "evidence": ", ".join(s["name"] for s in secs if s["rwx"]),
                    "meaning": "Memory that can be both modified and executed lets code rewrite itself, typical of packers and "
                               "shellcode loaders. Modern compilers avoid it."})
    if hi:
        out.append({"id": "high_entropy_sections", "severity": "low", "title": f"{len(hi)} high-entropy section(s)",
                    "evidence": ", ".join(f"{s['name']} ({s['entropy']:.2f})" for s in hi),
                    "meaning": "Near-random content: compressed or encrypted data. Normal for compressed resources (icons, "
                               "installer payloads); suspicious when it is the code section."})
    if ep_sec and ep_sec["entropy"] > 7.0:
        out.append({"id": "packed_entry", "severity": "medium", "title": "Entry point is in compressed/encrypted data",
                    "evidence": f"entry section {ep_sec['name']} entropy {ep_sec['entropy']:.2f}",
                    "meaning": "Execution starts in near-random bytes, so the real code must be unpacked first: a classic packer sign."})
    if pe.get("entry_outside_sections"):
        out.append({"id": "entry_outside", "severity": "medium", "title": "Entry point outside all sections",
                    "evidence": pe.get("entry_point", ""), "meaning": "Unusual layout produced by some packers and hand-crafted files."})
    ov, size = pe.get("overlay_size", 0), pe.get("size", 0) or 1
    if ov and ov / size > 0.3:
        out.append({"id": "large_overlay", "severity": "low", "title": f"Large appended data block ({ov / size:.0%} of file)",
                    "evidence": f"{ov:,} bytes after the last section, entropy {pe.get('overlay_entropy', 0):.2f}",
                    "meaning": "Installers, self-extracting archives and droppers carry their payload here. Its contents are "
                               "compressed, so static features cannot see what is inside."})
    if pe.get("embedded_pe", 0) > 1:
        out.append({"id": "embedded_pe", "severity": "medium", "title": f"{pe['embedded_pe'] - 1} embedded executable header(s)",
                    "evidence": "additional 'This program cannot be run in DOS mode' stubs",
                    "meaning": "Other executables are stored inside this one uncompressed: typical of droppers, but also of "
                               "bundles and setup programs."})
    if pe.get("tls"):
        out.append({"id": "tls", "severity": "low", "title": "TLS callbacks",
                    "evidence": "TLS directory present", "meaning": "Code that runs before the main entry point. Used by some "
                    "protectors and anti-debug tricks, and legitimately by some runtimes."})
    if not pe.get("aslr") or not pe.get("dep"):
        miss = [n for n, ok in (("ASLR", pe.get("aslr")), ("DEP", pe.get("dep"))) if not ok]
        out.append({"id": "no_mitigations", "severity": "low", "title": f"Missing exploit mitigations ({', '.join(miss)})",
                    "evidence": f"DllCharacteristics {pe.get('dll_characteristics', '')}",
                    "meaning": "Built without standard protections. Common for older toolchains and many installers; "
                               "rare for modern Microsoft-built software."})
    ts = pe.get("timestamp_unix")
    if ts is not None and (ts == 0 or ts > datetime.now(timezone.utc).timestamp() + 86400 or ts < 788918400):
        out.append({"id": "odd_timestamp", "severity": "low", "title": "Unrealistic compile timestamp",
                    "evidence": pe.get("timestamp", ""), "meaning": "Zeroed, ancient or future build dates are often forged; "
                    "reproducible-build tools also zero them."})
    if not pe.get("version_info"):
        out.append({"id": "no_version", "severity": "info", "title": "No version information",
                    "evidence": "no VS_VERSIONINFO resource", "meaning": "No product name, company or description embedded. "
                    "Most commercial software includes it; quick builds and malware often omit it."})
    urls = pe.get("urls") or []
    if urls:
        out.append({"id": "urls", "severity": "info", "title": f"{len(urls)} URL(s) in strings",
                    "evidence": ", ".join(urls[:4]), "meaning": "Web addresses embedded in the file: update servers, licences, "
                    "documentation, or command-and-control. Check whether they match the claimed publisher."})
    out.sort(key=lambda s: SEV_ORDER.get(s["severity"], 9))
    return out


def origin_signals(submissions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Signals from how the file arrived (EDR metadata)."""
    out = []
    for s in submissions:
        m = s.get("meta") or {}
        motw = m.get("motw") or {}
        if motw.get("zone") is not None and motw["zone"] >= 3:
            out.append({"id": "motw_internet", "severity": "info", "title": "Downloaded from the internet",
                        "evidence": motw.get("host_url") or f"Zone {motw['zone']}",
                        "meaning": "Windows tagged this file as coming from the internet (Mark-of-the-Web)."})
        nonstd = [r for r in m.get("remote", [])]
        if nonstd and "nonstd_port" in (m.get("rules") or []):
            out.append({"id": "edr_nonstd", "severity": "medium", "title": "Process talked to a public IP on an unusual port",
                        "evidence": ", ".join(nonstd[:4]), "meaning": "The running program connected somewhere outside the usual "
                        "web/mail ports. Reverse shells and C2 often do; so do games, P2P and some cloud tools."})
    return out


# ---------------------------------------------------------------- assessment (correlation)

def assessment(report: dict[str, Any], sigs: list[dict[str, Any]]) -> dict[str, Any]:
    """Heuristic analyst note that correlates the model's reasons with the context signals."""
    verdict, p = report.get("verdict"), report.get("probability")
    thr = next((e["threshold"] for e in report.get("engines", []) if e.get("recommended")), None)
    exp = report.get("explanation") or {}
    ids = {s["id"] for s in sigs}
    signed = "signed_valid" in ids
    signer = next((s["title"].replace("Validly signed by ", "") for s in sigs if s["id"] == "signed_valid"), "")
    installer = [s for s in sigs if s.get("model_bias") or s["id"] in ("format_inno",)]
    strong_bad = [s for s in sigs if s["severity"] in ("high", "medium") and not s["id"].startswith("format_")]
    groups = exp.get("groups", [])
    up = [g for g in groups if g["contribution"] > 0][:2]
    down = [g for g in groups if g["contribution"] < 0][:2]
    top_up = [r for r in exp.get("top", []) if r["contribution"] > 0][:3]
    top_down = [r for r in exp.get("top", []) if r["contribution"] < 0][:3]

    if p is None:
        return {"label": "Not scored", "tone": "neutral", "summary": "The file could not be scored; see the error on the Engines tab.",
                "points_for": [], "points_against": []}

    lines = [f"The pe_v3 model scored this file {p:.4f} against a threshold of {thr:.4f}"
             f" ({'flagged as malicious' if verdict == 'malicious' else 'below the threshold, so not flagged'})."]
    up = [g for g in up if g["contribution"] >= 0.1]
    down = [g for g in down if g["contribution"] <= -0.1]
    fmt_g = lambda gs: " and ".join(f"{g['label'].lower()} ({g['contribution']:+.2f})" for g in gs)  # noqa: E731
    lead_g, other_g = (up, down) if verdict == "malicious" else (down, up)
    if lead_g:
        lines.append(f"Most of the pull towards {'malicious' if verdict == 'malicious' else 'benign'} came from {fmt_g(lead_g)}"
                     + (f", while {fmt_g(other_g)} pulled the other way" if other_g else "") + " (log-odds).")
    lead = top_up if verdict == "malicious" else top_down
    if lead:
        lines.append(f"The strongest individual reasons towards {'malicious' if verdict == 'malicious' else 'benign'} were: "
                     + "; ".join(f"{r['title'].rstrip('.')} = {r['value']}" for r in lead) + ".")

    for_mal, against = [], []
    for s in strong_bad:
        for_mal.append(f"{s['title']}: {s['evidence']}")
    if signed:
        against.append(f"Valid Authenticode signature from {signer} (the model does not use signatures).")
    for s in installer:
        against.append(f"{s['title']}: a format the model is biased against (see its signal below).")
    if "no_version" not in ids:
        against.append("Has version information (product/company metadata).")
    if "signature_bad" in ids:
        for_mal.append("Signature exists but does not verify, so the claimed publisher is unconfirmed.")

    if verdict == "malicious":
        if installer and signed:
            label, tone = "Likely false positive - review", "warn"
            lines.append(f"Correlation: the main reasons are properties every {installer[0]['title'].split(' /')[0]} package shares "
                         f"(compressed appended data, a stock loader, framework section layout), and the file is validly signed by "
                         f"{signer}. This matches the known false-positive pattern for this model.")
        elif installer:
            label, tone = "Possible false positive - installer format", "warn"
            lines.append("Correlation: the file uses an installer/packer format the model associates with malware. The reasons "
                         "describe the wrapper, not its payload, so confirm the source before trusting or blocking it.")
        elif strong_bad:
            label, tone = "Consistent with malware indicators", "bad"
            lines.append("Correlation: the model's verdict is backed by independent structural or capability indicators "
                         "listed below.")
        elif signed:
            label, tone = "Flagged, but signed - review", "warn"
            lines.append("Correlation: no corroborating structural indicator was found and the file carries a valid signature. "
                         "Verify the signer is the expected publisher.")
        else:
            label, tone = "Flagged by model - unverified", "bad"
            lines.append("Correlation: no independent indicator confirms or contradicts the model; treat as suspicious until reviewed.")
    else:
        if p >= 0.5:
            label, tone = "Borderline - below threshold", "warn"
            lines.append("The score is high but under the calibrated threshold, which is set strictly to limit false positives.")
        elif [s for s in strong_bad if s["severity"] == "high"] and not signed:
            label, tone = "Not flagged, but indicators present", "warn"
            lines.append("Correlation: the model is not concerned, but high-severity capability indicators are present; review them.")
        else:
            label, tone = "No significant concern", "good"
    return {"label": label, "tone": tone, "summary": " ".join(lines), "paragraphs": lines, "points_for": for_mal, "points_against": against,
            "note": "Heuristic analyst note generated from the model's reasons and file context. It does not change the model verdict."}


GLOSSARY_EXTRA = {
    "Model score": "Probability-like output (0-1) of the pe_v3 LightGBM model. 1 means 'looks like the malware it was trained on'.",
    "Threshold": "Cut-off for a malicious verdict. 0.9603 was calibrated on 246 real benign files to keep false positives near 1%.",
    "Risk band": "High = at or above the threshold; Elevated = 0.5 up to the threshold (borderline); Low = below 0.5.",
    "Contribution (log-odds)": "SHAP value: how much one feature moved the score, in log-odds. +0.7 roughly doubles the odds of "
                               "'malicious'; -0.7 halves them. Contributions add up from the average file to the final score.",
    "Strength": "strong >= 0.5, moderate >= 0.2, minor < 0.2 (absolute log-odds).",
    "Typical benign / malware": "Median value of that feature among the 3,162 benign and 2,076 malware files the model was trained on.",
    "Disposition": "Analyst decision recorded on the dashboard (confirmed malicious, false positive, benign). It never changes the model output.",
}
