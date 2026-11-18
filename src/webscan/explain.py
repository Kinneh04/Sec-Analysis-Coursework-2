"""Plain-English explanations for SA2 Scan reports (V8 blend: EMBER2024 + Binary Ninja model).

Three layers, all derived from the scanned file (nothing is executed):
  1. reasons()     - the model's own drivers: per-feature SHAP contributions (EMBER2024's booster, plus 0.3 x the Binary
                     Ninja model's on files that have Binary Ninja features) translated into sentences, with the file's
                     value compared to typical benign / malware values from the V8 training pool.
  2. signals()     - context the model does not judge directly: signature validity, installer/packer family, API
                     capabilities, structural anomalies. Each signal says what it means and how often it is benign.
  3. assessment()  - correlates 1 and 2 into an analyst note (heuristic, clearly separate from the model verdict).

Feature names: em_<group>_<field> for the 2568 EMBER v3 features (layout in src/v8/ember_map.py, values computed by
thrember), cap6_* / hl6_* for the Binary Ninja features (src/v6/bn_capabilities.py, src/v6/bn_hlil.py). pe3_* names of
the retired V3.2 model are still described so stored V3.2 reports keep rendering.
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from src.v3.pe_features_v3 import DLL_BUCKETS, EXPORT_BUCKETS, IMPORT_BUCKETS, SECTION_BUCKETS, stable_bucket

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path("artifacts/v8/feature_reference.json")
STRONG, MODERATE = 0.5, 0.2  # |log-odds| cut-offs used by strength()

# ---------------------------------------------------------------- feature catalogue

GROUPS = {
    "entropy": ("Compression & encryption", "How random the bytes look: byte-value histogram, local-entropy histogram and "
                "section entropy. Compressed or encrypted content is close to 8 bits/byte; code and text are lower."),
    "overlay": ("Appended data (overlay)", "Bytes stored after the last PE section. Installers, self-extracting archives, "
                "signatures and droppers keep data here."),
    "headers": ("Headers & build toolchain", "DOS, COFF and optional-header fields set by the compiler/linker: architecture, "
                "subsystem, versions, sizes, timestamps and exploit-mitigation flags. They fingerprint how the file was built."),
    "directories": ("Data directories", "Size and address of the standard PE tables (imports, exceptions, relocations, "
                    "debug info, TLS, load configuration, .NET header...)."),
    "sections": ("Sections & layout", "How the file is divided into sections: names, sizes, permissions, and the section "
                 "where execution starts. Section names are hashed into slots, so some slots mix several names."),
    "imports": ("Imported APIs", "DLLs and functions the file asks the loader for (hashed into slots). They hint at "
                "capabilities, though most APIs are used by legitimate software too."),
    "exports": ("Exported functions", "Functions the file offers to other programs (mostly DLLs), hashed into slots."),
    "strings": ("Text strings", "Printable text inside the file: amount, character mix, and counts of strings matching "
                "patterns such as URLs, IP addresses, registry keys or words like 'password'."),
    "resources": ("Resources", "Size and location of the resource table (icons, dialogs, version information, manifests, "
                  "embedded data). Individual resources are not counted."),
    "size": ("File size", "Overall size of the file."),
    "rich": ("Rich header (build tools)", "Undocumented Microsoft linker record of the compiler and tool versions used to "
             "build the file. Entries are hashed into slots."),
    "signature": ("Authenticode signature (structure)", "Size and structure of the embedded code-signing data: number of "
                  "signatures and certificates, timestamps, parse errors. The model does not check whether it is valid."),
    "warnings": ("PE parser warnings", "Anomalies the pefile parser reported while reading the file (corrupt tables, odd "
                 "alignments, suspicious section flags). Common in packed and hand-crafted files, rare in normal builds."),
    "code": ("Code analysis (Binary Ninja)", "Indicators from disassembling and decompiling the code with Binary Ninja: API calls in "
             "the code, signs of run-time API resolution, stack strings, decoding loops, capability rules. Only present when Binary Ninja "
             "features were available; weighted 0.3 in the blend."),
}

# -- legacy V3.2 (pe3_*) catalogue: stored reports from the retired model are still rendered with these titles.
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

# -- EMBER v3 (thrember) catalogue. Categorical codes are indexes into thrember's HeaderFileInfo lists.
EM_MACHINES = ["unknown", "x86 (32-bit)", "MIPS R3000", "MIPS R4000", "MIPS R10000", "MIPS WCE v2", "Alpha", "SH3", "SH3 DSP",
               "SH3E", "SH4", "SH5", "ARM", "ARM Thumb", "ARM Thumb-2", "AM33", "PowerPC", "PowerPC FP", "IA-64", "MIPS16",
               "Alpha 64", "AXP 64", "MIPS FPU", "MIPS16 FPU", "TriCore", "CEF", "EFI byte code", "RISC-V 32", "RISC-V 64",
               "RISC-V 128", "LoongArch 32", "LoongArch 64", "x64", "M32R", "ARM64", "CEE"]
EM_SUBSYSTEMS = ["unknown", "native / driver", "Windows GUI", "console", "OS/2 console", "POSIX console", "native Win9x driver",
                 "Windows CE GUI", "EFI application", "EFI boot-service driver", "EFI runtime driver", "EFI ROM", "Xbox",
                 "Windows boot application"]
EM_HEADER = {
    "coff_timestamp": ("Compile timestamp (COFF header; can be forged, zeroed or a reproducible-build hash)", "time"),
    "coff_number_of_sections": ("Number of sections (COFF header)", "num"),
    "coff_number_of_symbols": ("COFF symbol count (normally 0 in executables)", "num"),
    "coff_sizeof_optional_header": ("Size of the optional header", "bytes"),
    "coff_pointer_to_symbol_table": ("COFF symbol-table offset (normally 0)", "hex"),
    "coff_machine": ("Target CPU architecture", "em_machine"),
    "optional_subsystem": ("Windows subsystem (GUI / console / driver)", "em_subsystem"),
    "optional_major_image_version": ("Image version field (major)", "num"),
    "optional_minor_image_version": ("Image version field (minor)", "num"),
    "optional_major_linker_version": ("Linker major version (build toolchain)", "num"),
    "optional_minor_linker_version": ("Linker minor version (build toolchain)", "num"),
    "optional_major_operating_system_version": ("Minimum Windows version field (major)", "num"),
    "optional_minor_operating_system_version": ("Minimum Windows version field (minor)", "num"),
    "optional_major_subsystem_version": ("Subsystem version field (major)", "num"),
    "optional_minor_subsystem_version": ("Subsystem version field (minor)", "num"),
    "optional_sizeof_code": ("Declared size of code", "bytes"),
    "optional_sizeof_headers": ("Size of the headers", "bytes"),
    "optional_sizeof_image": ("Size once loaded in memory", "bytes"),
    "optional_sizeof_initialized_data": ("Declared size of initialised data", "bytes"),
    "optional_sizeof_uninitialized_data": ("Declared size of uninitialised data", "bytes"),
    "optional_sizeof_stack_reserve": ("Reserved stack size", "bytes"),
    "optional_sizeof_stack_commit": ("Committed stack size", "bytes"),
    "optional_sizeof_heap_reserve": ("Reserved heap size", "bytes"),
    "optional_sizeof_heap_commit": ("Committed heap size", "bytes"),
    "optional_address_of_entrypoint": ("Entry-point address (RVA)", "hex"),
    "optional_base_of_code": ("Start address of code (RVA)", "hex"),
    "optional_image_base": ("Preferred load address", "hex"),
    "optional_section_alignment": ("Section alignment in memory", "bytes"),
    "optional_checksum": ("Header checksum value (0 = not filled in)", "hex"),
    "optional_number_of_rvas_and_sizes": ("Number of data-directory slots", "num"),
}
EM_CHARACTERISTICS = {
    "relocs_stripped": "relocations stripped", "executable_image": "executable image", "line_nums_stripped": "line numbers stripped",
    "local_syms_stripped": "local symbols stripped", "aggresive_ws_trim": "aggressive working-set trim (obsolete)",
    "large_address_aware": "large-address aware", "16bit_machine": "16-bit machine", "bytes_reversed_lo": "bytes reversed, low (obsolete)",
    "32bit_machine": "32-bit machine", "debug_stripped": "debug information stripped", "removable_run_from_swap": "run from swap if on removable media",
    "net_run_from_swap": "run from swap if on network", "system": "system file (driver)", "dll": "file is a DLL",
    "up_system_only": "uniprocessor only", "bytes_reversed_hi": "bytes reversed, high (obsolete)",
}
EM_DOS = {
    "e_magic": ("DOS header signature (0x5A4D = 'MZ')", "hex"), "e_cblp": ("DOS header: bytes on last page", "num"),
    "e_cp": ("DOS header: pages in file", "num"), "e_crlc": ("DOS header: relocation count", "num"),
    "e_cparhdr": ("DOS header: header size in paragraphs", "num"), "e_minalloc": ("DOS header: minimum extra paragraphs", "num"),
    "e_maxalloc": ("DOS header: maximum extra paragraphs", "num"), "e_ss": ("DOS header: initial SS", "hex"),
    "e_sp": ("DOS header: initial SP", "hex"), "e_csum": ("DOS header: checksum", "hex"), "e_ip": ("DOS header: initial IP", "hex"),
    "e_cs": ("DOS header: initial CS", "hex"), "e_lfarlc": ("DOS header: relocation-table offset", "hex"),
    "e_ovno": ("DOS header: overlay number", "num"), "e_oemid": ("DOS header: OEM id", "num"), "e_oeminfo": ("DOS header: OEM info", "num"),
    "e_lfanew": ("Offset of the PE header (DOS e_lfanew)", "hex"),
}
EM_SECTION = {
    "n_sections": ("Number of sections", "num", "sections"), "n_zero_size": ("Sections with no data on disk", "num", "sections"),
    "n_empty_name": ("Sections with no name", "num", "sections"),
    "n_rx": ("Sections that are readable and executable", "num", "sections"), "n_w": ("Writable sections", "num", "sections"),
    "max_entropy": ("Highest entropy of any section or of the appended data", "entropy", "entropy"),
    "min_entropy": ("Lowest section entropy (thrember adds a 0 to the list, so this is always 0)", "entropy", "entropy"),
    "max_size_ratio": ("Largest share of the file held by one section or by the appended data", "pct", "sections"),
    "min_size_ratio": ("Smallest share of the file held by one section (thrember adds a 0, so always 0)", "pct", "sections"),
    "max_vsize_ratio": ("Largest disk-size / memory-size ratio of a section", "ratio", "sections"),
    "min_vsize_ratio": ("Smallest disk-size / memory-size ratio of a section (thrember adds a 0, so always 0)", "ratio", "sections"),
    "overlay_size": ("Size of appended data (overlay)", "bytes", "overlay"),
    "overlay_size_ratio": ("Share of the file that is appended data", "pct", "overlay"),
    "overlay_entropy": ("Entropy of the appended data", "entropy", "overlay"),
}
EM_DIRS = {
    "export": ("export table", "exports"), "import": ("import table", "imports"), "resource": ("resource table", "resources"),
    "exception": ("exception (unwind) table", "directories"), "security": ("Authenticode certificate table", "signature"),
    "basereloc": ("base-relocation table", "directories"), "debug": ("debug directory", "directories"),
    "copyright": ("architecture-data slot (unused on Windows)", "directories"), "globalptr": ("global-pointer slot", "directories"),
    "tls": ("TLS (thread-local storage) table", "directories"), "load_config": ("load-configuration table", "directories"),
    "bound_import": ("bound-import table", "imports"), "iat": ("import address table", "imports"),
    "delay_import": ("delay-load import table", "imports"), "com_descriptor": (".NET (CLR) header", "directories"),
    "reserved": ("reserved slot (thrember skips the last slot, so this is 0 for standard headers)", "directories"),
}
EM_AUTH = {
    "num_certs": ("Number of Authenticode signatures parsed", "num"),
    "self_signed": ("A certificate before the last one in a signature has issuer = subject", "bool"),
    "empty_program_name": ("A signature has no program name", "bool"),
    "no_countersigner": ("A signature has no countersignature (no timestamp)", "bool"),
    "parse_error": ("The signature data could not be parsed", "bool"),
    "chain_max_depth": ("Certificates in the largest signature", "num"),
    "latest_signing_time": ("Latest countersigned signing time", "time"),
    "signing_time_diff": ("Signing time minus compile timestamp", "duration"),
}
SEC_PROPS = {"CNT_CODE": "contains code", "CNT_INITIALIZED_DATA": "contains initialised data",
             "CNT_UNINITIALIZED_DATA": "contains uninitialised data", "MEM_EXECUTE": "executable", "MEM_READ": "readable",
             "MEM_WRITE": "writable", "MEM_DISCARDABLE": "discardable", "MEM_SHARED": "shared", "MEM_NOT_PAGED": "not paged",
             "MEM_NOT_CACHED": "not cached", "LNK_INFO": "linker info", "LNK_REMOVE": "removed by linker", "LNK_COMDAT": "COMDAT data",
             "GPREL": "global-pointer relative", "LNK_NRELOC_OVFL": "extended relocations"}
# Regex keys of thrember's StringExtractor whose pattern does not match what the key suggests (thrember 0.1.0).
EM_REGEX_TEXT = {
    "url": "a URL (http, https or ftp)", "ipv4_addr": "an IPv4 address", "ipv6_addr": "an IPv6-like address pattern",
    "mac_addr": "a MAC-address pattern", "email_addr": "a MAC-address pattern (thrember's 'email' pattern is a copy of its MAC pattern)",
    "btc_wallet": "a Bitcoin-address-like token (loose pattern: ordinary text also matches)",
    "file_path": "'C:/' (a Windows path written with a forward slash)", "dos_msg": "'!This program' (a DOS stub, i.e. an MZ header)",
    "registry_key": "'HKCU' (thrember's registry pattern; its other spellings, KHEY_ and KHLM, are typos)",
    ".click(": "'click' after any character", "onlick": "'onclick'", "base64string": "the Base64 alphabet",
}
# Common names, used only to say which well-known name shares a hashed slot when this file has nothing there.
HINT_SECTIONS = [".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".idata", ".edata", ".tls", ".bss", ".crt", ".didat",
                 ".gfids", ".00cfg", ".xdata", "code", "data", "bss", ".itext", "upx0", "upx1", "upx2", ".ndata", ".aspack",
                 ".adata", ".mpress1", ".mpress2", ".themida", ".winlice", ".vmp0", ".vmp1", ".vmp2", ".petite", ".nsp0",
                 ".enigma1", ".rodata", ".eh_fram", "/4", ".debug", ".textbss", "init", "page", ".voltbl", ".retplne", ".sxdata"]
HINT_DLLS = ["kernel32.dll", "user32.dll", "advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll", "gdi32.dll", "ntdll.dll",
             "msvcrt.dll", "comctl32.dll", "comdlg32.dll", "shlwapi.dll", "version.dll", "mscoree.dll", "ws2_32.dll", "wsock32.dll",
             "wininet.dll", "winhttp.dll", "urlmon.dll", "crypt32.dll", "bcrypt.dll", "rpcrt4.dll", "iphlpapi.dll", "psapi.dll",
             "winmm.dll", "setupapi.dll", "userenv.dll", "netapi32.dll", "secur32.dll", "dbghelp.dll", "imm32.dll", "uxtheme.dll",
             "dwmapi.dll", "gdiplus.dll", "msimg32.dll", "winspool.drv", "oleacc.dll", "mpr.dll", "wtsapi32.dll", "vcruntime140.dll",
             "msvcp140.dll", "ucrtbase.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-stdio-l1-1-0.dll",
             "api-ms-win-crt-heap-l1-1-0.dll", "api-ms-win-crt-string-l1-1-0.dll", "api-ms-win-crt-math-l1-1-0.dll",
             "api-ms-win-crt-locale-l1-1-0.dll", "msvbvm60.dll", "python3.dll", "libgcc_s_dw2-1.dll", "cabinet.dll", "wintrust.dll"]
HINT_FUNCS = {
    "kernel32.dll": ["GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExW", "GetModuleHandleA", "GetModuleHandleW",
                     "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualFree", "WriteProcessMemory", "ReadProcessMemory",
                     "CreateRemoteThread", "OpenProcess", "CreateProcessA", "CreateProcessW", "WinExec", "CreateFileA", "CreateFileW",
                     "WriteFile", "ReadFile", "DeleteFileW", "CopyFileW", "MoveFileExW", "FindFirstFileW", "FindNextFileW",
                     "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "Process32FirstW", "Process32NextW",
                     "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA", "GetTickCount", "Sleep",
                     "QueryPerformanceCounter", "ExitProcess", "TerminateProcess", "GetCurrentProcess", "GetCurrentProcessId",
                     "GetCurrentThreadId", "CreateThread", "ResumeThread", "SuspendThread", "SetThreadContext", "GetThreadContext",
                     "QueueUserAPC", "CreateMutexA", "CreateMutexW", "GetLastError", "SetLastError", "GetCommandLineA",
                     "GetCommandLineW", "GetStartupInfoW", "GetSystemTimeAsFileTime", "HeapAlloc", "HeapFree", "GetProcessHeap",
                     "InitializeCriticalSectionAndSpinCount", "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection",
                     "UnhandledExceptionFilter", "SetUnhandledExceptionFilter", "IsProcessorFeaturePresent", "RtlCaptureContext",
                     "RtlLookupFunctionEntry", "RtlVirtualUnwind", "GetModuleFileNameA", "GetModuleFileNameW", "GetTempPathW",
                     "GetWindowsDirectoryW", "GetSystemDirectoryW", "CreateFileMappingW", "MapViewOfFile", "UnmapViewOfFile",
                     "FreeLibrary", "GetFileSize", "SetFilePointer", "CloseHandle", "WaitForSingleObject", "DeviceIoControl",
                     "GetVersionExA", "GetVersionExW", "GlobalAlloc", "GlobalFree", "LocalAlloc", "LocalFree", "MultiByteToWideChar",
                     "WideCharToMultiByte", "lstrlenA", "lstrlenW", "lstrcpyA", "lstrcpyW", "GetEnvironmentVariableW",
                     "SetFileAttributesW", "GetComputerNameW", "FindResourceW", "LoadResource", "LockResource", "SizeofResource"],
    "user32.dll": ["MessageBoxA", "MessageBoxW", "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
                   "GetForegroundWindow", "FindWindowA", "FindWindowW", "ShowWindow", "CreateWindowExW", "GetDC", "ReleaseDC",
                   "OpenClipboard", "GetClipboardData", "SetClipboardData", "DispatchMessageW", "GetMessageW", "PostQuitMessage",
                   "DefWindowProcW", "RegisterClassExW", "LoadIconW", "LoadCursorW", "SendMessageW", "wsprintfA", "wsprintfW",
                   "GetDesktopWindow", "GetSystemMetrics", "CharUpperW", "GetKeyboardState", "RegisterRawInputDevices"],
    "advapi32.dll": ["RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
                     "RegQueryValueExW", "RegCloseKey", "RegDeleteValueW", "OpenProcessToken", "AdjustTokenPrivileges",
                     "LookupPrivilegeValueA", "LookupPrivilegeValueW", "CreateServiceA", "CreateServiceW", "OpenSCManagerW",
                     "StartServiceW", "CryptAcquireContextA", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
                     "CryptImportKey", "CryptCreateHash", "CryptHashData", "GetUserNameW", "OpenServiceW", "ControlService"],
    "shell32.dll": ["ShellExecuteA", "ShellExecuteW", "ShellExecuteExW", "SHGetFolderPathW", "SHGetSpecialFolderPathW",
                    "CommandLineToArgvW", "SHFileOperationW", "SHGetKnownFolderPath"],
    "ntdll.dll": ["NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtQueryInformationProcess", "NtWriteVirtualMemory",
                  "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx", "RtlCreateUserThread", "RtlMoveMemory",
                  "NtSetInformationThread", "LdrLoadDll", "LdrGetProcedureAddress", "RtlGetVersion", "NtQuerySystemInformation"],
    "ws2_32.dll": ["WSAStartup", "WSACleanup", "socket", "connect", "send", "recv", "closesocket", "gethostbyname", "getaddrinfo",
                   "inet_addr", "htons", "bind", "listen", "accept", "WSASocketW"],
    "wininet.dll": ["InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile", "InternetConnectW",
                    "HttpOpenRequestW", "HttpSendRequestW", "InternetCloseHandle"],
    "winhttp.dll": ["WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest", "WinHttpReceiveResponse",
                    "WinHttpReadData"],
    "urlmon.dll": ["URLDownloadToFileA", "URLDownloadToFileW"],
    "crypt32.dll": ["CryptUnprotectData", "CryptStringToBinaryA", "CertOpenStore"],
    "mscoree.dll": ["_CorExeMain", "_CorDllMain"],
    "msvbvm60.dll": ["ThunRTMain"],
    "gdi32.dll": ["BitBlt", "CreateCompatibleDC", "CreateCompatibleBitmap", "SelectObject", "DeleteObject", "GetDeviceCaps"],
    "ole32.dll": ["CoInitialize", "CoInitializeEx", "CoCreateInstance", "CoUninitialize", "OleInitialize"],
    "psapi.dll": ["EnumProcesses", "GetModuleBaseNameW", "EnumProcessModules"],
}
HINT_EXPORTS = ["DllMain", "DllRegisterServer", "DllUnregisterServer", "DllGetClassObject", "DllCanUnloadNow", "DllInstall",
                "ServiceMain", "SvchostPushServiceGlobals", "GetFileVersionInfoW", "Start", "Run", "main", "_start",
                "PyInit__ctypes", "CPlApplet", "DriverEntry", "WinMain", "Initialize", "StartW", "Uninstall", "Install"]
HINT_PROPS = [f"{s}:{p}" for s in (".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".idata", ".bss", ".tls", "upx0", "upx1",
                                   ".ndata", "code", "data", ".itext")
              for p in ("CNT_CODE", "MEM_EXECUTE", "MEM_READ", "MEM_WRITE", "CNT_INITIALIZED_DATA", "CNT_UNINITIALIZED_DATA",
                        "MEM_DISCARDABLE")]

# -- Binary Ninja features (exact meaning: src/v6/bn_capabilities.py features_from_doc, src/v6/bn_hlil.py features_from_doc)
BN_STRINGS = {"s_runkey": "autostart registry locations (Run key, Winlogon, Image File Execution Options)",
              "s_browser": "browser credential or cookie stores (Login Data, logins.json, cookies.sqlite...)",
              "s_wallet": "cryptocurrency wallets (wallet.dat, Electrum, Exodus, MetaMask, Ethereum)",
              "s_shadow": "shadow-copy or backup removal tools (vssadmin, wbadmin, bcdedit, 'delete shadows')",
              "s_shell": "shell commands (cmd /c, PowerShell, schtasks, reg add)",
              "s_vm": "virtual machines, sandboxes or analysis tools (VMware, VirtualBox, QEMU, Sandboxie, Wireshark...)",
              "s_url": "URLs, IPv4 addresses or .onion hosts",
              "s_ransom": "ransom-note words ('your files', decrypt, bitcoin, ransom, .locked)",
              "s_selfdel": "self-deletion commands (ping 127.0.0.1, del /f, choice /c)", "s_debugpriv": "SeDebugPrivilege"}
BN_RULES = {"r_injection": "process injection (remote memory write plus remote allocation or remote thread/APC)",
            "r_hollowing": "process hollowing (process creation, remote write, and unmap/thread-context APIs)",
            "r_keylog": "keyboard capture (hooks or key-state APIs)", "r_screen": "screen capture (2+ screen/bitmap APIs)",
            "r_clipboard": "clipboard access (2+ clipboard APIs)", "r_crypt_files": "file encryption (crypto APIs plus file enumeration)",
            "r_net_exec": "download-and-run (network plus process-launch APIs)",
            "r_persist_run": "autostart persistence (registry/service writes plus autostart-key strings)",
            "r_credential": "credential theft (credential APIs, or browser/wallet strings)", "r_antidebug": "debugger detection APIs",
            "r_privilege": "privilege adjustment (2+ token-privilege APIs, or one with 'SeDebugPrivilege')",
            "r_proc_scan_open": "process scanning (process enumeration plus OpenProcess)",
            "r_shadow": "shadow-copy deletion strings", "r_dyn_sensitive": "sensitive-API lookup (GetProcAddress plus sensitive API names in one function)"}
BN_API_GROUPS = {"inject_write": "remote memory write", "inject_alloc": "remote memory allocation/mapping",
                 "inject_exec": "remote thread/APC/context", "hollow": "unmap/thread-context (hollowing)", "proc_open": "process opening",
                 "proc_enum": "process enumeration", "keylog": "keyboard capture", "screen": "screen capture", "clipboard": "clipboard",
                 "crypto": "encryption", "credential": "credential access", "file_enum": "file enumeration", "net": "network",
                 "exec": "process launch", "persist": "registry/service persistence", "antidebug": "debugger detection",
                 "privilege": "token privileges", "memprotect": "memory allocation/protection", "dyn": "API resolution/library loading"}
BN = {
    "cap6_call_after_resolve": ("Indirect calls made after GetProcAddress in the same function", "num"),
    "cap6_cpuid": ("CPUID instructions (CPU / virtual-machine fingerprinting)", "num"),
    "cap6_export_parse": ("Functions using memory offsets +0x3C and +0x78/+0x88 (PE export-directory parsing, a sign of "
                          "manual API lookup)", "num"),
    "cap6_fn_dyn_call": ("Functions with an indirect call after a GetProcAddress call (likely calling a looked-up API)", "num"),
    "cap6_fn_hash_loop": ("Functions with an API-hashing-style loop (rotate, loop, 32-bit compare)", "num"),
    "cap6_fn_peb_export": ("Functions with both a PEB/TEB access and export-directory offsets (a sign of manual API lookup)",
                           "num"),
    "cap6_fn_xor_loop": ("Functions with a byte-XOR loop (simple decoding)", "num"),
    "cap6_frac_call_func": ("Share of calls that go to the file's own functions", "pct"),
    "cap6_frac_call_import": ("Share of calls that go to imported APIs", "pct"),
    "cap6_frac_call_mem_indirect": ("Share of calls through memory pointers", "pct"),
    "cap6_frac_call_reg_unresolved": ("Share of calls through registers not traced to an import", "pct"),
    "cap6_frac_disassembled": ("Share of functions disassembled within the time budget", "pct"),
    "cap6_imported_unused_frac": ("Share of imported APIs never called from the disassembled code", "pct"),
    "cap6_known_hash": ("Constants equal to known API-name hashes (ROR13 or CRC32)", "num"),
    "cap6_n_dyn_names": ("Known API names referenced as strings in functions that call GetProcAddress (likely run-time "
                         "resolution; inferred, not observed)", "num"),
    "cap6_n_dyn_sensitive": ("Sensitive API names referenced as strings in functions that call GetProcAddress (likely "
                             "run-time resolution; inferred, not observed)", "num"),
    "cap6_n_functions": ("Functions found by Binary Ninja", "num"),
    "cap6_n_imports": ("Distinct imported APIs seen by Binary Ninja", "num"),
    "cap6_n_insn": ("Instructions disassembled", "num"),
    "cap6_n_rules_fired": ("Capability rules matched in at least one function (of 14, disassembly)", "num"),
    "cap6_overlay_stripped": ("Appended data was cut off before analysis (file over 16 MB)", "bool"),
    "cap6_peb": ("Instructions reading the PEB/TEB (fs:[0x30], gs:[0x60]...)", "num"),
    "cap6_per_kinsn_backward_jumps": ("Backward jumps (loops) per 1,000 instructions", "num"),
    "cap6_per_kinsn_cmp_imm32": ("Compares with a 32-bit constant per 1,000 instructions", "num"),
    "cap6_per_kinsn_rot_imm": ("Rotate-by-constant instructions per 1,000 instructions", "num"),
    "cap6_per_kinsn_xor_byte": ("Byte-sized XOR instructions per 1,000 instructions", "num"),
    "cap6_per_kinsn_xor_nonself": ("XOR instructions with two different operands per 1,000 instructions", "num"),
    "cap6_rdtsc": ("RDTSC timing instructions (timing-based anti-analysis)", "num"),
    "cap6_stack_str_bytes": ("Bytes of strings built on the stack (disassembly)", "bytes"),
    "cap6_stack_str_runs": ("Strings built on the stack (runs of 4+ printable-constant moves)", "num"),
    "cap6_str_sensitive_api_not_imported": ("Sensitive API names present as strings but not imported", "num"),
    "cap6_strong_any": ("Any strong evasion indicator (PEB+export walk, hash loop with known hash, sensitive API name in a "
                        "function that calls GetProcAddress, or direct syscall)", "bool"),
    "cap6_syscall": ("Direct system-call instructions (syscall, sysenter, int 0x2e)", "num"),
    "cap6_unpacked_upx": ("File was UPX-unpacked before analysis", "bool"),
    "hl6_frac_library_named": ("Share of functions with a name other than sub_* (library signatures, symbols or exports)",
                               "pct"),
    "hl6_gpa_const": ("GetProcAddress calls with a constant API name (decompiled code)", "num"),
    "hl6_gpa_global_store": ("GetProcAddress results stored in globals (API pointer tables)", "num"),
    "hl6_gpa_nonconst": ("GetProcAddress calls with a computed name (decompiled code)", "num"),
    "hl6_loadlib": ("LoadLibrary / GetModuleHandle calls (decompiled code)", "num"),
    "hl6_n_modules_loaded": ("Distinct module names passed to LoadLibrary / GetModuleHandle", "num"),
    "hl6_n_resolved": ("Distinct API names passed as constants to GetProcAddress (decompiled code)", "num"),
    "hl6_n_resolved_sensitive": ("Distinct sensitive API names passed as constants to GetProcAddress (decompiled code)", "num"),
    "hl6_n_rules_fired": ("Capability rules matched in at least one function (of 14, decompiled code)", "num"),
    "hl6_n_stack_strings": ("Strings built on the stack (decompiled code)", "num"),
    "hl6_n_sub": ("Functions without a name (sub_*); the decompiled-code features come from these", "num"),
    "hl6_stack_api_names": ("Known API names among stack-built strings", "num"),
    "hl6_stack_dll_names": ("DLL names among stack-built strings", "num"),
}
for _k, _v in BN_STRINGS.items():
    BN[f"cap6_file_{_k}"] = (f"Strings in the file naming {_v}", "num")
    BN[f"hl6_stack_{_k}"] = (f"Stack-built strings naming {_v}", "num")
for _k, _v in BN_RULES.items():
    BN[f"cap6_{_k}"] = (f"Functions matching the {_v} rule (disassembly)", "num")
    BN[f"hl6_{_k}"] = (f"Functions matching the {_v} rule (decompiled code)", "num")
for _k, _v in BN_API_GROUPS.items():
    BN[f"hl6_resolved_{_k}"] = (f"API names passed as constants to GetProcAddress: {_v}", "num")


def _char_name(i: int) -> str:
    c = chr(i + 0x20)
    return {" ": "space", "\x7f": "DEL (0x7F)"}.get(c, f"'{c}'")


@lru_cache(maxsize=1)
def _thrember_info() -> dict[str, Any]:
    """Regex patterns and pefile warning texts straight from thrember's feature classes (empty if thrember is absent)."""
    try:
        from thrember import features as tf
    except Exception:
        return {}
    se = tf.StringExtractor()
    regex = {}
    for name, idx in se.regex_idxs.items():
        pat = se._regexes[name]
        regex[idx] = (name, pat.pattern, bool(pat.flags & re.IGNORECASE))
    warn: dict[int, str] = {}
    try:
        wf = Path(tf.__file__).with_name("pefile_warnings.txt")
        warn = {i: t for t, i in tf.PEFormatWarnings(wf).warning_ids.items()}
    except Exception:
        pass
    return {"regex": regex, "warn": warn}


def _regex_title(idx: int, slug: str) -> str:
    info = _thrember_info().get("regex", {}).get(idx)
    if not info:
        return f"Strings matching thrember pattern '{slug}'"
    name, pattern, icase = info
    text = EM_REGEX_TEXT.get(name)
    if text is None:
        text = f"'{pattern}'" + (" (any case)" if icase else "")
    return f"Strings containing {text}"


def _warn_title(idx: int) -> str:
    t = _thrember_info().get("warn", {}).get(idx)
    if not t:
        return f"pefile warning #{idx}"
    return "pefile warning: " + t.replace("...", " ...").strip()


# ---------------------------------------------------------------- hashed EMBER features

HASH_DIMS = {"sec": 50, "props": 50, "entry": 10, "lib": 256, "fn": 1024, "exp": 128, "rich": 32}
HASH_SIGNED = {"sec": True, "props": True, "entry": True, "lib": False, "fn": False, "exp": True, "rich": True}


def hash_slots(tokens: list[str], kind: str) -> list[tuple[int, int]]:
    """(slot, sign) of each token, using the same sklearn FeatureHasher settings thrember uses for `kind`."""
    if not tokens:
        return []
    from sklearn.feature_extraction import FeatureHasher

    x = FeatureHasher(HASH_DIMS[kind], input_type="string", alternate_sign=HASH_SIGNED[kind]).transform([[t] for t in tokens]).tocsr()
    out = []
    for i in range(len(tokens)):
        a = x.indptr[i]
        out.append((int(x.indices[a]), 1 if x.data[a] > 0 else -1))
    return out


def _by_slot(tokens: list[str], kind: str) -> dict[int, list[tuple[str, int]]]:
    out: dict[int, list[tuple[str, int]]] = {}
    for t, (slot, sign) in zip(tokens, hash_slots(tokens, kind)):
        out.setdefault(slot, []).append((t, sign))
    return out


@lru_cache(maxsize=1)
def _hints() -> dict[str, dict[int, list[str]]]:
    toks = {"sec": HINT_SECTIONS, "entry": HINT_SECTIONS, "lib": HINT_DLLS, "exp": HINT_EXPORTS, "props": HINT_PROPS,
            "fn": [f"{d}:{f}" for d, fs in HINT_FUNCS.items() for f in fs]}
    try:
        return {k: {s: [t for t, _ in v] for s, v in _by_slot(list(t), k).items()} for k, t in toks.items()}
    except Exception:
        return {}


def _em_tokens_exact(raw: bytes) -> dict[str, list[str]]:
    """Hashed-feature tokens exactly as thrember 0.1.0 builds them (same pefile parse, same strings)."""
    import pefile
    from thrember import features as tf

    try:
        pe = pefile.PE(data=raw)
    except (pefile.PEFormatError, AttributeError):
        return {k: [] for k in HASH_DIMS}
    try:
        secs = []
        for s in pe.sections:
            name = s.Name.strip(b"\x00").decode(errors="ignore").lower()
            secs.append((name, [sc[10:] for sc, _ in pefile.section_characteristics if s.__dict__[sc]]))
        entry = ""  # SectionInfo.raw_features: last section containing the entry point, else first executable section
        aoep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        inside = False
        for s in pe.sections:
            if s.contains_rva(aoep):
                entry = s.Name.strip(b"\x00").decode(errors="ignore").lower()
                inside = True
        i, fallback = 0, False
        while entry == "" and i < len(pe.sections):
            if pe.sections[i].Characteristics & 0x20000000 > 0:
                entry = pe.sections[i].Name.strip(b"\x00").decode(errors="ignore").lower()
                fallback = True
            i += 1
        entry_where = ("unnamed_fallback" if inside else "first_exec") if fallback else ("inside" if inside else "outside")
        imports = tf.ImportsInfo().raw_features(raw, pe)
        exports = tf.ExportsInfo().raw_features(raw, pe)
        rich = list(pe.RICH_HEADER.values) if pe.RICH_HEADER is not None else []
    finally:
        pe.close()
    return {
        "sec": [n for n, _ in secs], "props": [f"{n}:{p}" for n, props in secs for p in props],
        "entry": [entry] if secs else [], "_entry_where": entry_where,
        "lib": list({lib.lower() for lib in imports}), "fn": [lib.lower() + ":" + e for lib, es in imports.items() for e in es],
        "exp": list(exports), "rich": [str(rich[i]) for i in range(0, len(rich) - 1, 2)],
    }


def _em_tokens_approx(sections: list[str], imports: dict[str, list[str]], exports: list[str]) -> dict[str, list[str]]:
    """Tokens rebuilt from scanner.pe_details() lists. Exact for named imports/exports and ASCII section names; ordinal
    imports lose the DLL name's original case. No section flags, entry section or Rich header."""
    fn = []
    for dll, fns in imports.items():
        d = dll.lower()
        fn += [f"{d}:{d}:ordinal{f[4:]}" if f.startswith("ord_") else f"{d}:{f}" for f in fns]
    return {"sec": [(s or "").strip("\x00").lower() for s in sections], "lib": list({d.lower() for d in imports}), "fn": fn,
            "exp": [f"ordinal{e[4:]}" if e.startswith("ord_") else e for e in exports]}


def build_context(sections: list[str], imports: dict[str, list[str]], exports: list[str], raw: bytes | None = None) -> dict[str, Any]:
    """Per-file lookup tables that turn hashed feature slots back into this file's names.

    raw (optional): the file bytes. With them, slots are resolved exactly as thrember computes them (section flags,
    entry section and Rich header included); without them, from the pe_details() lists (approximate, see above).
    """
    sb, ib, db, eb = {}, {}, {}, {}
    for s in sections:
        sb.setdefault(stable_bucket(s or "<empty>", SECTION_BUCKETS), []).append(s or "<empty>")
    for dll, fns in imports.items():
        db.setdefault(stable_bucket(dll, DLL_BUCKETS), []).append(dll)
        for fn in fns:
            ib.setdefault(stable_bucket(f"{dll}:{fn}" if not fn.startswith("ord_") else f"{dll}:ord{fn[4:]}", IMPORT_BUCKETS), []).append(f"{dll}:{fn}")
    for e in exports:
        eb.setdefault(stable_bucket(e if not e.startswith("ord_") else f"ord{e[4:]}", EXPORT_BUCKETS), []).append(e)
    ctx: dict[str, Any] = {"sections_by_bucket": sb, "imports_by_bucket": ib, "dlls_by_bucket": db, "exports_by_bucket": eb}
    em: dict[str, Any] = {"resolution": "none", "have": set()}
    toks = None
    if raw is not None:
        try:
            toks, em["resolution"] = _em_tokens_exact(raw), "exact"
            em["entry_where"] = toks.pop("_entry_where", None)  # inside | first_exec | outside (for the entry-section title)
        except Exception:
            toks = None
    if toks is None:
        try:
            toks, em["resolution"] = _em_tokens_approx(sections, imports, exports), "approximate"
        except Exception:
            toks = None
    if toks is not None:
        try:
            for kind, t in toks.items():
                em[kind] = _by_slot(t, kind)
                em["have"].add(kind)
        except Exception:  # sklearn missing: no slot resolution
            em = {"resolution": "none", "have": set()}
    ctx["em"] = em
    return ctx


def _uniq(xs: list[str]) -> list[str]:
    return list(dict.fromkeys(xs))


def _show(names: list[str], n: int = 3) -> str:
    u = _uniq(names)
    return ", ".join(u[:n]) + (f" and {len(u) - n} more" if len(u) > n else "")


def _sec(n: str) -> str:
    return n if n else "(unnamed)"


def _fn(tok: str) -> str:
    dll, _, f = tok.partition(":")
    m = re.match(r"^.*:ordinal(\d+)$", f)
    return f"ordinal {m.group(1)} ({dll})" if m else f"{f} ({dll})"


def _prop(tok: str) -> str:
    n, _, p = tok.rpartition(":")
    return f"{_sec(n)} {SEC_PROPS.get(p, p.lower().replace('_', ' '))}"


def _rich(tok: str) -> str:
    try:
        v = int(tok)
        return f"tool id 0x{v >> 16:04X} build {v & 0xFFFF}"
    except ValueError:
        return tok


def _hint(kind: str, slot: int, fmt: Any = str) -> str:
    h = _hints().get(kind, {}).get(slot)
    return f"; slot of {', '.join(fmt(x) for x in h[:2])} among others" if h else ""


def _hashed(kind: str, slot: int, field_kind: str, ctx: dict[str, Any], value: float | None) -> tuple[str, str]:
    """(title, fmt) for one hashed slot, worded so it stays true under signed hashing and collisions."""
    em = (ctx or {}).get("em") or {}
    have = kind in em.get("have", set())
    members = (em.get(kind) or {}).get(slot, []) if have else []
    nonzero = value is not None and not (isinstance(value, float) and math.isnan(value)) and value != 0
    w = {"sec": 2, "props": 2, "entry": 1, "lib": 3, "fn": 4, "exp": 3, "rich": 2}[kind]
    tag = f"hashed slot {slot:0{w}d}"
    if kind == "sec":
        label, base = {"size": ("Size on disk", "bytes"), "vsize": ("Size in memory", "bytes"), "entropy": ("Entropy", "entropy")}[field_kind]
        if members:
            names = _uniq([_sec(n) for n, _ in members])
            if len(members) == 1:
                return f"{label} of section {names[0]}", f"abs{base}"
            return f"{label}, signed sum over sections {_show(names, 4)} ({tag}; values can cancel)", "num"
        if have and not nonzero:
            return f"{label} of sections in {tag} (none in this file{_hint('sec', slot)})", base
        return f"{label} of sections whose names fall in {tag} (names not resolved)", "num"
    if kind == "props":
        if members:
            if len(members) == 1:
                return f"Section flag: {_prop(members[0][0])}", "flag"
            return f"Section flags {_show([_prop(t) for t, _ in members], 4)} (signed count, {tag})", "num"
        if have and not nonzero:
            return f"Section flags in {tag} (none in this file{_hint('props', slot, _prop)})", "num"
        return f"Section-flag tokens in {tag} (not resolved)", "num"
    if kind == "entry":
        if members:
            name, where = members[0][0], em.get("entry_where")
            if where == "outside":
                return "Entry point lies outside every section (and no section is executable)", "flag"
            if where == "first_exec":
                return f"Entry point lies outside every section; first executable section {_sec(name)} used instead", "flag"
            if where == "unnamed_fallback":
                return f"Entry point is in an unnamed section; first executable section {_sec(name)} used instead", "flag"
            return (f"Execution starts in section {name}" if name else "Execution starts in an unnamed section"), "flag"
        if have and not nonzero:
            return f"Execution starts in a section named in {tag} (not this file{_hint('entry', slot, _sec)})", "flag"
        return f"Entry-point section name falls in {tag} (name not resolved)", "num"
    if kind == "lib":
        if members:
            return f"Imports from {_show([n for n, _ in members])}", "num"
        if have and not nonzero:
            return f"Imports from a DLL in {tag} (none in this file{_hint('lib', slot)})", "num"
        return f"Imported DLLs in {tag} (not resolved)", "num"
    if kind == "fn":
        if members:
            n = len(members)
            return f"Imports {_show([_fn(t) for t, _ in members])}" + (f" ({n} imports in {tag})" if n > 1 else ""), "num"
        if have and not nonzero:
            return f"Imports a function in {tag} (none in this file{_hint('fn', slot, _fn)})", "num"
        return f"Imported functions in {tag} (not resolved)", "num"
    if kind == "exp":
        if members:
            if len(members) == 1:
                return f"Exports {members[0][0]}", "flag"
            return f"Exports {_show([n for n, _ in members])} (signed count, {tag})", "num"
        if have and not nonzero:
            return f"Exports a name in {tag} (none in this file{_hint('exp', slot)})", "num"
        return f"Export names in {tag} (not resolved)", "num"
    # rich
    if members:
        if len(members) == 1:
            return f"Rich header: objects built by {_rich(members[0][0])}", "absnum"
        return f"Rich header: signed sum of object counts for {_show([_rich(t) for t, _ in members])} ({tag})", "num"
    if have and not nonzero:
        return f"Rich header records in {tag} (none in this file)", "num"
    return f"Rich header records in {tag} (not resolved)", "num"


# ---------------------------------------------------------------- describe

def _describe_em(name: str, ctx: dict[str, Any], value: float | None) -> tuple[str, str, str] | None:
    try:
        group, field = name[3:].split("_", 1)
    except ValueError:
        return None
    if group == "general":
        if field == "size":
            return "size", "File size", "bytes"
        if field == "entropy":
            return "entropy", "Overall byte entropy of the file", "entropy"
        if field == "is_pe":
            return "headers", "File parsed as a valid PE", "bool"
        m = re.fullmatch(r"start_byte_(\d)", field)
        if m:
            k = int(m.group(1))
            what = {0: "First byte of the file (normally 'M')", 1: "Second byte of the file (normally 'Z')",
                    2: "Third byte of the file (DOS header)", 3: "Fourth byte of the file (DOS header)"}[k]
            return "headers", what, "byte"
    if group == "histogram":
        m = re.fullmatch(r"byte_([0-9a-f]{2})", field)
        if m:
            return "entropy", f"Share of bytes equal to 0x{m.group(1).upper()}", "pct"
    if group == "byteentropy":
        m = re.fullmatch(r"e(\d{2})_b([0-9a-f])", field)
        if m:
            e, b = int(m.group(1)), m.group(2).upper()
            lo, hi = e / 2, e / 2 + 0.5
            kind = "near-random (compressed or encrypted)" if lo >= 7 else ("structured (code or data)" if lo >= 4 else "repetitive or sparse")
            # thrember ByteEntropyHistogram: 2048-byte windows every 1024 bytes (overlapping), each window's bytes counted
            # in (entropy bin, high nibble); the 256 cells are normalised together, so this is a joint share.
            return "entropy", (f"Share of all sampled bytes that are 0x{b}0-0x{b}F and sit in a {kind} window "
                               f"({lo:.1f}-{hi:.1f} bits/byte; overlapping 2 KB windows, 1 KB step)"), "pct"
    if group == "strings":
        fixed = {"numstrings": ("Number of printable strings (5+ characters)", "num"),
                 "avlength": ("Average printable-string length (characters)", "num"),
                 "printables": ("Total characters in printable strings", "num"),
                 "entropy": ("Character entropy of printable strings", "entropy")}
        if field in fixed:
            t, f = fixed[field]
            return "strings", t, f
        m = re.fullmatch(r"char_(\d{2})", field)
        if m:
            return "strings", f"Share of string characters that are {_char_name(int(m.group(1)))}", "pct"
        m = re.fullmatch(r"regex_(\d{2})_(.+)", field)
        if m:
            return "strings", _regex_title(int(m.group(1)), m.group(2)), "num"
    if group == "header":
        if field in EM_HEADER:
            t, f = EM_HEADER[field]
            return "headers", t, f
        if field.startswith("characteristic_") and field[15:] in EM_CHARACTERISTICS:
            return "headers", f"COFF flag: {EM_CHARACTERISTICS[field[15:]]}", "bool"
        if field.startswith("dllchar_") and field[8:] in DLLCHAR:
            return "headers", f"Mitigation flag: {DLLCHAR[field[8:]]}", "bool"
        if field.startswith("dos_") and field[4:] in EM_DOS:
            t, f = EM_DOS[field[4:]]
            return "headers", t, f
    if group == "section":
        if field in EM_SECTION:
            t, f, g = EM_SECTION[field]
            return g, t, f
        m = re.fullmatch(r"(size|vsize|entropy|props)_hash_(\d{2})", field)
        if m:
            kind = "props" if m.group(1) == "props" else "sec"
            t, f = _hashed(kind, int(m.group(2)), m.group(1), ctx, value)
            return ("entropy" if m.group(1) == "entropy" else "sections"), t, f
        m = re.fullmatch(r"entry_name_hash_(\d)", field)
        if m:
            t, f = _hashed("entry", int(m.group(1)), "", ctx, value)
            return "sections", t, f
    if group == "imports":
        if field == "n_functions":
            return "imports", "Number of imported functions", "num"
        if field == "n_libraries":
            return "imports", "Number of imported DLLs", "num"
        m = re.fullmatch(r"(library|function)_hash_(\d+)", field)
        if m:
            t, f = _hashed("lib" if m.group(1) == "library" else "fn", int(m.group(2)), "", ctx, value)
            return "imports", t, f
    if group == "exports":
        if field == "has_exports_128":
            return "exports", "Has exported functions (thrember stores 128 for any export table)", "flag"
        m = re.fullmatch(r"export_hash_(\d{3})", field)
        if m:
            t, f = _hashed("exp", int(m.group(1)), "", ctx, value)
            return "exports", t, f
    if group == "datadirectories":
        if field == "has_relocs":
            return "directories", "Has a parsed base-relocation table", "bool"
        if field == "has_dynamic_relocs":
            return "directories", "Has dynamic relocations (load configuration)", "bool"
        m = re.fullmatch(r"(.+)_(size|vaddr)", field)
        if m and m.group(1) in EM_DIRS:
            what, g = EM_DIRS[m.group(1)]
            if m.group(2) == "size":
                return g, f"Size of the {what}", "bytes"
            return g, f"Address (RVA) of the {what}", "hex"
    if group == "richheader":
        if field == "n_pairs":
            return "rich", "Rich header entries (build-tool records)", "num"
        m = re.fullmatch(r"pair_hash_(\d{2})", field)
        if m:
            t, f = _hashed("rich", int(m.group(1)), "", ctx, value)
            return "rich", t, f
    if group == "authenticode" and field in EM_AUTH:
        t, f = EM_AUTH[field]
        return "signature", t, f
    if group == "pefilewarnings":
        if field == "n_warnings":
            return "warnings", "Number of distinct pefile parser warnings", "num"
        m = re.fullmatch(r"warn_(\d{2})", field)
        if m:
            return "warnings", _warn_title(int(m.group(1))), "bool"
    return None


def describe(name: str, ctx: dict[str, Any], value: float | None = None) -> tuple[str, str, str]:
    """feature -> (group, plain title, value format). ctx resolves hashed slots back to this file's names; value (optional)
    lets hashed titles say when a slot is set but its names could not be resolved."""
    if name.startswith("em_"):
        r = _describe_em(name, ctx or {}, value)
        if r:
            return r
    if name in BN:
        t, fmt = BN[name]
        return "code", t, fmt
    if name.startswith(("cap6_", "hl6_")):
        return "code", f"Binary Ninja indicator {name}", "num"
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
        names = (ctx or {}).get("sections_by_bucket", {}).get(int(k)) or []
        who = ", ".join(names) if names else "a section name this file does not have"
        label = {"size": "Size on disk", "entropy": "Entropy", "vsize": "Size in memory"}[kind]
        return ("entropy" if kind == "entropy" else "sections"), f"{label} of section {who}", ("entropy" if kind == "entropy" else "bytes")
    if f.startswith("imp_bucket_"):
        toks = (ctx or {}).get("imports_by_bucket", {}).get(int(f[11:])) or []
        if toks:
            shown = ", ".join(t.split(":", 1)[1] for t in toks[:3]) + (" ..." if len(toks) > 3 else "")
            return "imports", f"Imports {shown}", "num"
        return "imports", "Absence of a group of commonly imported APIs (hashed import feature)", "num"
    if f.startswith("impdll_bucket_"):
        dlls = (ctx or {}).get("dlls_by_bucket", {}).get(int(f[14:])) or []
        return "imports", (f"Imports from {', '.join(dlls)}" if dlls else "Absence of a commonly imported DLL (hashed feature)"), "num"
    if f.startswith("exp_bucket_"):
        ex = (ctx or {}).get("exports_by_bucket", {}).get(int(f[11:])) or []
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


def _bytes(n: float) -> str:
    neg, n = n < 0, abs(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            s = f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
            return ("-" if neg else "") + s
        n /= 1024
    return str(n)


def fmt_value(v: float | None, fmt: str) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "n/a"
    if fmt == "bool":
        return "yes" if v else "no"
    if fmt == "flag":  # hashed or 128-valued presence: any non-zero value means present
        return "yes" if v else "no"
    if fmt in ("bytes", "logbytes"):
        return _bytes(math.expm1(v) if fmt == "logbytes" else v)
    if fmt == "absbytes":
        return _bytes(abs(v))
    if fmt in ("entropy", "absentropy"):
        return f"{abs(v) if fmt == 'absentropy' else v:.2f} bits/byte"
    if fmt == "absnum":
        v = abs(v)
        return f"{v:,.0f}" if float(v).is_integer() else f"{v:,.3f}"
    if fmt == "pct":
        return f"{v * 100:.2f}%" if v < 0.1 else f"{v * 100:.1f}%"
    if fmt == "ratio":
        return f"{v:.2f}x"
    if fmt == "hex":
        return f"0x{int(v):X}" if v >= 0 else f"-0x{int(-v):X}"
    if fmt == "byte":
        b = int(v)
        return f"0x{b:02X}" + (f" ('{chr(b)}')" if 0x20 < b < 0x7F else "")
    if fmt == "arch":
        return ARCH.get(int(v), f"0x{int(v):X}")
    if fmt == "subsystem":
        return SUBSYS.get(int(v), str(int(v)))
    if fmt == "em_machine":
        i = int(v)
        return EM_MACHINES[i] if 0 <= i < len(EM_MACHINES) else f"code {i}"
    if fmt == "em_subsystem":
        i = int(v)
        return EM_SUBSYSTEMS[i] if 0 <= i < len(EM_SUBSYSTEMS) else f"code {i}"
    if fmt == "time":
        if v <= 0:
            return "0 (not set)"
        try:
            return datetime.fromtimestamp(v, timezone.utc).strftime("%Y-%m-%d")
        except (OverflowError, OSError, ValueError):
            return f"{v:,.0f}"
    if fmt == "duration":
        d = v / 86400
        return f"{d:+,.0f} days" if abs(d) >= 1 else f"{v:+,.0f} s"
    return f"{v:,.0f}" if float(v).is_integer() else f"{v:,.3f}"


@lru_cache(maxsize=1)
def reference() -> dict[str, Any]:
    p = REFERENCE if REFERENCE.is_absolute() else ROOT / REFERENCE
    for cand in (p, REFERENCE):
        try:
            return json.loads(cand.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return {}


def strength(c: float) -> str:
    a = abs(c)
    return "strong" if a >= STRONG else ("moderate" if a >= MODERATE else "minor")


def _kind(name: str) -> str:
    """Value kind used for the 'typical' comparison: cat | hash | bool | num."""
    if name in ("em_general_is_pe", "em_header_coff_machine", "em_header_optional_subsystem") or name.startswith("em_general_start_byte_"):
        return "cat"
    if re.search(r"_hash_\d+$", name):
        return "hash"
    return "num"


def _typical(name: str, fmt: str, ref: dict[str, Any]) -> str | None:
    r = ref.get("features", {}).get(name)
    if not r:
        return None
    bmed, mmed, bnz, mnz = r
    pool = " Binary Ninja-covered" if name.startswith(("cap6_", "hl6_")) else ""
    kind = _kind(name)
    if kind == "cat":
        m = ref.get("modes", {}).get(name)
        if not m:
            return None
        return (f"most common in{pool} training files: benign {fmt_value(m[0], fmt)} ({m[2] * 100:.0f}%), "
                f"malware {fmt_value(m[1], fmt)} ({m[3] * 100:.0f}%)")
    if kind == "hash" or fmt in ("bool", "flag"):
        return f"non-zero in {bnz * 100:.0f}% of benign and {mnz * 100:.0f}% of malware{pool} training files"
    if bmed == 0 and mmed == 0:
        return f"non-zero in {bnz * 100:.0f}% of benign and {mnz * 100:.0f}% of malware{pool} training files"
    out = f"typical benign {fmt_value(bmed, fmt)}, typical malware {fmt_value(mmed, fmt)}"
    if (bmed == 0) != (mmed == 0):  # a zero median just means "usually absent"; say how often it is present
        out += f" (non-zero in {bnz * 100:.0f}% of benign and {mnz * 100:.0f}% of malware{pool} files)"
    return out


def reasons(contrib: list[tuple[str, float, float]], base: float, ctx: dict[str, Any], top_k: int = 12) -> dict[str, Any]:
    """contrib: [(feature, value, contribution_log_odds)] for every model feature. Returns groups + top reasons.

    For the V8 blend the contributions are EMBER2024's SHAP values (all 2568 features) plus, on files with Binary Ninja
    features, 0.3 x the Binary Ninja model's SHAP values, so base + sum == logit(final_probability) on the display scale.
    """
    ref = reference()
    groups: dict[str, float] = {}
    rows = []
    for name, value, c in contrib:
        c = float(c)
        if math.isnan(c):
            c = 0.0
        g, title, fmt = describe(name, ctx, value)
        groups[g] = groups.get(g, 0.0) + c
        rows.append((name, value, c, g, title, fmt))
    rows.sort(key=lambda r: -abs(r[2]))
    top = []
    for name, value, c, g, title, fmt in rows[:top_k]:
        missing = value is None or (isinstance(value, float) and math.isnan(value))
        top.append({"feature": name, "group": g, "title": title,
                    "value": "not available" if missing else fmt_value(value, fmt), "raw_value": None if missing else value,
                    "contribution": round(c, 4), "direction": "malicious" if c > 0 else "benign",
                    "strength": strength(c), "typical": _typical(name, fmt, ref),
                    "source": "binary_ninja" if name.startswith(("cap6_", "hl6_")) else ("ember2024" if name.startswith("em_") else "model")})
    gl = [{"group": g, "label": GROUPS[g][0], "contribution": round(v, 4)} for g, v in groups.items()]
    gl.sort(key=lambda x: -abs(x["contribution"]))
    raw = base + sum(r[2] for r in rows)
    em = (ctx or {}).get("em") or {}
    return {"base_log_odds": round(base, 4), "base_probability": round(_sig(base), 4),
            "final_probability": round(_sig(raw), 6), "groups": gl, "top": top,
            "hash_resolution": em.get("resolution", "none"),
            "bn_contribution": round(groups.get("code", 0.0), 4) if any(r[3] == "code" for r in rows) else None}


def _sig(x: float) -> float:
    return 1 / (1 + math.exp(-x)) if x >= 0 else math.exp(x) / (1 + math.exp(x))


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
# A file kind is marked as a model bias when benign files of that kind were flagged by EMBER2024 at the deployed
# threshold at least BIAS_RATIO times as often as benign pool files overall, with at least BIAS_MIN_BENIGN of them.
BIAS_RATIO, BIAS_MIN_BENIGN = 3.0, 20


def generic_title(sig: dict[str, Any]) -> str:
    """File-independent signal name for aggregate views (titles of some signals embed this file's numbers)."""
    return GENERIC_TITLES.get(sig["id"], sig["title"])


SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "positive": 4}


def class_note(pid: str) -> tuple[str, bool]:
    """(sentence about this file kind in the V8 training pool, whether it counts as a model bias)."""
    ref = reference()
    c = ref.get("classes", {}).get(pid)
    if not c or "benign_flagged_r1" not in c:
        return "", False
    b, m, bf = c["benign"], c["malicious"], c["benign_flagged_r1"]
    if b + m == 0:
        return "", False
    n_b = (ref.get("n") or {}).get("benign") or 0
    ops = (ref.get("r1_operating_points_pool_rates") or {}).get("fpr_0.01") or {}
    base = ops.get("benign_flagged", 0) / n_b if n_b else 0.01
    note = f" In the V8 training pool, {m} of {b + m} files of this kind were malware"
    if b:
        note += f"; EMBER2024 flagged {bf} of the {b} benign ones ({bf / b:.0%}) at the deployed threshold, against {base:.1%} of all benign pool files."
    else:
        note += "; there were no benign ones, so the pool says nothing about false positives for this kind."
    note += f" ({c.get('how', 'detection approximate')}.)" if "approximate" in c.get("how", "") else ""
    bias = b >= BIAS_MIN_BENIGN and base > 0 and bf / b >= BIAS_RATIO * base
    return note, bias


def _sig_signal(sig: dict[str, Any], embedded: bool = True) -> dict[str, Any]:
    st = sig.get("status", "Unknown")
    who = sig.get("signer") or "unknown signer"
    if st == "Valid":
        return {"id": "signed_valid", "severity": "positive", "title": f"Validly signed by {who}",
                "evidence": f"Authenticode status Valid; issued by {sig.get('issuer') or 'unknown CA'}"
                            + ("; timestamped" if sig.get("timestamped") else "")
                            + ("" if embedded else "; catalog-signed (no signature embedded in the file, so the model's "
                               "signature features read it as unsigned)"),
                "meaning": "The publisher's code-signing certificate checks out and the file has not changed since it was signed. "
                           "Strong evidence of origin, though stolen or abused certificates do occur. The model reads the "
                           "signature's structure but never checks its validity."}
    if st == "NotSigned":
        return {"id": "unsigned", "severity": "info", "title": "Not digitally signed",
                "evidence": "No Authenticode signature", "meaning": "There is no publisher signature to confirm who made the file. "
                "Many legitimate tools are unsigned; most commercial software is signed."}
    if st in ("HashMismatch", "NotTrusted", "UnknownError"):
        return {"id": "signature_bad", "severity": "high" if st == "HashMismatch" else "medium",
                "title": f"Signature present but {st}", "evidence": f"Authenticode status {st}; signer {who}",
                "meaning": "A signature exists but does not verify: the file was modified after signing (HashMismatch) "
                           "or the certificate is not trusted. Treat the claimed publisher as unconfirmed. The model cannot "
                           "tell a broken signature from a valid one."}
    return {"id": "signature_unknown", "severity": "info", "title": "Signature status unknown",
            "evidence": f"Authenticode status {st}", "meaning": "The signature check could not be completed."}


def signals(pe: dict[str, Any], raw: bytes) -> list[dict[str, Any]]:
    """File-level context signals. pe = scanner.pe_details() output."""
    out: list[dict[str, Any]] = []
    if pe.get("error"):
        return [{"id": "parse_error", "severity": "medium", "title": "PE structure could not be fully parsed",
                 "evidence": pe["error"], "meaning": "Malformed headers are common in malware and in deliberately broken samples."}]
    sec_names = {s["name"] for s in pe.get("sections", [])}
    out.append(_sig_signal(pe.get("signature") or {}, pe.get("embedded_signature", True)))

    for pid, title, det, meaning in PACKERS:
        try:
            hit = det(sec_names, raw)
        except Exception:
            hit = False
        if hit:
            note, bias = class_note(pid)
            out.append({"id": f"format_{pid}", "severity": "medium" if pid in ("themida", "vmprotect") else "low",
                        "title": title, "evidence": f"sections: {', '.join(sorted(sec_names)) or 'none'}", "meaning": meaning + note,
                        "model_bias": bias})

    if pe.get("dotnet"):
        note, bias = class_note("dotnet")
        out.append({"id": "format_dotnet", "severity": "info", "title": ".NET assembly",
                    "evidence": ".NET (CLR) header present",
                    "meaning": "Managed .NET code. Most logic is IL bytecode, which native-PE features and native-code "
                               "disassembly describe only coarsely." + note, "model_bias": bias})

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
                               "Tiny legitimate utilities and .NET programs can also look like this."})
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
                    "meaning": "Installers, self-extracting archives and droppers carry their payload here. When it is "
                               "compressed, static features cannot see what is inside."})
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
                    "reproducible-build tools also zero them or replace them with a hash."})
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

ENGINE_NAMES = {"v8_blend": "V8 blend (EMBER2024 + Binary Ninja)", "ember2024": "EMBER2024", "pe_v3": "pe_v3 model",
                "pe_v1s": "pe_v1s model"}


def _f(x: Any) -> float | None:
    try:
        v = float(x)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(v) else v


def _lc(label: str) -> str:
    """Lower-case a group label for use mid-sentence, keeping acronyms and proper names ("APIs", "PE", "Binary Ninja")."""
    words = label.split(" ")
    out = [w if (sum(c.isupper() for c in w) > 1 or w.strip("()") in ("Binary", "Ninja", "Authenticode", "Rich")) else w.lower() for w in words]
    return " ".join(out)


DISAGREE_LABELS = {  # (blend flags, kind) -> assessment label when the two engines disagree
    (True, "bn"): "Flagged by code analysis only - review", (True, "either"): "Flagged by code analysis only - review",
    (True, "offset"): "Flagged by the blend threshold offset - borderline, review",
    (True, "both"): "Flagged by code analysis plus threshold offset - review",
    (True, "unknown"): "Flagged by the blend only - review",
    (False, "bn"): "Cleared by code analysis - review", (False, "either"): "Cleared by code analysis - review",
    (False, "offset"): "Cleared by the blend threshold offset - borderline, review",
    (False, "both"): "Cleared by code analysis plus threshold offset - review",
    (False, "unknown"): "Cleared by the blend only - review",
}
_DECISIVE = {"bn": "The Binary Ninja term alone was enough to cross the threshold.",
             "either": "Either one alone would have been enough to cross the threshold.",
             "both": "Neither was enough on its own; together they crossed the threshold."}
_CAUSE = {"bn": "the Binary Ninja term", "either": "the Binary Ninja term", "offset": "the blend's threshold offset",
          "both": "the Binary Ninja term together with the threshold offset", "unknown": "the blend's other terms"}


def disagreement(report: dict[str, Any]) -> dict[str, Any] | None:
    """Why the V8 blend and EMBER2024 decide differently on this file, from the report's own v8_blend numbers.

    On covered files the blend margin m = logit(R1) + w*logit(BN) - t_blend splits into EMBER2024's own margin
    r1_margin = r1_logit - display_shift (display_shift = logit(thr_R1)), the Binary Ninja term w*bn_logit, and a fixed
    threshold offset display_shift - t_blend (+0.142 log-odds with the frozen values). kind says which term was decisive:
    bn (Binary Ninja term alone suffices), offset (offset alone suffices), both (neither alone, together yes), either
    (each alone suffices), unknown (numbers missing or inconsistent). None when the engines agree.
    """
    engines = report.get("engines") or []
    b = next((e for e in engines if e.get("name") == "v8_blend"), None)
    r1 = next((e for e in engines if e.get("name") == "ember2024"), None)
    if not b or not r1 or bool(b.get("flagged")) == bool(r1.get("flagged")):
        return None
    up = bool(b.get("flagged"))
    out: dict[str, Any] = {"blend_flags": up, "kind": "unknown", "r1_margin": None, "bn_term": None, "offset": None,
                           "blend_margin": _f(b.get("blend_margin"))}
    vals = [_f(b.get(k)) for k in ("r1_logit", "bn_logit", "w", "t_blend", "display_shift", "blend_margin")]
    if b.get("coverage") == "covered" and None not in vals:
        r1l, bnl, w, tb, shift, m = vals
        r1m, bt, off = r1l - shift, w * bnl, shift - tb
        if abs(r1m + bt + off - m) <= 1e-3 and (m >= 0) == up and (r1m >= 0) == bool(r1.get("flagged")):
            cross = (lambda x: x >= 0) if up else (lambda x: x < 0)  # noqa: E731
            bn_alone, off_alone = cross(r1m + bt), cross(r1m + off)
            kind = "either" if bn_alone and off_alone else ("bn" if bn_alone else ("offset" if off_alone else "both"))
            out.update(kind=kind, r1_margin=r1m, bn_term=bt, offset=off)
            text = (f"EMBER2024 alone is {r1m:+.3f} log-odds from its threshold, so on its own it "
                    f"{'does not flag' if up else 'flags'} the file; the blend adds the Binary Ninja term {bt:+.3f} "
                    f"({w:g} x {bnl:+.3f}) and a fixed threshold offset of {off:+.3f}, for a margin of {m:+.3f}. ")
            if kind == "offset":
                helps = bt > 0 if up else bt < 0
                text += ("The threshold offset alone was enough to cross the threshold; the Binary Ninja term "
                         + ("helped but was not enough on its own." if helps else ("added nothing." if bt == 0 else "pushed the other way.")))
            else:
                text += _DECISIVE[kind]
            out["text"] = text
    if out["kind"] == "unknown":
        out["text"] = ("The report does not carry consistent blend numbers, so it cannot say whether the Binary Ninja term "
                       "or the blend's threshold offset moved the decision.")
    out["label"] = DISAGREE_LABELS[(up, out["kind"])]
    out["cause"] = _CAUSE[out["kind"]]
    return out


def assessment(report: dict[str, Any], sigs: list[dict[str, Any]]) -> dict[str, Any]:
    """Heuristic analyst note that correlates the model's reasons with the context signals. Never changes the verdict."""
    verdict, p = report.get("verdict"), _f(report.get("probability"))
    engines = report.get("engines") or []
    rec = next((e for e in engines if e.get("recommended")), None) or {}
    r1e = next((e for e in engines if e.get("name") == "ember2024"), None)
    thr = _f(rec.get("threshold"))
    exp = report.get("explanation") or {}
    dpath = report.get("decision_path") or {}
    ids = {s["id"] for s in sigs}
    signed = "signed_valid" in ids
    signer = next((s["title"].replace("Validly signed by ", "") for s in sigs if s["id"] == "signed_valid"), "")
    biased = [s for s in sigs if s.get("model_bias")]
    strong_bad = [s for s in sigs if s["severity"] in ("high", "medium") and not s["id"].startswith("format_")]
    groups = exp.get("groups", [])
    top_up = [r for r in exp.get("top", []) if r["contribution"] > 0][:3]
    top_down = [r for r in exp.get("top", []) if r["contribution"] < 0][:3]
    note = "Heuristic analyst note generated from the model's reasons and file context. It does not change the model verdict."

    if p is None:
        return {"label": "Not scored", "tone": "neutral", "summary": "The file could not be scored; see the error on the Engines tab.",
                "paragraphs": [], "points_for": [], "points_against": [], "note": note}

    model = ENGINE_NAMES.get(rec.get("name"), rec.get("name") or "model")
    flagged = verdict == "malicious"
    lines = [f"The {model} scored this file {p:.4f}" + (f" against a threshold of {thr:.4f}" if thr is not None else "")
             + f" ({'flagged as malicious' if flagged else 'below the threshold, so not flagged'})."]
    path = dpath.get("path")
    r1_score, r1_flag = (_f(r1e.get("probability")), bool(r1e.get("flagged"))) if r1e else (None, None)
    dis = disagreement(report)
    disagree = r1e is not None and r1_flag != flagged
    if path == "blend":
        bn = _f(rec.get("bn_score"))
        lines.append("Binary Ninja code features were available, so the verdict combines EMBER2024"
                     + (f" ({r1_score:.4f})" if r1_score is not None else "") + " with the Binary Ninja model"
                     + (f" ({bn:.4f})" if bn is not None else "") + " at weight 0.3. The score is on a rescaled display "
                     "scale, not a calibrated probability.")
    elif path == "r1_fallback":
        why = (dpath.get("note") or dpath.get("reason") or "").strip().rstrip(".")
        lines.append("Binary Ninja features were not available" + (f" ({why})" if why else "")
                     + ", so this is EMBER2024's own verdict and the score is its probability.")
    if disagree:
        lines.append(f"The two engines disagree: EMBER2024 alone would {'flag' if r1_flag else 'not flag'} this file"
                     + (f" ({r1_score:.4f})" if r1_score is not None else "") + ". "
                     + (dis["text"] if dis else ""))

    up = [g for g in groups if g["contribution"] >= 0.1][:2]
    down = [g for g in groups if g["contribution"] <= -0.1][:2]
    fmt_g = lambda gs: " and ".join(f"{_lc(g['label'])} ({g['contribution']:+.2f})" for g in gs)  # noqa: E731
    lead_g, other_g = (up, down) if flagged else (down, up)
    if lead_g:
        lines.append(f"Most of the pull towards {'malicious' if flagged else 'benign'} came from {fmt_g(lead_g)}"
                     + (f", while {fmt_g(other_g)} pulled the other way" if other_g else "") + " (log-odds).")
    lead = top_up if flagged else top_down
    if lead:
        lines.append(f"The strongest individual reasons towards {'malicious' if flagged else 'benign'} were: "
                     + "; ".join(f"{r['title'].rstrip('. ')} = {r['value']}" for r in lead) + ".")

    for_mal, against = [], []
    for s in strong_bad:
        for_mal.append(f"{s['title']}: {s['evidence']}")
    if signed:
        against.append(f"Valid Authenticode signature from {signer} (the model does not check signature validity).")
    for s in biased:
        against.append(f"{s['title']}: benign files of this kind were flagged unusually often in the training pool (see its signal).")
    if "no_version" not in ids:
        against.append("Has version information (product/company metadata).")
    if "signature_bad" in ids:
        for_mal.append("Signature exists but does not verify, so the claimed publisher is unconfirmed.")
    if disagree:
        (for_mal if flagged else against).append(
            f"Only the blend {'flags' if flagged else 'clears'} this file; EMBER2024 on its own {'does not' if flagged else 'does'}.")

    ops = reference().get("r1_operating_points") or {}
    t5 = _f(ops.get("fpr_0.05"))
    if flagged:
        if biased and signed:
            label, tone = "Likely false positive - review", "warn"
            lines.append(f"Correlation: the file is a {biased[0]['title'].split(' /')[0]}, a kind whose benign files were flagged "
                         f"unusually often in the training pool, and it is validly signed by {signer}.")
        elif biased:
            label, tone = "Possible false positive - file format", "warn"
            lines.append("Correlation: benign files of this format were flagged unusually often in the training pool. Static "
                         "features describe the wrapper more than its payload, so confirm the source before trusting or blocking it.")
        elif strong_bad:
            label, tone = "Consistent with malware indicators", "bad"
            lines.append("Correlation: the verdict is backed by independent structural or capability indicators listed below.")
        elif disagree:
            label, tone = (dis["label"] if dis else DISAGREE_LABELS[(True, "unknown")]), "warn"
            lines.append("Correlation: no independent structural indicator was found, and EMBER2024 alone does not flag the file.")
        elif signed:
            label, tone = "Flagged, but signed - review", "warn"
            lines.append("Correlation: no corroborating structural indicator was found and the file carries a valid signature. "
                         "Verify the signer is the expected publisher.")
        else:
            label, tone = "Flagged by model - unverified", "bad"
            lines.append("Correlation: no independent indicator confirms or contradicts the model; treat as suspicious until reviewed.")
    else:
        if disagree:
            label, tone = (dis["label"] if dis else DISAGREE_LABELS[(False, "unknown")]), "warn"
            lines.append(f"Correlation: EMBER2024 alone flags this file; {(dis or {}).get('cause', _CAUSE['unknown'])} took the "
                         "blend under the threshold.")
        elif t5 is not None and thr is not None and t5 <= p < thr:
            label, tone = "Borderline - below threshold", "warn"
            lines.append(f"The score is under the threshold (set for about 1% false positives on the training pool's benign "
                         f"files) but above {t5:.4f}, EMBER2024's cut-off for 5% false positives.")
        elif [s for s in strong_bad if s["severity"] == "high"] and not signed:
            label, tone = "Not flagged, but indicators present", "warn"
            lines.append("Correlation: the model is not concerned, but high-severity capability indicators are present; review them.")
        else:
            label, tone = "No significant concern", "good"
    return {"label": label, "tone": tone, "summary": " ".join(lines), "paragraphs": lines, "points_for": for_mal,
            "points_against": against, "engines_disagree": bool(disagree), "disagreement": dis if disagree else None,
            "decision_path": path, "note": note}


def _glossary() -> dict[str, str]:
    ref = reference()
    n = ref.get("n") or {}
    nbn = {k: v.get("benign", 0) + v.get("malicious", 0) for k, v in (ref.get("n_bn") or {}).items()}
    ops = ref.get("r1_operating_points") or {}
    t1, t5 = ops.get("fpr_0.01"), ops.get("fpr_0.05")
    pool = (f"the {n['benign']:,} benign and {n['malicious']:,} malware files of the V8 training pool" if n
            else "the V8 training pool")
    bnpool = (f" (Binary Ninja features: the {nbn['cap6']:,} pool files with usable disassembly features and the {nbn['hl6']:,} "
              "with usable decompiler features)" if "cap6" in nbn and "hl6" in nbn else "")
    return {
        "Model score": "Display score (0-1) of the V8 blend. Without Binary Ninja features it is EMBER2024's probability; with "
                       "them it is sigmoid(blend margin + logit(threshold)), a rescaling so one threshold fits every file. It is "
                       "not a calibrated probability on those files.",
        "Threshold": ("Cut-off for a malicious verdict" + (f": {t1:.4f}" if t1 else "") + ", EMBER2024's score at a 1% "
                      "false-positive rate on the benign files of the V8 training pool. The same value applies to the blend's "
                      "display score."),
        "Risk band": ("High = at or above the threshold. Borderline = below it but at or above " + (f"{t5:.4f}, " if t5 else "")
                      + "EMBER2024's cut-off for a 5% false-positive rate on the same benign files. Low = below that."),
        "Decision path": "blend: Binary Ninja features were available and the verdict combines EMBER2024 with the Binary Ninja "
                         "model (weight 0.3). r1_fallback: they were not (Binary Ninja off, busy with another scan, unreachable, "
                         "timed out or analysis unusable), so the verdict is EMBER2024's own.",
        "EMBER2024": "Pretrained LightGBM model over 2,568 static EMBER v3 features (thrember), trained by its authors on their "
                     "own corpus. Shown as a second engine; on blend-path files it can disagree with the blend.",
        "Hashed slot": "Imports, exports, section names and Rich-header entries are hashed into a fixed number of slots. Several "
                       "names can share a slot, and for some features opposite signs can cancel; titles name this file's entries "
                       "in the slot when they could be resolved.",
        "Contribution (log-odds)": "SHAP value: how much one feature moved the score, in log-odds. EMBER2024's values come from its "
                                   "booster; Binary Ninja values are 0.3 x that model's SHAP. +0.7 roughly doubles the odds of "
                                   "'malicious'; -0.7 halves them. Base value plus all contributions equals the logit (log-odds) of the "
                                   "final score.",
        "Strength": f"strong >= {STRONG}, moderate >= {MODERATE}, minor < {MODERATE} (absolute log-odds).",
        "Typical benign / malware": f"Median value of that feature among {pool}{bnpool}. EMBER2024 itself was trained on other data.",
        "Disposition": "Analyst decision recorded on the dashboard (confirmed malicious, false positive, benign). It never changes the model output.",
    }


GLOSSARY_EXTRA = _glossary()
