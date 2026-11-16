"""Model-independent PE strata, computed with pefile identically for benign and malicious files.

primary  ("ordinary"): native (no CLR header), no packer section names, max section entropy < 7.2,
                       and at least 20 imported functions.
secondary ("packed"):  packer section names, 8 or fewer imports, or max section entropy >= 7.2.
dotnet:                CLR header present (Binary Ninja does not analyze IL).
other:                 remaining native files (9-19 imports and normal entropy).
"""

from __future__ import annotations

from pathlib import Path

import pefile

PACKER_SECTIONS = ("upx", ".aspack", ".adata", "mpress", ".themida", ".vmp", ".enigma", ".petite", ".nsp", "pec2", ".packed",
                   ".mew", "fsg", ".yp", ".taz", ".winlice", ".boom", ".ccg", ".perplex")
ORDINARY_MIN_IMPORTS = 20
MINIMAL_IMPORTS = 8
HIGH_ENTROPY = 7.2


def traits(path: str | Path) -> dict:
    t = {"pe_ok": False, "dotnet": False, "packer_section": False, "upx": False, "n_imports": -1, "max_entropy": 0.0}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        return t
    try:
        t["pe_ok"] = True
        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        t["dotnet"] = len(dirs) > 14 and dirs[14].VirtualAddress != 0
        names = [s.Name.rstrip(b"\x00").decode("latin-1", "ignore").lower() for s in pe.sections]
        t["upx"] = any(n.startswith("upx") for n in names)
        t["packer_section"] = any(n.startswith(p) for n in names for p in PACKER_SECTIONS)
        t["n_imports"] = sum(len(e.imports) for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
        t["max_entropy"] = round(max((s.get_entropy() for s in pe.sections), default=0.0), 3)
    finally:
        pe.close()
    return t


def stratum(t: dict) -> str:
    if not t.get("pe_ok"):
        return "invalid"
    if t["dotnet"]:
        return "dotnet"
    if t["packer_section"] or 0 <= t["n_imports"] <= MINIMAL_IMPORTS or t["max_entropy"] >= HIGH_ENTROPY:
        return "packed"
    if t["n_imports"] >= ORDINARY_MIN_IMPORTS:
        return "ordinary"
    return "other"
