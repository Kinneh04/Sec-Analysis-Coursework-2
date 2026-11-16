from __future__ import annotations

import math
import re
import struct
from pathlib import Path
from typing import Any

import pefile

PE_MAGIC = b"MZ"


def is_pe_file(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            head = f.read(2)
        return head == PE_MAGIC
    except OSError:
        return False


def pe_inventory_fields(path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {
        "is_pe": False,
        "machine": None,
        "is_dll": None,
        "subsystem": None,
        "inventory_status": "ok",
    }
    if not is_pe_file(path):
        out["inventory_status"] = "not_pe"
        return out
    try:
        pe = pefile.PE(str(path), fast_load=True)
        out["is_pe"] = True
        out["machine"] = hex(pe.FILE_HEADER.Machine)
        out["is_dll"] = bool(pe.FILE_HEADER.IMAGE_FILE_DLL)
        out["subsystem"] = int(pe.OPTIONAL_HEADER.Subsystem)
        pe.close()
    except pefile.PEFormatError:
        out["inventory_status"] = "pe_parse_error"
    except Exception as e:
        out["inventory_status"] = f"error:{type(e).__name__}"
    return out


def section_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def read_strings_count(data: bytes, min_len: int = 5) -> int:
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return len(pat.findall(data))


def malware_path(corpus: Path, rel_path: str) -> Path:
    """Map analysis.csv rel_path to on-disk *.malware filename."""
    parts = rel_path.replace("\\", "/").split("/")
    name = parts[-1]
    if "." not in name:
        suffix = ""
    else:
        base, ext = name.rsplit(".", 1)
        name = f"{base}.{ext}"
    batch = "/".join(parts[:-1])
    candidate = corpus / batch / f"{name}.malware"
    if candidate.exists():
        return candidate
    return corpus / rel_path.replace("\\", "/")


def imphash_buckets(imports: list[str], dim: int = 256) -> list[int]:
    counts = [0] * dim
    for imp in imports:
        h = hash(imp.lower()) % dim
        counts[h] += 1
    return counts
