"""Static unpacking for packers whose format can be reversed without running the sample.

Only UPX is supported: `upx -d` decompresses the packed sections from the file format itself and
never executes sample code. Packers that need emulation or execution to unpack are left packed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pefile

UPX_EXE = Path("tools/upx/upx-4.2.4-win64/upx.exe")
UNPACK_DIR = Path("artifacts/v6/unpacked")


def is_upx(path: Path) -> bool:
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return False
    names = [s.Name.rstrip(b"\x00").decode("latin-1", "ignore") for s in pe.sections]
    pe.close()
    return any(n.upper().startswith("UPX") for n in names)


def image_end(path: Path) -> int | None:
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return None
    end = max((s.PointerToRawData + s.SizeOfRawData for s in pe.sections), default=0)
    end = max(end, pe.OPTIONAL_HEADER.SizeOfHeaders)
    pe.close()
    return end


def strip_overlay(path: Path, sha256: str, max_bytes: int) -> tuple[Path, str]:
    """For files over max_bytes, write the PE image without its overlay (file-inflation padding)."""
    if path.stat().st_size <= max_bytes:
        return path, "none"
    end = image_end(path)
    if end is None or end <= 0 or end > max_bytes:
        return path, "too_large"
    UNPACK_DIR.mkdir(parents=True, exist_ok=True)
    out = UNPACK_DIR / f"{sha256}.img"
    if not out.is_file():
        with open(path, "rb") as src:
            out.write_bytes(src.read(end))
    return out, "overlay_stripped"


def prepare(path: Path, sha256: str, max_bytes: int) -> tuple[Path, list[str]]:
    """Static normalization before analysis: overlay stripping for inflated files, then UPX unpacking."""
    target, s1 = strip_overlay(path, sha256, max_bytes)
    if s1 == "too_large":
        return path, [s1]
    target, s2 = unpack(target, sha256)
    return target, [s for s in (s1, s2) if s != "none"]


def unpack(path: Path, sha256: str) -> tuple[Path, str]:
    """Return (path to analyze, unpack status). Status: none, upx, upx_failed."""
    if not is_upx(path):
        return path, "none"
    UNPACK_DIR.mkdir(parents=True, exist_ok=True)
    out = UNPACK_DIR / f"{sha256}.bin"
    if out.is_file():
        return out, "upx"
    try:
        r = subprocess.run([str(UPX_EXE), "-d", "-q", "-o", str(out), str(path)], capture_output=True, timeout=60)
    except subprocess.TimeoutExpired:
        return path, "upx_failed"
    if r.returncode != 0 or not out.is_file():
        out.unlink(missing_ok=True)
        return path, "upx_failed"
    return out, "upx"
