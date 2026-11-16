"""Static scan of one quarantined file: V3.2 engines + SHAP + PE details. Nothing is executed."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import pefile

from src.common.winsig import signature_status
from src.v3 import score

MODEL_TAG = "v3.2"
CALIBRATION = Path("artifacts/deploy/calibration_temporal_benign.json")
_lock = threading.Lock()
_bundle: dict[str, Any] | None = None


def bundle() -> dict[str, Any]:
    global _bundle
    with _lock:
        if _bundle is None:
            _bundle = score.load_bundle(MODEL_TAG, verify=False)
        return _bundle


def thresholds() -> dict[str, dict[str, Any]]:
    """D1: pe_v3 uses the deploy-calibrated threshold; pe_v1s keeps its frozen one."""
    b = bundle()
    cal = json.loads(CALIBRATION.read_text(encoding="utf-8"))
    return {
        "pe_v3": {"threshold": float(cal["recommended_threshold"]), "source": "deploy_calibrated",
                  "frozen": float(b["pe_v3"]["threshold"])},
        "pe_v1s": {"threshold": float(b["pe_v1s"]["threshold"]), "source": "frozen",
                   "frozen": float(b["pe_v1s"]["threshold"])},
    }


def hashes(raw: bytes) -> dict[str, str]:
    return {"md5": hashlib.md5(raw).hexdigest(), "sha1": hashlib.sha1(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest()}


def is_pe(raw: bytes) -> bool:
    return raw[:2] == b"MZ"


def engines(path: Path, top_k: int = 15) -> dict[str, Any] | None:
    """None when the file is not a parseable PE."""
    row = score._feature_row(path)
    if row is None:
        return None
    b, thr = bundle(), thresholds()
    s = score.score_row(row, b)
    out = []
    for name in ("pe_v3", "pe_v1s"):
        p = float(s[f"{name}_probability"])
        t = thr[name]["threshold"]
        out.append({"name": name, "model_tag": MODEL_TAG, "probability": p, "threshold": t,
                    "threshold_source": thr[name]["source"], "frozen_threshold": thr[name]["frozen"],
                    "flagged": p >= t, "recommended": name == "pe_v3"})
    spec = b["pe_v3"]
    frame = pd.DataFrame([row])
    cols = [c for c in spec["cols"] if c in frame.columns]
    contrib = spec["model"].predict(frame[cols], pred_contrib=True)[0][:-1]
    top = sorted(zip(cols, contrib), key=lambda t: -abs(t[1]))[:top_k]
    return {"engines": out, "top_features": [{"feature": c, "contribution": float(v)} for c, v in top]}


def _ts(v: int) -> str:
    try:
        return datetime.fromtimestamp(v, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return str(v)


def pe_details(path: Path, raw: bytes) -> dict[str, Any]:
    try:
        pe = pefile.PE(data=raw, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY[k] for k in (
            "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT", "IMAGE_DIRECTORY_ENTRY_RESOURCE")])
    except Exception as e:  # hostile input: any parser failure is just "no details"
        return {"error": f"pefile: {type(e).__name__}"}
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    sections = []
    for s in pe.sections:
        ch = s.Characteristics
        r, w, x = bool(ch & 0x40000000), bool(ch & 0x80000000), bool(ch & 0x20000000)
        sections.append({"name": s.Name.rstrip(b"\x00").decode("latin-1"), "virtual_address": hex(s.VirtualAddress),
                         "virtual_size": s.Misc_VirtualSize, "raw_size": s.SizeOfRawData,
                         "entropy": round(s.get_entropy(), 3), "flags": ("r" if r else "-") + ("w" if w else "-") + ("x" if x else "-"),
                         "rwx": r and w and x})
    imports: dict[str, list[str]] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:200]:
        dll = entry.dll.decode("latin-1", "replace").lower()
        imports[dll] = [(i.name.decode("latin-1", "replace") if i.name else f"ord_{i.ordinal}") for i in entry.imports[:500]]
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exports = [(e.name.decode("latin-1", "replace") if e.name else f"ord_{e.ordinal}") for e in pe.DIRECTORY_ENTRY_EXPORT.symbols[:500]]
    resources = len(getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []) or [])
    overlay_off = pe.get_overlay_data_start_offset()
    try:
        imphash = pe.get_imphash()
    except Exception:
        imphash = ""
    return {
        "machine": pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine)),
        "format": "PE32+" if oh.Magic == 0x20B else "PE32",
        "is_dll": bool(fh.Characteristics & 0x2000),
        "subsystem": pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem)),
        "timestamp": _ts(fh.TimeDateStamp),
        "entry_point": hex(oh.AddressOfEntryPoint),
        "image_base": hex(oh.ImageBase),
        "sections": sections, "imports": imports, "exports": exports,
        "resource_types": resources,
        "overlay_size": (len(raw) - overlay_off) if overlay_off else 0,
        "imphash": imphash,
        "signature": signature_status(str(path)),
    }


def scan(path: Path) -> dict[str, Any]:
    """Full report body for a quarantined file. Raises nothing; errors go into the dict."""
    t0 = time.perf_counter()
    raw = path.read_bytes()
    eng = engines(path)
    report: dict[str, Any] = {"pe": pe_details(path, raw)}
    if eng is None:
        report.update(verdict="error", error="pe_parse_failed", engines=[], top_features=[], flag_count=0, engine_count=0)
    else:
        flagged = [e for e in eng["engines"] if e["flagged"]]
        rec = next(e for e in eng["engines"] if e["recommended"])
        report.update(eng, verdict="malicious" if rec["flagged"] else "benign",
                      flag_count=len(flagged), engine_count=len(eng["engines"]), probability=rec["probability"])
    report["scan_ms"] = round((time.perf_counter() - t0) * 1000)
    return report


if __name__ == "__main__":
    import sys
    print(json.dumps(scan(Path(sys.argv[1])), indent=2, default=str))
