"""Static scan of one quarantined file: V8 blend + EMBER2024 engines, SHAP explanation, PE details and context signals.
Nothing is executed. Scoring lives in src/v8/deploy.py; Binary Ninja (when reachable) in src/v8/bn_live.py."""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pefile

from src.common.winsig import signature_info
from src.v8 import deploy
from src.webscan import explain

MODEL_TAG = deploy.MODEL_TAG  # "v8"
REPORT_VERSION = 5  # 5: V8 blend + EMBER2024 engines (4 and older: V3.2)
ENGINE_BLEND, ENGINE_R1 = deploy.ENGINE_BLEND, deploy.ENGINE_R1  # "v8_blend", "ember2024"
SCALE_NOTE = ("Display score = sigmoid(blend margin + logit(thr_R1)): a monotone rescaling so one threshold fits every file; "
              "equals EMBER2024's raw score when Binary Ninja features are unavailable. Not a calibrated probability.")
_lock = threading.Lock()
_bundle: dict[str, Any] | None = None
_URL = re.compile(rb"https?://[\x21-\x7e]{4,200}")
_URL_NOISE = ("digicert.com", "verisign.com", "symcb.com", "symcd.com", "globalsign", "sectigo.com", "comodoca", "usertrust.com",
              "microsoft.com/pki", "thawte", "entrust", "ocsp.", "crl.", "schemas.microsoft.com", "www.w3.org", "nsis.sf.net",
              "nsis.sourceforge", "ns.adobe.com", "certum", "godaddy.com/repository", "letsencrypt")


def bundle() -> dict[str, Any]:
    """Frozen V8 bundle (candidate.pkl, R1 threshold, EMBER2024 booster). Downloads EMBER2024_PE.model on first use."""
    global _bundle
    with _lock:
        if _bundle is None:
            _bundle = deploy.load_bundle(verify=True)
        return _bundle


def thresholds() -> dict[str, dict[str, Any]]:
    """Both engines use the frozen V8 thr_R1 (0.31491...). For v8_blend it applies on the display scale (see SCALE_NOTE)."""
    t = float(bundle()["thr_r1"])
    return {
        ENGINE_BLEND: {"threshold": t, "source": "frozen", "frozen": t, "scale": "display"},
        ENGINE_R1: {"threshold": t, "source": "frozen", "frozen": t, "scale": "probability"},
    }


def freeze_status() -> dict[str, Any]:
    """Deployed V8 files that differ from artifacts/v8/freeze/freeze_manifest.json (EOL-only code changes accepted)."""
    bad = deploy.verify_freeze()
    return {"bad": bad, "models_ok": not any("/models/" in b for b in bad)}


def hashes(raw: bytes) -> dict[str, str]:
    return {"md5": hashlib.md5(raw).hexdigest(), "sha1": hashlib.sha1(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest()}


def is_pe(raw: bytes) -> bool:
    return raw[:2] == b"MZ"


def engines(path: Path, pe: dict[str, Any] | None = None, top_k: int = 12, raw: bytes | None = None,
            use_bn: bool | None = None) -> dict[str, Any] | None:
    """Engine results, or {"error": reason} when the file could not be scored: "pe_parse_failed" (thrember's pefile parse
    failed, not a PE) or "ember_failed:<Type>: <message>" (feature extraction raised)."""
    b, thr = bundle(), thresholds()
    s = deploy.score_file(path, b, raw=raw, use_bn=use_bn, contributions=True)
    if "error" in s:
        return {"error": s["error"]}
    bn = s["bn"]
    blend = {"name": ENGINE_BLEND, "model_tag": MODEL_TAG, "probability": s["probability"], "threshold": thr[ENGINE_BLEND]["threshold"],
             "threshold_source": thr[ENGINE_BLEND]["source"], "frozen_threshold": thr[ENGINE_BLEND]["frozen"],
             "flagged": s["decision"], "recommended": True,
             "coverage": "covered" if s["covered"] else "uncovered", "decision_path": s["decision_path"],
             "fallback_reason": None if s["covered"] else bn["reason"], "blend_margin": s["blend_margin"],
             "r1_score": s["r1_score"], "r1_logit": s["r1_logit"], "bn_score": s["bn_score"], "bn_logit": s["bn_logit"],
             "w": s["w"], "t_blend": s["t_blend"], "display_shift": s["display_shift"], "scale_note": SCALE_NOTE}
    r1 = {"name": ENGINE_R1, "model_tag": "EMBER2024_PE", "probability": s["r1_score"], "threshold": thr[ENGINE_R1]["threshold"],
          "threshold_source": thr[ENGINE_R1]["source"], "frozen_threshold": thr[ENGINE_R1]["frozen"],
          "flagged": s["r1_score"] >= thr[ENGINE_R1]["threshold"], "recommended": False,
          "coverage": "n/a", "r1_score": s["r1_score"]}
    pe = pe or {}
    ctx = explain.build_context([x["name"] for x in pe.get("sections", [])], pe.get("imports", {}), pe.get("exports", []), raw=raw)
    # Contributions are additive log-odds on the display scale: base + sum == logit(probability) of v8_blend.
    exp = explain.reasons(s["contrib"], s["contrib_base"], ctx, top_k)
    exp["base_parts"] = s["contrib_parts"]
    path_note = {"path": s["decision_path"], "reason": bn["reason"], "note": bn["note"]}
    bn_out = {k: bn[k] for k in ("covered", "reason", "note", "cap6_status", "hl6_status", "seconds", "url", "mode_enforced", "prep", "cached")}
    return {"engines": [blend, r1], "explanation": exp, "decision_path": path_note, "bn": bn_out, "timings_ms": s["timings_ms"],
            "top_features": [{"feature": r["feature"], "contribution": r["contribution"]} for r in exp["top"]]}


def _ts(v: int) -> str:
    try:
        return datetime.fromtimestamp(v, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return str(v)


def _version_info(pe: pefile.PE) -> dict[str, str]:
    out: dict[str, str] = {}
    for fi in getattr(pe, "FileInfo", None) or []:
        for entry in fi if isinstance(fi, list) else [fi]:
            for st in getattr(entry, "StringTable", []) or []:
                for k, v in st.entries.items():
                    key = k.decode("latin-1", "replace") if isinstance(k, bytes) else str(k)
                    val = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
                    if key in ("CompanyName", "ProductName", "FileDescription", "OriginalFilename", "FileVersion",
                               "ProductVersion", "LegalCopyright", "InternalName") and val.strip():
                        out[key] = val.strip()[:200]
    return out


def pe_details(path: Path, raw: bytes) -> dict[str, Any]:
    try:
        pe = pefile.PE(data=raw, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY[k] for k in (
            "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT", "IMAGE_DIRECTORY_ENTRY_RESOURCE")])
    except Exception as e:  # hostile input: any parser failure is just "no details"
        return {"error": f"pefile: {type(e).__name__}", "signature": signature_info(str(path)), "size": len(raw)}
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    ep = oh.AddressOfEntryPoint
    sections, ep_in_any = [], False
    for s in pe.sections:
        ch = s.Characteristics
        r, w, x = bool(ch & 0x40000000), bool(ch & 0x80000000), bool(ch & 0x20000000)
        has_ep = s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
        ep_in_any |= has_ep
        sections.append({"name": s.Name.rstrip(b"\x00").decode("latin-1"), "virtual_address": hex(s.VirtualAddress),
                         "virtual_size": s.Misc_VirtualSize, "raw_size": s.SizeOfRawData,
                         "entropy": round(s.get_entropy(), 3), "flags": ("r" if r else "-") + ("w" if w else "-") + ("x" if x else "-"),
                         "rwx": r and w and x, "has_entry_point": has_ep})
    imports: dict[str, list[str]] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:200]:
        dll = entry.dll.decode("latin-1", "replace").lower()
        imports[dll] = [(i.name.decode("latin-1", "replace") if i.name else f"ord_{i.ordinal}") for i in entry.imports[:500]]
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exports = [(e.name.decode("latin-1", "replace") if e.name else f"ord_{e.ordinal}") for e in pe.DIRECTORY_ENTRY_EXPORT.symbols[:500]]
    res_types = []
    for e in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []) or []:
        name = str(e.name) if e.name else pefile.RESOURCE_TYPE.get(e.id, str(e.id))
        n = len(e.directory.entries) if hasattr(e, "directory") else 1
        res_types.append({"type": name.replace("RT_", "").lower(), "count": n})
    try:
        pe.parse_version_information  # noqa: B018 (exists on all supported pefile versions)
        vi = _version_info(pe)
    except Exception:
        vi = {}
    ov_off = pe.get_overlay_data_start_offset()
    overlay = raw[ov_off:] if ov_off else b""
    try:
        imphash = pe.get_imphash()
    except Exception:
        imphash = ""
    dirs = list(oh.DATA_DIRECTORY)
    dsize = lambda i: dirs[i].Size if i < len(dirs) else 0  # noqa: E731
    urls = []
    for m in _URL.findall(raw):
        u = m.decode("latin-1").rstrip(".,;)\"'")
        if not any(n in u.lower() for n in _URL_NOISE) and u not in urls:
            urls.append(u)
        if len(urls) >= 20:
            break
    pe.close()
    return {
        "machine": pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine)),
        "format": "PE32+" if oh.Magic == 0x20B else "PE32",
        "is_dll": bool(fh.Characteristics & 0x2000),
        "subsystem": pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem)),
        "timestamp": _ts(fh.TimeDateStamp), "timestamp_unix": fh.TimeDateStamp,
        "entry_point": hex(ep), "entry_outside_sections": not ep_in_any and ep != 0,
        "image_base": hex(oh.ImageBase), "linker": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
        "dll_characteristics": hex(oh.DllCharacteristics),
        "aslr": bool(oh.DllCharacteristics & 0x0040), "dep": bool(oh.DllCharacteristics & 0x0100),
        "cfg": bool(oh.DllCharacteristics & 0x4000),
        "dotnet": dsize(14) > 0, "tls": dsize(9) > 0, "embedded_signature": dsize(4) > 0, "has_debug": dsize(6) > 0, "has_relocs": dsize(5) > 0,
        "sections": sections, "imports": imports, "exports": exports, "resources": res_types,
        "resource_types": len(res_types), "version_info": vi,
        "overlay_size": len(overlay), "overlay_entropy": round(_entropy(overlay), 3) if overlay else 0.0,
        "embedded_pe": raw.count(b"This program cannot be run in DOS mode"),
        "urls": urls, "imphash": imphash, "size": len(raw),
        "signature": signature_info(str(path)),
    }


def _entropy(data: bytes) -> float:
    import math
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data[: 8 * 1024 * 1024]:
        counts[b] += 1
    n = min(len(data), 8 * 1024 * 1024)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def scan(path: Path) -> dict[str, Any]:
    """Full report body for a quarantined file. Raises nothing; errors go into the dict."""
    t0 = time.perf_counter()
    raw = path.read_bytes()
    pe = pe_details(path, raw)
    eng = engines(path, pe, raw=raw)
    report: dict[str, Any] = {"report_version": REPORT_VERSION, "pe": pe, "signals": explain.signals(pe, raw)}
    if eng is None or "error" in eng:
        report.update(verdict="error", error=(eng or {}).get("error") or "pe_parse_failed", engines=[], top_features=[],
                      explanation={}, flag_count=0, engine_count=0)
    else:
        flagged = [e for e in eng["engines"] if e["flagged"]]
        rec = next(e for e in eng["engines"] if e["recommended"])
        report.update(eng, verdict="malicious" if rec["flagged"] else "benign",
                      flag_count=len(flagged), engine_count=len(eng["engines"]), probability=rec["probability"])
    report["scan_ms"] = round((time.perf_counter() - t0) * 1000)
    return report


if __name__ == "__main__":
    import sys
    rep = scan(Path(sys.argv[1]))
    print(json.dumps({k: rep.get(k) for k in ("verdict", "probability", "scan_ms", "error")}, indent=1))
    print(json.dumps(explain.assessment(rep, rep["signals"]), indent=1, ensure_ascii=True))
    for s in rep["signals"]:
        print(f"  [{s['severity']:8}] {s['title']} -- {s['evidence'][:90]}".encode("ascii", "replace").decode())
    for r in (rep.get("explanation") or {}).get("top", [])[:8]:
        print(f"  {r['contribution']:+.3f} {r['strength']:8} {r['title'][:70]} = {r['value']} ({r['typical']})".encode("ascii", "replace").decode())
