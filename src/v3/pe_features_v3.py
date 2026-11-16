"""PE-v3 static features (pefile + raw bytes; no execution, no Binary Ninja).

Predictor columns are prefixed ``pe3_``. Metadata columns (``v3_*``) are never predictors.
Hashing uses MD5-derived buckets so assignments are stable across processes and machines.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import re
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pefile

EXTRACTOR_VERSION = "pe_v3"

IMPORT_BUCKETS = 1024
DLL_BUCKETS = 128
EXPORT_BUCKETS = 128
SECTION_BUCKETS = 32
WINDOW = 2048
STEP = 1024
CHUNK_BLOCKS = 8192

RESOURCE_TYPES = {
    1: "cursor", 2: "bitmap", 3: "icon", 4: "menu", 5: "dialog", 6: "string", 9: "accelerator",
    10: "rcdata", 11: "messagetable", 12: "group_cursor", 14: "group_icon", 16: "version",
    24: "manifest",
}

DLL_CHAR_FLAGS = {
    "high_entropy_va": 0x0020, "dynamic_base": 0x0040, "force_integrity": 0x0080, "nx_compat": 0x0100,
    "no_isolation": 0x0200, "no_seh": 0x0400, "no_bind": 0x0800, "appcontainer": 0x1000,
    "wdm_driver": 0x2000, "guard_cf": 0x4000, "terminal_server_aware": 0x8000,
}

_STR_RE = re.compile(rb"[\x20-\x7e]{5,}")
_URL_RE = re.compile(rb"https?://", re.IGNORECASE)
_PATH_RE = re.compile(rb"[a-zA-Z]:\\\\")
_REG_RE = re.compile(rb"HKEY_", re.IGNORECASE)
_MZ_RE = re.compile(rb"MZ")


def stable_bucket(token: str, dim: int) -> int:
    digest = hashlib.md5(token.lower().encode("utf-8", errors="replace")).digest()
    return int.from_bytes(digest[:8], "little") % dim


def _entropy(counts: np.ndarray) -> float:
    total = counts.sum()
    if total <= 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(-(p * np.log2(p)).sum())


def byte_histogram(a: np.ndarray) -> np.ndarray:
    h = np.bincount(a, minlength=256).astype(np.float64)
    return h / max(len(a), 1)


def byte_entropy_histogram(a: np.ndarray) -> np.ndarray:
    """EMBER-style 16x16 (window entropy bin x high-nibble) histogram, normalized."""
    out = np.zeros((16, 16), dtype=np.float64)
    if len(a) < WINDOW:
        coarse = np.bincount(a >> 4, minlength=16).astype(np.float64)
        ent = _entropy(coarse) * 2  # scale 0..4 bits -> 0..8
        out[min(int(ent * 2), 15), :] += coarse
        return (out / max(out.sum(), 1)).ravel()
    n_blocks = len(a) // STEP
    block_counts = np.zeros((n_blocks, 16), dtype=np.int32)
    for start in range(0, n_blocks, CHUNK_BLOCKS):
        stop = min(start + CHUNK_BLOCKS, n_blocks)
        seg = a[start * STEP: stop * STEP] >> 4
        ids = np.repeat(np.arange(stop - start, dtype=np.int64), STEP) * 16 + seg
        block_counts[start:stop] = np.bincount(ids, minlength=(stop - start) * 16).reshape(-1, 16)
    win = block_counts[:-1] + block_counts[1:]
    totals = win.sum(axis=1, keepdims=True).astype(np.float64)
    p = np.where(win > 0, win / totals, 1.0)
    ent = -(np.where(win > 0, p * np.log2(p), 0.0)).sum(axis=1) * 2
    ent_bin = np.clip((ent * 2).astype(int), 0, 15)
    np.add.at(out, ent_bin, win.astype(np.float64))
    return (out / max(out.sum(), 1)).ravel()


def string_features(raw: bytes) -> dict[str, float]:
    strings = _STR_RE.findall(raw)
    out: dict[str, float] = {"pe3_str_count": float(len(strings))}
    if strings:
        lengths = np.fromiter((len(s) for s in strings), dtype=np.float64)
        out["pe3_str_avg_len"] = float(lengths.mean())
        out["pe3_str_max_len"] = float(lengths.max())
        joined = b"".join(strings)
        chars = np.frombuffer(joined, dtype=np.uint8).astype(np.int64) - 0x20
        hist = np.bincount(chars, minlength=96).astype(np.float64)
        out["pe3_str_char_entropy"] = _entropy(hist)
        hist /= max(hist.sum(), 1)
        for i, v in enumerate(hist):
            out[f"pe3_str_char_{i:02d}"] = float(v)
        out["pe3_str_printable_ratio"] = float(len(joined) / max(len(raw), 1))
    else:
        out.update({"pe3_str_avg_len": 0.0, "pe3_str_max_len": 0.0, "pe3_str_char_entropy": 0.0,
                    "pe3_str_printable_ratio": 0.0})
        for i in range(96):
            out[f"pe3_str_char_{i:02d}"] = 0.0
    out["pe3_str_urls"] = float(len(_URL_RE.findall(raw)))
    out["pe3_str_paths"] = float(len(_PATH_RE.findall(raw)))
    out["pe3_str_registry"] = float(len(_REG_RE.findall(raw)))
    out["pe3_str_mz"] = float(len(_MZ_RE.findall(raw)))
    return out


def _header_features(pe: pefile.PE, raw_len: int) -> dict[str, float]:
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    out: dict[str, float] = {
        "pe3_hdr_machine": float(fh.Machine),
        "pe3_hdr_timestamp": float(fh.TimeDateStamp),
        "pe3_hdr_characteristics": float(fh.Characteristics),
        "pe3_hdr_is_dll": float(bool(fh.Characteristics & 0x2000)),
        "pe3_hdr_is_exe": float(bool(fh.Characteristics & 0x0002)),
        "pe3_hdr_large_address_aware": float(bool(fh.Characteristics & 0x0020)),
        "pe3_hdr_is_64bit": float(oh.Magic == 0x20B),
        "pe3_hdr_subsystem": float(oh.Subsystem),
        "pe3_hdr_dll_characteristics": float(oh.DllCharacteristics),
        "pe3_hdr_linker_major": float(oh.MajorLinkerVersion),
        "pe3_hdr_linker_minor": float(oh.MinorLinkerVersion),
        "pe3_hdr_os_major": float(oh.MajorOperatingSystemVersion),
        "pe3_hdr_image_major": float(oh.MajorImageVersion),
        "pe3_hdr_subsystem_major": float(oh.MajorSubsystemVersion),
        "pe3_hdr_size_of_code": float(oh.SizeOfCode),
        "pe3_hdr_size_of_init_data": float(oh.SizeOfInitializedData),
        "pe3_hdr_size_of_uninit_data": float(oh.SizeOfUninitializedData),
        "pe3_hdr_entry_point": float(oh.AddressOfEntryPoint),
        "pe3_hdr_image_base_low32": float(oh.ImageBase & 0xFFFFFFFF),
        "pe3_hdr_section_alignment": float(oh.SectionAlignment),
        "pe3_hdr_file_alignment": float(oh.FileAlignment),
        "pe3_hdr_size_of_image": float(oh.SizeOfImage),
        "pe3_hdr_size_of_headers": float(oh.SizeOfHeaders),
        "pe3_hdr_checksum_nonzero": float(oh.CheckSum != 0),
        "pe3_hdr_stack_reserve": float(oh.SizeOfStackReserve),
        "pe3_hdr_heap_reserve": float(oh.SizeOfHeapReserve),
        "pe3_hdr_num_rva_and_sizes": float(oh.NumberOfRvaAndSizes),
        "pe3_hdr_image_to_file_ratio": float(oh.SizeOfImage / max(raw_len, 1)),
    }
    for name, bit in DLL_CHAR_FLAGS.items():
        out[f"pe3_dllchar_{name}"] = float(bool(oh.DllCharacteristics & bit))
    try:
        out["pe3_hdr_checksum_valid"] = float(oh.CheckSum != 0 and pe.verify_checksum())
    except Exception:
        out["pe3_hdr_checksum_valid"] = 0.0
    dirs = list(getattr(oh, "DATA_DIRECTORY", []))
    for i in range(16):
        size = float(dirs[i].Size) if i < len(dirs) else 0.0
        out[f"pe3_dir_{i:02d}_size"] = size
        out[f"pe3_dir_{i:02d}_present"] = float(size > 0)
    rich = pe.parse_rich_header() if hasattr(pe, "parse_rich_header") else None
    out["pe3_rich_present"] = float(bool(rich))
    out["pe3_rich_entries"] = float(len(rich.get("values", [])) // 2) if rich else 0.0
    return out


def _section_features(pe: pefile.PE) -> dict[str, float]:
    secs = pe.sections or []
    out: dict[str, float] = {"pe3_sec_count": float(len(secs))}
    name_size = np.zeros(SECTION_BUCKETS)
    name_ent = np.zeros(SECTION_BUCKETS)
    name_vsize = np.zeros(SECTION_BUCKETS)
    ents, ratios = [], []
    zero_raw = empty_name = rwx = execs = writes = 0
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    out["pe3_ep_in_exec_section"] = 0.0
    out["pe3_ep_section_entropy"] = 0.0
    out["pe3_ep_outside_sections"] = 1.0
    for s in secs:
        name = s.Name.rstrip(b"\x00").decode("latin-1", errors="replace")
        data = s.get_data()
        ent = s.get_entropy() if data else 0.0
        ents.append(ent)
        raw_size, vsize = int(s.SizeOfRawData), int(s.Misc_VirtualSize)
        ratios.append(vsize / max(raw_size, 1))
        chars = int(s.Characteristics)
        x, w, r = bool(chars & 0x20000000), bool(chars & 0x80000000), bool(chars & 0x40000000)
        zero_raw += raw_size == 0
        empty_name += name == ""
        rwx += r and w and x
        execs += x
        writes += w
        b = stable_bucket(name or "<empty>", SECTION_BUCKETS)
        name_size[b] += raw_size
        name_ent[b] += ent
        name_vsize[b] += vsize
        if s.VirtualAddress <= ep < s.VirtualAddress + max(vsize, raw_size):
            out["pe3_ep_in_exec_section"] = float(x)
            out["pe3_ep_section_entropy"] = float(ent)
            out["pe3_ep_outside_sections"] = 0.0
    out.update({
        "pe3_sec_zero_raw": float(zero_raw), "pe3_sec_empty_name": float(empty_name),
        "pe3_sec_rwx": float(rwx), "pe3_sec_exec": float(execs), "pe3_sec_write": float(writes),
        "pe3_sec_entropy_mean": float(np.mean(ents)) if ents else 0.0,
        "pe3_sec_entropy_max": float(np.max(ents)) if ents else 0.0,
        "pe3_sec_entropy_min": float(np.min(ents)) if ents else 0.0,
        "pe3_sec_vsize_raw_ratio_max": float(np.max(ratios)) if ratios else 0.0,
        "pe3_sec_high_entropy_count": float(sum(e > 7.0 for e in ents)),
    })
    for i in range(SECTION_BUCKETS):
        out[f"pe3_secname_size_{i:02d}"] = float(name_size[i])
        out[f"pe3_secname_entropy_{i:02d}"] = float(name_ent[i])
        out[f"pe3_secname_vsize_{i:02d}"] = float(name_vsize[i])
    return out


def _import_export_features(pe: pefile.PE) -> dict[str, float]:
    imp = np.zeros(IMPORT_BUCKETS)
    dlls = np.zeros(DLL_BUCKETS)
    n_imports = n_ordinal = 0
    dll_names: set[str] = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = (entry.dll or b"").decode("latin-1", errors="replace").lower()
        dll_names.add(dll)
        dlls[stable_bucket(dll, DLL_BUCKETS)] += 1
        for f in entry.imports:
            if f.name:
                token = f"{dll}:{f.name.decode('latin-1', errors='replace')}"
            else:
                token = f"{dll}:ord{f.ordinal}"
                n_ordinal += 1
            imp[stable_bucket(token, IMPORT_BUCKETS)] += 1
            n_imports += 1
    exp = np.zeros(EXPORT_BUCKETS)
    n_exports = 0
    ed = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if ed is not None:
        for sym in ed.symbols or []:
            token = sym.name.decode("latin-1", errors="replace") if sym.name else f"ord{sym.ordinal}"
            exp[stable_bucket(token, EXPORT_BUCKETS)] += 1
            n_exports += 1
    out = {
        "pe3_imp_count": float(n_imports),
        "pe3_imp_ordinal_count": float(n_ordinal),
        "pe3_imp_dll_count": float(len(dll_names)),
        "pe3_exp_count": float(n_exports),
        "pe3_delay_imp_present": float(bool(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", None))),
    }
    out.update({f"pe3_imp_bucket_{i:04d}": float(v) for i, v in enumerate(imp)})
    out.update({f"pe3_impdll_bucket_{i:03d}": float(v) for i, v in enumerate(dlls)})
    out.update({f"pe3_exp_bucket_{i:03d}": float(v) for i, v in enumerate(exp)})
    return out


def _resource_overlay_features(pe: pefile.PE, raw: bytes) -> dict[str, float]:
    out = {f"pe3_res_{name}": 0.0 for name in RESOURCE_TYPES.values()}
    out["pe3_res_other"] = 0.0
    out["pe3_res_total"] = 0.0
    rd = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if rd is not None:
        for entry in rd.entries or []:
            n = len(entry.directory.entries) if hasattr(entry, "directory") else 1
            key = RESOURCE_TYPES.get(entry.id)
            out[f"pe3_res_{key}" if key else "pe3_res_other"] += n
            out["pe3_res_total"] += n
    try:
        ov_start = pe.get_overlay_data_start_offset()
    except Exception:
        ov_start = None
    if ov_start is not None and ov_start < len(raw):
        ov = np.frombuffer(raw[ov_start:], dtype=np.uint8)
        out["pe3_overlay_size"] = float(len(ov))
        out["pe3_overlay_ratio"] = float(len(ov) / max(len(raw), 1))
        out["pe3_overlay_entropy"] = _entropy(np.bincount(ov, minlength=256).astype(np.float64))
    else:
        out.update({"pe3_overlay_size": 0.0, "pe3_overlay_ratio": 0.0, "pe3_overlay_entropy": 0.0})
    return out


def extract_pe_v3(path: Path, expected_sha256: str | None = None) -> dict[str, Any]:
    t0 = time.perf_counter()
    out: dict[str, Any] = {"v3_extractor": EXTRACTOR_VERSION, "v3_status": "ok"}
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    out["v3_sha_match"] = expected_sha256 is None or actual == expected_sha256
    if not out["v3_sha_match"]:
        out["v3_status"] = "sha_mismatch"
        out["v3_extract_seconds"] = time.perf_counter() - t0
        return out
    a = np.frombuffer(raw, dtype=np.uint8)
    out["pe3_file_size_log"] = math.log1p(len(raw))
    out["pe3_file_entropy"] = _entropy(np.bincount(a, minlength=256).astype(np.float64))
    for i, v in enumerate(byte_histogram(a)):
        out[f"pe3_bytehist_{i:03d}"] = float(v)
    for i, v in enumerate(byte_entropy_histogram(a)):
        out[f"pe3_byteent_{i:03d}"] = float(v)
    out.update(string_features(raw))
    try:
        pe = pefile.PE(data=raw, fast_load=False)
    except pefile.PEFormatError as e:
        out["v3_status"] = f"pe_error:{str(e)[:80]}"
        out["v3_extract_seconds"] = time.perf_counter() - t0
        return out
    try:
        out.update(_header_features(pe, len(raw)))
        out.update(_section_features(pe))
        out.update(_import_export_features(pe))
        out.update(_resource_overlay_features(pe, raw))
    except Exception as e:
        out["v3_status"] = f"partial:{type(e).__name__}"
    finally:
        pe.close()
    out["v3_extract_seconds"] = time.perf_counter() - t0
    return out


def _worker(args: tuple[str, str]) -> dict[str, Any]:
    path, sha = args
    try:
        feats = extract_pe_v3(Path(path), sha)
    except Exception as e:
        feats = {"v3_extractor": EXTRACTOR_VERSION, "v3_status": f"error:{type(e).__name__}", "v3_sha_match": False}
    feats["sha256"] = sha
    return feats


def v3_predictor_columns(df: pd.DataFrame, *, include_timestamp: bool = False) -> list[str]:
    from src.audit.schema import is_forbidden_predictor

    cols = []
    for c in df.columns:
        if not c.startswith("pe3_") or is_forbidden_predictor(c):
            continue
        if c == "pe3_hdr_timestamp" and not include_timestamp:
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            cols.append(c)
    return sorted(cols)


def extract_manifest(rows: list[tuple[str, str]], out_path: Path, *, workers: int) -> pd.DataFrame:
    results: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_worker, r) for r in rows]
        for i, fut in enumerate(as_completed(futs), 1):
            results.append(fut.result())
            if i % 100 == 0:
                print(f"  {i}/{len(rows)}", flush=True)
    df = pd.DataFrame(results).sort_values("sha256").reset_index(drop=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(".parquet.tmp")
    df.to_parquet(tmp, index=False)
    os.replace(tmp, out_path)
    return df


def main(argv: list[str] | None = None) -> int:
    from src.common.config import artifacts, load_config

    ap = argparse.ArgumentParser(description="PE-v3 static feature extraction (no BN, no execution)")
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--manifest", help="Parquet/CSV with sha256 and path columns; default = V1 PE cohort")
    ap.add_argument("--output", default=None)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    art = artifacts(cfg)
    if args.manifest:
        m = pd.read_parquet(args.manifest) if args.manifest.endswith(".parquet") else pd.read_csv(args.manifest)
        rows = list(zip(m["path"].astype(str), m["sha256"].astype(str)))
        out = Path(args.output) if args.output else art / "v3" / "features" / "pe_features_v3_new.parquet"
    else:
        inv = pd.read_parquet(art / "manifests" / "corpus_inventory.parquet")
        cohort = set(pd.read_parquet(art / "features" / "pe_features.parquet", columns=["sha256"])["sha256"])
        inv = inv[inv["sha256"].isin(cohort)]
        rows = list(zip(inv["relative_path"].astype(str), inv["sha256"].astype(str)))
        out = Path(args.output) if args.output else art / "features" / "pe_features_v3.parquet"

    t0 = time.perf_counter()
    df = extract_manifest(rows, out, workers=args.workers)
    status = df["v3_status"].value_counts().to_dict()
    print(f"PE-v3: {len(df)} rows, {len(v3_predictor_columns(df))} predictors, {time.perf_counter() - t0:.0f}s -> {out}")
    print(f"status: {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
