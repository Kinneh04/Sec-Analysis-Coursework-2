"""Conventional static PE feature extraction."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pefile

from src.common.config import artifacts, load_config
from src.common.pe_utils import imphash_buckets, read_strings_count, section_entropy


EXTRACTOR_VERSION = "pe_v1"


def extract_pe_features(path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {"pe_status": "ok", "pe_extractor": EXTRACTOR_VERSION}
    raw = path.read_bytes()
    out["pe_file_size"] = len(raw)
    out["pe_string_count"] = read_strings_count(raw)
    try:
        pe = pefile.PE(data=raw, fast_load=False)
    except pefile.PEFormatError as e:
        out["pe_status"] = f"pe_error:{e}"
        return out

    out["pe_machine"] = int(pe.FILE_HEADER.Machine)
    out["pe_is_dll"] = int(bool(pe.FILE_HEADER.IMAGE_FILE_DLL))
    out["pe_subsystem"] = int(pe.OPTIONAL_HEADER.Subsystem)
    out["pe_timestamp"] = int(pe.FILE_HEADER.TimeDateStamp)
    out["pe_size_optional_header"] = int(pe.FILE_HEADER.SizeOfOptionalHeader)
    out["pe_characteristics"] = int(pe.FILE_HEADER.Characteristics)

    secs = pe.sections or []
    out["pe_section_count"] = len(secs)
    entropies = []
    rwx = 0
    exec_secs = 0
    for s in secs:
        data = s.get_data()
        entropies.append(section_entropy(data))
        chars = int(s.Characteristics)
        w = bool(chars & 0x80000000)
        r = bool(chars & 0x40000000)
        x = bool(chars & 0x20000000)
        if r and w and x:
            rwx += 1
        if x:
            exec_secs += 1
    if entropies:
        out["pe_entropy_mean"] = float(np.mean(entropies))
        out["pe_entropy_max"] = float(np.max(entropies))
        out["pe_entropy_std"] = float(np.std(entropies))
    else:
        out["pe_entropy_mean"] = None
        out["pe_entropy_max"] = None
        out["pe_entropy_std"] = None
    out["pe_rwx_section_count"] = rwx
    out["pe_executable_section_count"] = exec_secs

    imports: list[str] = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="replace").lower()
                for imp in entry.imports:
                    if imp.name:
                        imports.append(f"{dll}!{imp.name.decode(errors='replace')}")
                    elif imp.ordinal is not None:
                        imports.append(f"{dll}!ord{imp.ordinal}")
    except Exception:
        pass
    out["pe_import_count"] = len(imports)
    out["pe_import_dll_count"] = len({i.split("!")[0] for i in imports if "!" in i})

    export_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
        export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols or [])
    out["pe_export_count"] = export_count

    resource_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") and pe.DIRECTORY_ENTRY_RESOURCE:
        resource_count = len(pe.DIRECTORY_ENTRY_RESOURCE.entries or [])
    out["pe_resource_dir_entries"] = resource_count

    for i, c in enumerate(imphash_buckets(imports, 256)):
        out[f"pe_imphash_h{i:03d}"] = c

    pe.close()
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    inv = pd.read_parquet(artifacts(cfg) / "manifests" / "corpus_inventory.parquet")
    inv = inv[inv["inventory_status"] == "ok"]
    if args.limit:
        inv = inv.head(args.limit)

    rows: list[dict] = []
    for _, row in inv.iterrows():
        path = Path(row["relative_path"])
        feats = extract_pe_features(path)
        feats["sha256"] = row["sha256"]
        feats["label"] = row["label"]
        rows.append(feats)

    df = pd.DataFrame(rows)
    out = artifacts(cfg) / "features" / "pe_features.parquet"
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    print(f"PE features: {len(df)} rows -> {out}")


if __name__ == "__main__":
    main()
