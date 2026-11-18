"""Names and layout of the 2568 EMBER v3 (thrember) features used by EMBER2024 (R1).

The layout is read from thrember's feature classes (group order, group widths, string regex order,
header member lists, pefile warning list); only the order of scalar fields inside a group mirrors
each class's process_raw_features(). Widths are asserted against the classes, so a thrember change
that moves features fails loudly instead of mislabelling them.

  ember_feature_map()[i] -> {"index", "name", "group", "group_class", "group_offset", "position", "field", "kind", "note"}
  python -m src.v8.ember_map --out ember_feature_map.json
"""

from __future__ import annotations

import argparse
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

EMBER_DIM = 2568

# Scalar fields in the order process_raw_features() stacks them (thrember 0.1.0, commit 0ef753e).
_GENERAL = [("size", "num"), ("entropy", "num"), ("is_pe", "cat"), ("start_byte_0", "cat"), ("start_byte_1", "cat"),
            ("start_byte_2", "cat"), ("start_byte_3", "cat")]
_HEADER_SCALARS = [
    ("coff_timestamp", "num"), ("coff_number_of_sections", "num"), ("coff_number_of_symbols", "num"),
    ("coff_sizeof_optional_header", "num"), ("coff_pointer_to_symbol_table", "num"), ("coff_machine", "cat"),
    ("optional_subsystem", "cat"), ("optional_major_image_version", "num"), ("optional_minor_image_version", "num"),
    ("optional_major_linker_version", "num"), ("optional_minor_linker_version", "num"),
    ("optional_major_operating_system_version", "num"), ("optional_minor_operating_system_version", "num"),
    ("optional_major_subsystem_version", "num"), ("optional_minor_subsystem_version", "num"), ("optional_sizeof_code", "num"),
    ("optional_sizeof_headers", "num"), ("optional_sizeof_image", "num"), ("optional_sizeof_initialized_data", "num"),
    ("optional_sizeof_uninitialized_data", "num"), ("optional_sizeof_stack_reserve", "num"), ("optional_sizeof_stack_commit", "num"),
    ("optional_sizeof_heap_reserve", "num"), ("optional_sizeof_heap_commit", "num"), ("optional_address_of_entrypoint", "num"),
    ("optional_base_of_code", "num"), ("optional_image_base", "num"), ("optional_section_alignment", "num"),
    ("optional_checksum", "num"), ("optional_number_of_rvas_and_sizes", "num"),
]
_SECTION_GENERAL = ["n_sections", "n_zero_size", "n_empty_name", "n_rx", "n_w", "max_entropy", "min_entropy",
                    "max_size_ratio", "min_size_ratio", "max_vsize_ratio", "min_vsize_ratio"]
_AUTHENTICODE = ["num_certs", "self_signed", "empty_program_name", "no_countersigner", "parse_error", "chain_max_depth",
                 "latest_signing_time", "signing_time_diff"]


def _slug(s: str) -> str:
    return re.sub(r"[^0-9a-zA-Z]+", "_", s).strip("_").lower() or "x"


def _group_fields(fe: Any) -> list[tuple[str, str, str]]:
    """(field, kind, note) for every column of one thrember feature group, in vector order."""
    n = fe.name
    if n == "general":
        return [(f, k, "") for f, k in _GENERAL]
    if n == "histogram":
        return [(f"byte_{i:02x}", "frac", f"share of bytes equal to 0x{i:02X}") for i in range(256)]
    if n == "byteentropy":
        return [(f"e{i // 16:02d}_b{i % 16:x}", "frac", f"window entropy {i // 16 / 2:.1f}-{i // 16 / 2 + 0.5:.1f} bits/byte, byte values 0x{i % 16:X}0-0x{i % 16:X}F")
                for i in range(256)]
    if n == "strings":
        out = [("numstrings", "num", ""), ("avlength", "num", ""), ("printables", "num", "")]
        out += [(f"char_{i:02d}", "frac", f"share of printable string characters equal to {chr(0x20 + i)!r}") for i in range(96)]
        out.append(("entropy", "num", "entropy of printable string characters"))
        for name, idx in sorted(fe.regex_idxs.items(), key=lambda kv: kv[1]):
            out.append((f"regex_{idx:02d}_{_slug(name)}", "num", f"strings matching regex {name!r}"))
        return out
    if n == "header":
        out = [(f, k, "") for f, k in _HEADER_SCALARS]
        out += [(f"characteristic_{_slug(c)}", "bool", c) for c in fe._image_characteristics]
        out += [(f"dllchar_{_slug(c)}", "bool", c) for c in fe._dll_characteristics]
        out += [(f"dos_{m}", "num", m) for m in fe._dos_members]
        return out
    if n == "section":
        out = [(f, "num", "") for f in _SECTION_GENERAL]
        for kind, note in (("size", "section raw size"), ("vsize", "section virtual size"), ("entropy", "section entropy"),
                           ("props", "section name:characteristic")):
            out += [(f"{kind}_hash_{i:02d}", "hash", f"FeatureHasher(50) bucket of {note}") for i in range(50)]
        out += [(f"entry_name_hash_{i}", "hash", "FeatureHasher(10) bucket of the entry-point section name") for i in range(10)]
        out += [("overlay_size", "num", ""), ("overlay_size_ratio", "num", ""), ("overlay_entropy", "num", "")]
        return out
    if n == "imports":
        out = [("n_functions", "num", ""), ("n_libraries", "num", "")]
        out += [(f"library_hash_{i:03d}", "hash", "FeatureHasher(256) bucket of lower-cased DLL names") for i in range(256)]
        out += [(f"function_hash_{i:04d}", "hash", "FeatureHasher(1024) bucket of 'dll:function'") for i in range(1024)]
        return out
    if n == "exports":
        return ([("has_exports_128", "num", "128 when the file has any exports, else 0 (thrember stores the hash width, not a count)")]
                + [(f"export_hash_{i:03d}", "hash", "FeatureHasher(128, signed) bucket of export names") for i in range(128)])
    if n == "datadirectories":
        out = []
        for d in fe._name_order:
            out += [(f"{_slug(d)}_size", "num", f"IMAGE_DIRECTORY_ENTRY_{d} size"),
                    (f"{_slug(d)}_vaddr", "num", f"IMAGE_DIRECTORY_ENTRY_{d} virtual address")]
        return out + [("has_relocs", "bool", ""), ("has_dynamic_relocs", "bool", "")]
    if n == "richheader":
        return [("n_pairs", "num", "")] + [(f"pair_hash_{i:02d}", "hash", "FeatureHasher(32) bucket of (comp id, count) pairs")
                                           for i in range(32)]
    if n == "authenticode":
        return [(f, "num", "") for f in _AUTHENTICODE]
    if n == "pefilewarnings":
        ids = sorted(fe.warning_ids.items(), key=lambda kv: kv[1])
        return [(f"warn_{i:02d}", "bool", text) for text, i in ids] + [("n_warnings", "num", "number of distinct pefile warnings")]
    raise ValueError(f"unknown thrember feature group {n!r}")


@lru_cache(maxsize=1)
def ember_feature_map() -> tuple[dict[str, Any], ...]:
    import thrember

    ext = thrember.PEFeatureExtractor()
    out: list[dict[str, Any]] = []
    for fe in ext.features:
        fields = _group_fields(fe)
        if len(fields) != fe.dim:
            raise RuntimeError(f"thrember group {fe.name}: {len(fields)} named fields but dim {fe.dim}")
        start = len(out)
        for pos, (field, kind, note) in enumerate(fields):
            out.append({"index": start + pos, "name": f"em_{fe.name}_{field}", "group": fe.name, "group_class": type(fe).__name__,
                        "group_offset": start, "position": pos, "field": field, "kind": kind, "note": note})
    if len(out) != EMBER_DIM or ext.dim != EMBER_DIM:
        raise RuntimeError(f"thrember vector has {ext.dim} features, expected {EMBER_DIM}")
    if len({r["name"] for r in out}) != EMBER_DIM:
        raise RuntimeError("EMBER feature names are not unique")
    return tuple(out)


def ember_feature_names() -> list[str]:
    return [r["name"] for r in ember_feature_map()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, help="Write the map as JSON (default: print a per-group summary)")
    args = ap.parse_args(argv)
    m = ember_feature_map()
    if args.out:
        args.out.write_text(json.dumps(list(m), indent=1), encoding="utf-8")
        print(f"{len(m)} features -> {args.out}")
    else:
        groups: dict[str, list[int]] = {}
        for r in m:
            groups.setdefault(r["group"], []).append(r["index"])
        for g, idx in groups.items():
            print(f"{g:16} {idx[0]:4d}..{idx[-1]:4d} ({len(idx)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
