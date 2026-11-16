"""Read-only corpus inventory (no execution)."""

from __future__ import annotations

import argparse
import csv
import hashlib
import random
from pathlib import Path

import pandas as pd

from src.common.config import artifacts, load_config
from src.common.hashing import sha256_file
from src.common.pe_utils import malware_path, pe_inventory_fields


def _benign_source_label(root: Path) -> tuple[str, str]:
    low = str(root).lower()
    if "system32" in low or "syswow64" in low:
        return "benign_windows_os", "windows_os_pe_inventory"
    if "program files" in low:
        return "benign_third_party", "installed_program_pe_inventory"
    return "benign_local", "local_pe_inventory"


def _benign_group_id(root: Path, path: Path) -> str:
    """Keep related binaries (same install directory tree) in one split group."""
    try:
        rel = path.relative_to(root)
        anchor = rel.parent.as_posix().lower() if rel.parent.parts else "."
    except ValueError:
        anchor = "."
    root_key = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:10]
    return f"benign_dir:{root_key}:{anchor}"


def _per_root_cap(root: str, default_cap: int, caps: dict | None) -> int:
    if not caps:
        return default_cap
    return int(caps.get(root) or caps.get("default") or default_cap)


def _collect_benign_root(
    root: str,
    max_files: int,
    max_mb: float,
    seed: int,
) -> list[dict]:
    rows: list[dict] = []
    max_bytes = int(max_mb * 1024 * 1024)
    base = Path(root)
    if not base.is_dir():
        return rows

    candidates: list[Path] = []
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".exe", ".dll", ".sys", ".scr"}:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= 0 or size > max_bytes:
            continue
        candidates.append(path)

    rng = random.Random(seed + hash(root) % 10000)
    rng.shuffle(candidates)

    for path in candidates:
        if len(rows) >= max_files:
            break
        try:
            size = path.stat().st_size
            digest = sha256_file(path)
        except OSError:
            continue
        meta = pe_inventory_fields(path)
        if not meta.get("is_pe"):
            continue
        source, label_source = _benign_source_label(base)
        rows.append(
            {
                "sha256": digest,
                "relative_path": str(path),
                "file_size": size,
                "file_type": path.suffix.lower(),
                "is_pe": True,
                "machine": meta.get("machine"),
                "is_dll": meta.get("is_dll"),
                "source": source,
                "label": "benign",
                "label_source": label_source,
                "benign_root": str(base),
                "software_source": base.name,
                "group_id": _benign_group_id(base, path),
                "inventory_status": meta.get("inventory_status"),
            }
        )
    return rows


def _inventory_benign_balanced(
    roots: list[str],
    max_files: int,
    max_mb: float,
    per_root_default: int,
    root_caps: dict | None,
    seed: int,
) -> list[dict]:
    """Round-robin across roots so no single source dominates before the global cap."""
    if not roots:
        return []
    per_root_lists: list[list[dict]] = []
    for root in roots:
        cap = _per_root_cap(root, per_root_default, root_caps)
        per_root_lists.append(_collect_benign_root(root, cap, max_mb, seed))

    merged: list[dict] = []
    indices = [0] * len(per_root_lists)
    while len(merged) < max_files:
        progressed = False
        for i, bucket in enumerate(per_root_lists):
            if len(merged) >= max_files:
                break
            if indices[i] < len(bucket):
                merged.append(bucket[indices[i]])
                indices[i] += 1
                progressed = True
        if not progressed:
            break
    return merged


def _inventory_malware_from_csv(
    cfg: dict, limit: int, seed: int
) -> list[dict]:
    csv_path = Path(cfg["paths"]["malware_analysis_csv"])
    corpus = Path(cfg["paths"]["malware_corpus"])
    rows: list[dict] = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        all_rows = list(reader)
    rng = random.Random(seed)
    rng.shuffle(all_rows)
    for rec in all_rows:
        if len(rows) >= limit:
            break
        rel = rec.get("rel_path") or ""
        sha = rec.get("sha256") or ""
        path = malware_path(corpus, rel)
        if not path.is_file():
            alt = corpus / rel.replace("\\", "/")
            path = alt if alt.is_file() else path
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        meta = pe_inventory_fields(path)
        imph = rec.get("imphash") or ""
        group = f"mb_imphash:{imph}" if imph else f"mb_sha:{sha[:16]}"
        rows.append(
            {
                "sha256": sha or sha256_file(path),
                "relative_path": str(path),
                "file_size": size,
                "file_type": Path(rel).suffix.lower() or meta.get("file_type"),
                "is_pe": meta.get("is_pe"),
                "machine": meta.get("machine"),
                "is_dll": meta.get("is_dll"),
                "source": "malwarebazaar",
                "label": "malicious",
                "label_source": "malwarebazaar_provenance",
                "software_source": "malwarebazaar",
                "group_id": group,
                "batch_date": rec.get("batch_date"),
                "inventory_status": meta.get("inventory_status"),
            }
        )
    return rows


def build_inventory(cfg: dict, limit_malware: int | None = None, limit_benign: int | None = None) -> pd.DataFrame:
    exp = cfg.get("experiment", {})
    lm = limit_malware or int(exp.get("max_malware_samples", 800))
    lb = limit_benign or int(exp.get("max_benign_samples", 800))
    seed = int(cfg.get("models", {}).get("random_seed", 42))
    max_mb = float(cfg.get("analysis", {}).get("max_file_size_mb", 50))
    per_root = int(exp.get("benign_max_per_root", 100))
    root_caps = exp.get("benign_root_caps")

    roots = list(cfg["paths"].get("benign_roots") or [])
    benign = _inventory_benign_balanced(roots, lb, max_mb, per_root, root_caps, seed)
    malware = _inventory_malware_from_csv(cfg, lm, seed)
    df = pd.DataFrame(benign + malware)
    if not df.empty:
        df = df.drop_duplicates(subset=["sha256"], keep="first")
    return df


def main() -> None:
    ap = argparse.ArgumentParser(description="Build read-only PE corpus inventory.")
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--limit-malware", type=int, default=None)
    ap.add_argument("--limit-benign", type=int, default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    out_dir = artifacts(cfg) / "manifests"
    out_dir.mkdir(parents=True, exist_ok=True)

    df = build_inventory(cfg, args.limit_malware, args.limit_benign)
    out_path = out_dir / "corpus_inventory.parquet"
    df.to_parquet(out_path, index=False)

    summary = {
        "total": len(df),
        "by_label": df.groupby("label").size().to_dict() if len(df) else {},
        "by_source": df.groupby("source").size().to_dict() if len(df) and "source" in df.columns else {},
        "by_software_source": df.groupby("software_source").size().to_dict()
        if len(df) and "software_source" in df.columns
        else {},
        "pe_ok": int((df["inventory_status"] == "ok").sum()) if len(df) else 0,
        "unique_groups": int(df["group_id"].nunique()) if len(df) and "group_id" in df.columns else 0,
    }
    summary_path = out_dir / "inventory_summary.txt"
    summary_path.write_text("\n".join(f"{k}: {v}" for k, v in summary.items()), encoding="utf-8")
    print(summary)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
