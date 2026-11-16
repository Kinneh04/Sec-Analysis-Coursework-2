"""Instruction-level Binary Ninja features: disassembly mnemonics of the largest functions.

Static analysis only, through the Binary Ninja GUI MCP server. Uses the same analysis limits and
intermediate analysis mode as V4. Raw mnemonic counts are cached per SHA-256.

  python -m src.v5.bn_insn extract --manifest artifacts/v5/manifests/insn_queue.csv
"""

from __future__ import annotations

import argparse
import json
import math
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from pathlib import Path
from typing import Any

import pandas as pd

from src.bn_mcp import BnMcpClient
from src.common.hashing import sha256_file
from src.ensure_bn_mcp import ensure_bn_mcp, reboot_bn_mcp
from src.v3.pe_features_v3 import stable_bucket
from src.v4.bn_extract import (ANALYSIS_TIMEOUT, FILE_TIMEOUT, MAX_BYTES, MCP_URL, SKIP_PATH_CONTAINS, FileTimeout,
                               _md, parse_table)

EXTRACTOR_VERSION = "bn_insn_v5"
CACHE_DIR = Path("artifacts/v5/bn_insn_cache")
TOP_K = 32
MAX_LINES = 1000
UNI_BUCKETS = 256
BI_BUCKETS = 512
INSN_RE = re.compile(r"^0x[0-9a-f]+\s+([a-z][a-z0-9.]*)", re.IGNORECASE)
CLASSES = {
    "call": ("call",), "jump": ("jmp",), "cond_jump": ("je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl", "jae", "jbe", "jge", "jle", "js", "jns", "jo", "jno", "jp", "jnp", "jcxz", "jecxz"),
    "stack": ("push", "pop"), "ret": ("ret", "retn"), "xor": ("xor",), "shift_rot": ("shl", "shr", "sar", "rol", "ror", "rcl", "rcr"),
    "simd": ("movdqa", "movdqu", "pxor", "movaps", "movups", "xorps", "pshufd", "aesenc", "aesdec"),
    "string": ("rep", "movsb", "movsd", "stosb", "stosd", "lodsb", "scasb"), "sys": ("int", "int3", "syscall", "sysenter", "cpuid", "rdtsc"),
    "nop": ("nop",),
}


def mnemonics(markdown: str) -> list[str]:
    out = []
    for line in markdown.splitlines():
        m = INSN_RE.match(line.strip())
        if m:
            out.append(m.group(1).lower())
    return out


def analyze(client: BnMcpClient, path: Path) -> dict[str, Any]:
    doc: dict[str, Any] = {}
    opened = client.call_tool("bn_open_item_open", {"path": path.resolve().as_posix(), "setActive": True})
    handle = (opened.get("openItem") or {}).get("handle")
    try:
        views = opened.get("binaryViews") or []
        bv = next((v for v in views if v.get("recommended")), None) or next((v for v in views if v.get("viewType") != "Raw"), None)
        if bv is None:
            return {"analysis_status": "unsupported"}
        client.call_tool("bn_binary_view_set_active", {"binaryView": bv["handle"]})
        pool = ThreadPoolExecutor(max_workers=1)
        fut = pool.submit(client.call_tool, "bn_analysis_update_and_wait", {})
        try:
            fut.result(timeout=ANALYSIS_TIMEOUT)
            doc["analysis_complete"] = True
        except FuturesTimeout:
            doc["analysis_complete"] = False
            try:
                abort = BnMcpClient(client.url)
                abort.connect()
                abort.call_tool("bn_analysis_abort", {})
            except Exception:
                pass
            try:
                fut.result(timeout=60)
            except FuturesTimeout:
                raise FileTimeout("analysis did not stop after abort")
        finally:
            pool.shutdown(wait=False)
        funcs = parse_table(_md(client.call_tool("bn_function_list", {"limit": 2000})))
        top = sorted(funcs, key=lambda f: int(f.get("basicBlockCount", "0") or 0), reverse=True)[:TOP_K]
        uni: Counter = Counter()
        bi: Counter = Counter()
        for f in top:
            seq = mnemonics(_md(client.call_tool("bn_function_disassembly", {"function": f["function"], "limit": MAX_LINES})))
            uni.update(seq)
            bi.update(f"{a}>{b}" for a, b in zip(seq, seq[1:]))
        doc["n_functions_sampled"] = len(top)
        doc["uni"] = dict(uni)
        doc["bi"] = dict(bi.most_common(3000))
        doc["n_insn"] = int(sum(uni.values()))
        doc["analysis_status"] = "ok" if doc["analysis_complete"] else "partial"
        return doc
    finally:
        if handle:
            client.close_item(handle)


def extract(queue: pd.DataFrame) -> dict[str, int]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    ensure_bn_mcp(MCP_URL)
    client = BnMcpClient(MCP_URL)
    client.connect()
    todo = [r for r in queue.itertuples(index=False) if not (CACHE_DIR / f"{r.sha256}.json").is_file()]
    print(f"BN insn v5: {len(queue) - len(todo)} cached, {len(todo)} to analyze", flush=True)
    counts: dict[str, int] = {}
    for i, r in enumerate(todo, 1):
        path, t0 = Path(r.path), time.time()
        try:
            size = path.stat().st_size
        except OSError:
            size = -1
        if size < 0:
            doc = {"analysis_status": "error", "errors": ["path_missing"]}
        elif size > MAX_BYTES or any(frag in str(path).lower() for frag in SKIP_PATH_CONTAINS):
            doc = {"analysis_status": "skipped"}
        elif sha256_file(path) != r.sha256:
            doc = {"analysis_status": "error", "errors": ["sha_mismatch"]}
        else:
            pool = ThreadPoolExecutor(max_workers=1)
            fut = pool.submit(analyze, client, path)
            try:
                doc = fut.result(timeout=FILE_TIMEOUT)
            except (FuturesTimeout, FileTimeout) as e:
                doc = {"analysis_status": "error", "errors": [f"timeout:{type(e).__name__}"]}
                reboot_bn_mcp(MCP_URL)
                client = BnMcpClient(MCP_URL)
                client.connect()
            except Exception as e:
                doc = {"analysis_status": "error", "errors": [f"{type(e).__name__}: {str(e)[:300]}"]}
                try:
                    reboot_bn_mcp(MCP_URL)
                    client = BnMcpClient(MCP_URL)
                    client.connect()
                except Exception:
                    pass
                continue  # transient: retry on a later run
            finally:
                pool.shutdown(wait=False)
        doc.update({"sha256": r.sha256, "extractor_version": EXTRACTOR_VERSION, "wall_seconds": round(time.time() - t0, 2)})
        tmp = CACHE_DIR / f"{r.sha256}.json.tmp"
        tmp.write_text(json.dumps(doc), encoding="utf-8")
        tmp.replace(CACHE_DIR / f"{r.sha256}.json")
        counts[doc["analysis_status"]] = counts.get(doc["analysis_status"], 0) + 1
        if i % 10 == 0:
            print(f"  {i}/{len(todo)} {counts}", flush=True)
    return counts


def features_from_doc(doc: dict[str, Any]) -> dict[str, float]:
    if doc.get("analysis_status") not in ("ok", "partial"):
        return {}
    uni, bi = doc.get("uni") or {}, doc.get("bi") or {}
    n = float(sum(uni.values()))
    f: dict[str, float] = {"in5_n_insn": n, "in5_distinct_mnemonics": float(len(uni))}
    if n <= 0:
        return f
    for cls, names in CLASSES.items():
        f[f"in5_frac_{cls}"] = sum(c for m, c in uni.items() if m in names) / n
    u = [0.0] * UNI_BUCKETS
    for m, c in uni.items():
        u[stable_bucket(m, UNI_BUCKETS)] += c
    b = [0.0] * BI_BUCKETS
    nb = float(sum(bi.values())) or 1.0
    for g, c in bi.items():
        b[stable_bucket(g, BI_BUCKETS)] += c
    f.update({f"in5_uni_h{i:03d}": v / n for i, v in enumerate(u)})
    f.update({f"in5_bi_h{i:03d}": v / nb for i, v in enumerate(b)})
    f["in5_entropy"] = -sum((c / n) * math.log2(c / n) for c in uni.values())
    return f


def build(shas: list[str]) -> pd.DataFrame:
    rows = []
    for sha in shas:
        p = CACHE_DIR / f"{sha}.json"
        doc = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {"analysis_status": "missing"}
        rows.append({"sha256": sha, "in5_status": doc.get("analysis_status", "missing"), **features_from_doc(doc)})
    return pd.DataFrame(rows)


def in5_columns(df: pd.DataFrame) -> list[str]:
    return sorted(c for c in df.columns if c.startswith("in5_") and c != "in5_status")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["extract"])
    ap.add_argument("--manifest", type=Path, required=True)
    args = ap.parse_args(argv)
    q = pd.read_csv(args.manifest)
    print(json.dumps(extract(q[["sha256", "path"]])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
