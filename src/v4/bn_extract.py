"""Binary Ninja whole-binary feature extraction over the GUI MCP server (static analysis only).

Raw per-file results are cached as JSON (artifacts/v4/bn_cache/<sha>.json) so features can be
rebuilt without re-analysis.

  python -m src.v4.bn_extract --manifest artifacts/v4/manifests/bn_queue.csv
"""

from __future__ import annotations

import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from pathlib import Path
from typing import Any

import pandas as pd

from src.bn_mcp import BnMcpClient
from src.common.hashing import sha256_file
from src.ensure_bn_mcp import ensure_bn_mcp, reboot_bn_mcp

EXTRACTOR_VERSION = "bn_v4"
CACHE_DIR = Path("artifacts/v4/bn_cache")
MCP_URL = "http://127.0.0.1:24642/mcp"
TOP_K_FUNCS = 32
MAX_FUNCS = 5000
MAX_STRINGS = 3000
PAGE = 2000
MAX_BYTES = 16 * 1024 * 1024
ANALYSIS_TIMEOUT = 60
FILE_TIMEOUT = 180
# Binary Ninja hangs on these .NET reference/analyzer assemblies (same policy as the V1 pipeline).
SKIP_PATH_CONTAINS = ("analyzers\\dotnet", "\\packs\\microsoft.netcore.app.ref\\")


class FileTimeout(RuntimeError):
    pass


def parse_table(markdown: str) -> list[dict[str, str]]:
    """Parse the first Markdown table in an MCP tool response."""
    rows: list[dict[str, str]] = []
    header: list[str] | None = None
    for line in markdown.splitlines():
        s = line.strip()
        if not (s.startswith("|") and s.endswith("|")):
            if header is not None and rows:
                break
            continue
        cells = [c.strip() for c in s[1:-1].split(" | ")]
        if header is None:
            header = cells
            continue
        if all(set(c) <= {"-", " "} for c in cells):
            continue
        if len(cells) == len(header):
            rows.append(dict(zip(header, cells)))
    return rows


def _md(result: Any) -> str:
    if isinstance(result, dict):
        return str(result.get("_raw_markdown") or "")
    return str(result or "")


def _paged(client: BnMcpClient, tool: str, cap: int, extra: dict | None = None) -> tuple[list[dict[str, str]], int]:
    out: list[dict[str, str]] = []
    offset, total = 0, 0
    while len(out) < cap:
        r = client.call_tool(tool, {"offset": offset, "limit": min(PAGE, cap - len(out)), **(extra or {})})
        total = int(str(r.get("total", 0)).strip('"') or 0) if isinstance(r, dict) else 0
        rows = parse_table(_md(r))
        out.extend(rows)
        nxt = r.get("nextOffset") if isinstance(r, dict) else None
        if not rows or nxt in (None, "null", "", "None"):
            break
        offset = int(str(nxt).strip('"'))
    return out, total


def _int(x: str) -> int:
    try:
        return int(x, 0)
    except (TypeError, ValueError):
        return 0


def analyze(client: BnMcpClient, path: Path) -> dict[str, Any]:
    doc: dict[str, Any] = {}
    opened = client.call_tool("bn_open_item_open", {"path": path.resolve().as_posix(), "setActive": True})
    handle = (opened.get("openItem") or {}).get("handle")
    try:
        views = opened.get("binaryViews") or []
        bv = next((v for v in views if v.get("recommended")), None) or next((v for v in views if v.get("viewType") != "Raw"), None)
        if bv is None:
            return {"analysis_status": "unsupported", "errors": ["no_binary_view"]}
        client.call_tool("bn_binary_view_set_active", {"binaryView": bv["handle"]})
        t0 = time.time()
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
        doc["analysis_seconds"] = round(time.time() - t0, 2)
        tri = client.call_tool("bn_binary_view_triage", {})
        bvm = tri.get("binaryView") or {}
        doc["view_type"] = bvm.get("viewType")
        doc["arch"] = bvm.get("architecture")
        doc["image_span"] = _int(bvm.get("end", "0")) - _int(bvm.get("start", "0"))
        for k in ("functionCount", "segmentCount", "sectionCount", "symbolCount", "stringCount", "dataVariableCount"):
            doc[k] = tri.get(k)

        funcs, doc["function_total"] = _paged(client, "bn_function_list", MAX_FUNCS)
        doc["functions"] = [
            {
                "addr": f.get("function"),
                "name": f.get("name", ""),
                "bb": _int(f.get("basicBlockCount", "0")),
                "size": max(0, _int(f.get("highestAddress", "0")) - _int(f.get("lowestAddress", "0")) + 1),
                "exported": f.get("exported") == "true",
                "auto": f.get("autoDiscovered") == "true",
            }
            for f in funcs
        ]
        strings, doc["string_total"] = _paged(client, "bn_string_list", MAX_STRINGS, {"previewBytes": 48})
        doc["strings"] = [{"type": s.get("type", ""), "len": _int(s.get("length", "0")), "text": s.get("previewEscaped", "")[:48]} for s in strings]
        imports, doc["import_total"] = _paged(client, "bn_import_list", 5000)
        imp_by_addr = {i.get("symbol"): f"{i.get('namespace', '')}!{i.get('name', '')}".lower() for i in imports}
        doc["imports"] = sorted(set(imp_by_addr.values()))

        top = sorted(doc["functions"], key=lambda f: f["bb"], reverse=True)[:TOP_K_FUNCS]
        doc["top_functions"] = []
        for f in top:
            entry: dict[str, Any] = {"addr": f["addr"], "bb": f["bb"]}
            cx = {r["Metric"]: r["Value"] for r in parse_table(_md(client.call_tool("bn_function_complexity", {"function": f["addr"]})))}
            entry["complexity"] = {k: (_int(v) if v not in ("null", "") else None) for k, v in cx.items()}
            callee_rows, _ = _paged(client, "bn_function_callees", 2000, {"function": f["addr"]})
            callees = []
            for r in callee_rows:
                fn = r.get("Callee Functions", "").split(" (")[0]
                addr = r.get("Callee Address", "")
                if fn:
                    callees.append(("func", fn))
                elif addr in imp_by_addr:
                    callees.append(("import", imp_by_addr[addr]))
                else:
                    callees.append(("unresolved", ""))
            entry["callees"] = callees
            doc["top_functions"].append(entry)
        doc["analysis_status"] = "ok" if doc.get("analysis_complete") else "partial"
        return doc
    finally:
        if handle:
            client.close_item(handle)


def _cache_path(sha: str) -> Path:
    return CACHE_DIR / f"{sha}.json"


def run(queue: pd.DataFrame, *, max_files: int | None = None) -> dict[str, int]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    ensure_bn_mcp(MCP_URL)
    client = BnMcpClient(MCP_URL)
    client.connect()
    todo = [r for r in queue.itertuples(index=False) if not _cache_path(r.sha256).is_file()]
    if max_files:
        todo = todo[:max_files]
    print(f"BN v4: {len(queue) - len(todo)} cached, {len(todo)} to analyze", flush=True)
    counts: dict[str, int] = {}
    fail_streak = 0
    for i, r in enumerate(todo, 1):
        path = Path(r.path)
        t0 = time.time()
        doc: dict[str, Any]
        try:
            size = path.stat().st_size
        except OSError:
            size = -1
        if size < 0:
            doc = {"analysis_status": "error", "errors": ["path_missing"]}
        elif size > MAX_BYTES:
            doc = {"analysis_status": "skipped", "errors": [f"size_{size}_over_{MAX_BYTES}"]}
        elif any(frag in str(path).lower() for frag in SKIP_PATH_CONTAINS):
            doc = {"analysis_status": "skipped", "errors": ["path_skip_policy"]}
        elif sha256_file(path) != r.sha256:
            doc = {"analysis_status": "error", "errors": ["sha_mismatch"]}
        else:
            pool = ThreadPoolExecutor(max_workers=1)
            fut = pool.submit(analyze, client, path)
            try:
                doc = fut.result(timeout=FILE_TIMEOUT)
                fail_streak = 0
            except (FuturesTimeout, FileTimeout) as e:
                # Binary Ninja is wedged on this file: record it, restart the GUI, move on.
                doc = {"analysis_status": "error", "errors": [f"timeout:{type(e).__name__}"]}
                print(f"  timeout on {r.sha256[:12]}; rebooting Binary Ninja", flush=True)
                reboot_bn_mcp(MCP_URL)
                client = BnMcpClient(MCP_URL)
                client.connect()
            except Exception as e:
                fail_streak += 1
                doc = {"analysis_status": "error", "errors": [f"{type(e).__name__}: {str(e)[:300]}"]}
                if fail_streak >= 2:
                    print("  MCP failing; rebooting Binary Ninja", flush=True)
                    reboot_bn_mcp(MCP_URL)
                    client = BnMcpClient(MCP_URL)
                    client.connect()
                    fail_streak = 0
                    continue  # retry this file on a later run; do not cache transient failures
            finally:
                pool.shutdown(wait=False)
        doc.update({"sha256": r.sha256, "extractor_version": EXTRACTOR_VERSION, "wall_seconds": round(time.time() - t0, 2)})
        tmp = _cache_path(r.sha256).with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc), encoding="utf-8")
        tmp.replace(_cache_path(r.sha256))
        st = doc["analysis_status"]
        counts[st] = counts.get(st, 0) + 1
        if i % 10 == 0 or st != "ok":
            print(f"  {i}/{len(todo)} {r.sha256[:12]} {st} {doc['wall_seconds']}s {counts}", flush=True)
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", type=Path, required=True, help="CSV/parquet with sha256,path")
    ap.add_argument("--max-files", type=int, default=None)
    args = ap.parse_args(argv)
    q = pd.read_csv(args.manifest) if args.manifest.suffix == ".csv" else pd.read_parquet(args.manifest)
    print(json.dumps(run(q[["sha256", "path"]], max_files=args.max_files)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
