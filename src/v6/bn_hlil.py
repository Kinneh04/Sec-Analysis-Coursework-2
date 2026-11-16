"""Binary Ninja full-analysis HLIL indicators (static analysis only).

Requires Binary Ninja `analysis.mode` = full. For every non-library function (name `sub_*`;
functions named by signatures or symbols count as library code), largest first within a time budget,
the HLIL text is parsed for:
  - GetProcAddress / LdrGetProcedureAddress calls with constant API names (dynamic resolution);
  - results of resolution stored to globals (function-pointer tables);
  - LoadLibrary / GetModuleHandle module names;
  - strings materialized on the stack (`__builtin_strcpy` / `__builtin_memcpy` / `__builtin_strncpy`);
  - known API calls and the string literals passed to them.
Per-function summaries are cached in artifacts/v6/hlil_cache/<sha>.json.

  python -m src.v6.bn_hlil extract --manifest artifacts/v6/manifests/gate_queue.csv
"""

from __future__ import annotations

import argparse
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from pathlib import Path
from typing import Any

import pandas as pd

from src.bn_mcp import BnMcpClient
from src.common.hashing import sha256_file
from src.ensure_bn_mcp import ensure_bn_mcp, reboot_bn_mcp
from src.v4.bn_extract import MAX_BYTES, MCP_URL, SKIP_PATH_CONTAINS, FileTimeout, _md, _paged
from src.v6.bn_capabilities import ALL_KNOWN, API_GROUPS, RULES, SENSITIVE, STRING_GROUPS, _groups, norm_api
from src.v6.unpack import prepare

EXTRACTOR_VERSION = "bn_hlil_v6b"
CACHE_DIR = Path("artifacts/v6/hlil_cache")
ANALYSIS_TIMEOUT = 180
HLIL_BUDGET_S = 150
FILE_TIMEOUT = 480
MAX_FUNCS = 5000
MAX_LINES = 1000

HLIL_LINE_RE = re.compile(r"^0x[0-9a-f]+\s+(.*)$", re.IGNORECASE)
CALL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_@]*)\(")
STR_LIT_RE = re.compile(r'u?"((?:[^"\\]|\\.){2,200})"')
RESOLVE_RE = re.compile(r"(GetProcAddress|LdrGetProcedureAddress)\(([^,]*),\s*(.*)\)")
LOADLIB_RE = re.compile(r"(LoadLibrary\w*|GetModuleHandle\w*|LdrLoadDll)\(")
BUILTIN_RE = re.compile(r"__builtin_(?:strcpy|memcpy|strncpy|wcscpy|memset)\([^,]*,\s*(?:\w+:\s*)?u?\"((?:[^\"\\]|\\.)*)\"")
GLOBAL_STORE_RE = re.compile(r"^\*?\(?data_[0-9a-f]+\)?\s*=\s*(?:\([^)]*\))?\s*(GetProcAddress|LdrGetProcedureAddress)\(")
API_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{3,60}$")


def summarize_hlil(text: str) -> dict[str, Any]:
    calls: set[str] = set()
    resolved: list[str] = []
    s: dict[str, Any] = {"n_lines": 0, "gpa_const": 0, "gpa_nonconst": 0, "gpa_global_store": 0, "loadlib": 0}
    modules: list[str] = []
    stack_strings: list[str] = []
    call_strings: list[str] = []
    for raw in text.splitlines():
        m = HLIL_LINE_RE.match(raw.strip())
        if not m:
            continue
        line = m.group(1)
        s["n_lines"] += 1
        names = [norm_api(n) for n in CALL_RE.findall(line)]
        known = [n for n in names if n in ALL_KNOWN]
        calls.update(known)
        lits = STR_LIT_RE.findall(line)
        if known and lits:
            call_strings.extend(x[:120] for x in lits)
        r = RESOLVE_RE.search(line)
        if r:
            lit = STR_LIT_RE.search(r.group(3))
            if lit and API_NAME_RE.match(lit.group(1)):
                s["gpa_const"] += 1
                resolved.append(norm_api(lit.group(1)))
            else:
                s["gpa_nonconst"] += 1
            if GLOBAL_STORE_RE.search(line):
                s["gpa_global_store"] += 1
        if LOADLIB_RE.search(line):
            s["loadlib"] += 1
            modules.extend(x.lower()[:60] for x in lits)
        stack_strings.extend(x[:120] for x in BUILTIN_RE.findall(line))
    return {"calls": sorted(calls), "resolved": sorted(set(resolved)), "modules": sorted(set(modules)),
            "stack_strings": stack_strings[:40], "call_strings": list(dict.fromkeys(call_strings))[:40], "ind": s}


def _run_analysis(client: BnMcpClient) -> bool:
    pool = ThreadPoolExecutor(max_workers=1)
    fut = pool.submit(client.call_tool, "bn_analysis_update_and_wait", {})
    try:
        fut.result(timeout=ANALYSIS_TIMEOUT)
        return True
    except FuturesTimeout:
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
        return False
    finally:
        pool.shutdown(wait=False)


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
        t0 = time.time()
        doc["analysis_complete"] = _run_analysis(client)
        doc["analysis_seconds"] = round(time.time() - t0, 2)
        funcs, doc["function_total"] = _paged(client, "bn_function_list", MAX_FUNCS)
        user = [f for f in funcs if f.get("name", "").startswith("sub_")]
        doc["n_library_named"] = len(funcs) - len(user)
        doc["n_sub"] = len(user)
        user.sort(key=lambda f: int(f.get("basicBlockCount", "0") or 0), reverse=True)
        t1 = time.time()
        doc["functions"] = []
        unavailable = attempted = 0
        for f in user:
            if time.time() - t1 > HLIL_BUDGET_S:
                break
            attempted += 1
            try:
                txt = _md(client.call_tool("bn_function_il", {"function": f["function"], "level": "hlil", "limit": MAX_LINES}))
            except RuntimeError:
                unavailable += 1
                continue
            s = summarize_hlil(txt)
            if s["calls"] or s["resolved"] or s["stack_strings"] or s["ind"]["gpa_nonconst"] or s["ind"]["loadlib"]:
                s["addr"] = f["function"]
                doc["functions"].append(s)
        doc["functions_attempted"] = attempted
        doc["hlil_unavailable"] = unavailable
        doc["hlil_seconds"] = round(time.time() - t1, 2)
        doc["hlil_complete"] = attempted == len(user)
        doc["analysis_status"] = "ok" if doc["analysis_complete"] and doc["hlil_complete"] else "partial"
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
    print(f"BN hlil v6b: {len(queue) - len(todo)} cached, {len(todo)} to analyze", flush=True)
    counts: dict[str, int] = {}
    for i, r in enumerate(todo, 1):
        path, t0 = Path(r.path), time.time()
        try:
            size = path.stat().st_size
        except OSError:
            size = -1
        prep: list[str] = []
        if size < 0:
            doc = {"analysis_status": "error", "errors": ["path_missing"]}
        elif any(frag in str(path).lower() for frag in SKIP_PATH_CONTAINS):
            doc = {"analysis_status": "skipped"}
        elif sha256_file(path) != r.sha256:
            doc = {"analysis_status": "error", "errors": ["sha_mismatch"]}
        elif (target_prep := prepare(path, r.sha256, MAX_BYTES))[1] == ["too_large"]:
            doc = {"analysis_status": "skipped", "errors": [f"size_{size}_image_over_{MAX_BYTES}"]}
        else:
            target, prep = target_prep
            pool = ThreadPoolExecutor(max_workers=1)
            fut = pool.submit(analyze, client, target)
            try:
                doc = fut.result(timeout=FILE_TIMEOUT)
            except (FuturesTimeout, FileTimeout) as e:
                doc = {"analysis_status": "error", "errors": [f"timeout:{type(e).__name__}"]}
                print(f"  timeout on {r.sha256[:12]}; rebooting Binary Ninja", flush=True)
                reboot_bn_mcp(MCP_URL)
                client = BnMcpClient(MCP_URL)
                client.connect()
            except Exception as e:
                print(f"  error on {r.sha256[:12]}: {type(e).__name__}: {str(e)[:200]}; rebooting", flush=True)
                try:
                    reboot_bn_mcp(MCP_URL)
                    client = BnMcpClient(MCP_URL)
                    client.connect()
                except Exception:
                    pass
                continue
            finally:
                pool.shutdown(wait=False)
        doc.update({"sha256": r.sha256, "prep": prep, "extractor_version": EXTRACTOR_VERSION, "wall_seconds": round(time.time() - t0, 2)})
        tmp = CACHE_DIR / f"{r.sha256}.json.tmp"
        tmp.write_text(json.dumps(doc), encoding="utf-8")
        tmp.replace(CACHE_DIR / f"{r.sha256}.json")
        counts[doc["analysis_status"]] = counts.get(doc["analysis_status"], 0) + 1
        if i % 10 == 0 or doc["analysis_status"] not in ("ok", "partial"):
            print(f"  {i}/{len(todo)} {counts} last {doc['wall_seconds']}s", flush=True)
    return counts


def features_from_doc(doc: dict[str, Any]) -> dict[str, float]:
    if doc.get("analysis_status") not in ("ok", "partial"):
        return {}
    funcs = doc.get("functions") or []
    total = float(doc.get("function_total") or 0)
    f: dict[str, float] = {"hl6_frac_library_named": (doc.get("n_library_named") or 0) / max(1.0, total),
                           "hl6_n_sub": float(doc.get("n_sub") or 0)}
    ind: dict[str, float] = {}
    resolved: set[str] = set()
    modules: set[str] = set()
    stack: list[str] = []
    rule_funcs = {k: 0 for k in RULES}
    for fn in funcs:
        for k, v in (fn.get("ind") or {}).items():
            ind[k] = ind.get(k, 0.0) + float(v)
        res = set(fn.get("resolved") or [])
        resolved |= res
        modules |= set(fn.get("modules") or [])
        stack.extend(fn.get("stack_strings") or [])
        strings = (fn.get("call_strings") or []) + (fn.get("stack_strings") or [])
        stack_apis = {norm_api(x) for x in fn.get("stack_strings") or [] if API_NAME_RE.match(x)} & ALL_KNOWN
        g = _groups(set(fn.get("calls") or []), strings, (res & ALL_KNOWN) | stack_apis, bool(res) or (fn.get("ind") or {}).get("gpa_nonconst", 0) > 0)
        for k, rule in RULES.items():
            if rule(g):
                rule_funcs[k] += 1
    for k in ("gpa_const", "gpa_nonconst", "gpa_global_store", "loadlib"):
        f[f"hl6_{k}"] = ind.get(k, 0.0)
    f["hl6_n_resolved"] = float(len(resolved))
    f["hl6_n_resolved_sensitive"] = float(len(resolved & SENSITIVE))
    for grp, apis in API_GROUPS.items():
        f[f"hl6_resolved_{grp}"] = float(len(resolved & apis))
    f["hl6_n_modules_loaded"] = float(len(modules))
    f["hl6_n_stack_strings"] = float(len(stack))
    stack_apis = {norm_api(x) for x in stack if API_NAME_RE.match(x)}
    f["hl6_stack_api_names"] = float(len(stack_apis & ALL_KNOWN))
    f["hl6_stack_dll_names"] = float(sum(1 for x in stack if x.lower().endswith(".dll")))
    for k, rx in STRING_GROUPS.items():
        f[f"hl6_stack_{k}"] = float(sum(1 for x in stack if rx.search(x)))
    for k, v in rule_funcs.items():
        f[f"hl6_{k}"] = float(v)
    f["hl6_n_rules_fired"] = float(sum(v > 0 for v in rule_funcs.values()))
    return f


def build(shas: list[str]) -> pd.DataFrame:
    rows = []
    for sha in shas:
        p = CACHE_DIR / f"{sha}.json"
        doc = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {"analysis_status": "missing"}
        rows.append({"sha256": sha, "hl6_status": doc.get("analysis_status", "missing"), **features_from_doc(doc)})
    return pd.DataFrame(rows)


def hl6_columns(df: pd.DataFrame) -> list[str]:
    return sorted(c for c in df.columns if c.startswith("hl6_") and c != "hl6_status")


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
