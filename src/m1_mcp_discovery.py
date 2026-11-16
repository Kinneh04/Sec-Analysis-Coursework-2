"""M1: enumerate Binary Ninja GUI MCP tools and probe structured CFG/IL capability."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.bn_mcp import BnMcpClient, parse_tool_result
from src.common.config import artifacts, load_config


CAPABILITY_TOOLS = (
    "bn_function_list",
    "bn_function_basic_blocks",
    "bn_function_il",
    "bn_function_complexity",
    "bn_function_callees",
    "bn_binary_view_triage",
)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def discover(url: str, fixture: Path) -> dict[str, Any]:
    client = BnMcpClient(url=url)
    client.connect()
    out: dict[str, Any] = {
        "discovered_at_utc": datetime.now(timezone.utc).isoformat(),
        "mcp_url": url,
        "fixture_path": str(fixture),
        "fixture_sha256": _sha256_file(fixture) if fixture.is_file() else None,
        "tools": [],
        "probes": {},
        "verified_extraction_path": None,
        "blockers": [],
    }
    try:
        listed = client.list_tools()
        out["tools"] = [
            {"name": t.get("name"), "description": (t.get("description") or "")[:500]}
            for t in listed
        ]
        tool_names = {t["name"] for t in out["tools"] if t.get("name")}

        missing = [t for t in CAPABILITY_TOOLS if t not in tool_names]
        if missing:
            out["blockers"].append(f"Missing expected tools: {missing}")

        opened = parse_tool_result(
            client.call_tool_raw("bn_open_item_open", {"path": fixture.as_posix(), "setActive": True})
        )
        out["probes"]["open"] = {"ok": opened.ok, "error": opened.error, "payload_keys": list((opened.data or {}).keys())}
        if not opened.ok:
            out["blockers"].append(f"Could not open fixture: {opened.error}")
            return out

        oi = (opened.data or {}).get("openItem") or {}
        open_handle = oi.get("handle")
        views = (opened.data or {}).get("binaryViews") or []
        bv = next((v for v in views if v.get("recommended") or v.get("active")), views[0] if views else None)
        if bv and bv.get("handle"):
            client.call_tool_raw("bn_binary_view_set_active", {"binaryView": bv["handle"]})

        client.call_tool_raw("bn_analysis_update_and_wait", {})

        triage = parse_tool_result(client.call_tool_raw("bn_binary_view_triage", {}))
        out["probes"]["triage"] = {"ok": triage.ok, "error": triage.error}
        entry = None
        if triage.ok and isinstance(triage.data, dict):
            entry = triage.data.get("entryPoint")

        fl = parse_tool_result(client.call_tool_raw("bn_function_list", {"limit": 5}))
        out["probes"]["function_list"] = {"ok": fl.ok, "error": fl.error}
        func_addr = entry
        if fl.ok and isinstance(fl.data, dict):
            items = fl.data.get("functions") or fl.data.get("items") or []
            if items and not func_addr:
                func_addr = items[0].get("function") or items[0].get("address")
        if not func_addr:
            func_addr = "0x1400101d8"

        for tool, extra in (
            ("bn_function_basic_blocks", {"function": func_addr, "limit": 20}),
            ("bn_function_il", {"function": func_addr, "level": "mlil", "limit": 50}),
            ("bn_function_complexity", {"function": func_addr}),
            ("bn_function_callees", {"function": func_addr, "limit": 20}),
        ):
            if tool not in tool_names:
                continue
            res = parse_tool_result(client.call_tool_raw(tool, extra))
            sample = res.data
            if isinstance(sample, str):
                sample = sample[:2000]
            out["probes"][tool] = {
                "ok": res.ok,
                "error": res.error,
                "is_structured_json": isinstance(res.data, dict),
                "sample": sample,
            }

        il_probe = out["probes"].get("bn_function_il") or {}
        bb_probe = out["probes"].get("bn_function_basic_blocks") or {}
        if bb_probe.get("ok") and il_probe.get("ok"):
            out["verified_extraction_path"] = (
                "mcp_structured_hybrid: bn_function_basic_blocks (block/edge tables) + "
                "bn_function_complexity (metrics) + bn_function_il level=mlil (text IL lines; "
                "M2 must parse MLIL operation tokens from IL text — not HLIL regex). "
                "No JSON MLIL object export exposed; form=text only."
            )
        elif bb_probe.get("ok"):
            out["verified_extraction_path"] = "mcp_partial: CFG tables only; IL probe failed"
        else:
            out["blockers"].append("Structured CFG/IL probe did not succeed on fixture")

        if open_handle:
            client.call_tool_raw("bn_open_item_close", {"openItem": open_handle})
    finally:
        pass
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="M1 MCP capability discovery (fix.md)")
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--fixture", default=r"C:\Windows\System32\notepad.exe")
    ap.add_argument("--url", default=None)
    args = ap.parse_args()
    cfg = load_config(args.config)
    url = args.url or cfg.get("analysis", {}).get("bn_mcp_url", "http://127.0.0.1:24642/mcp")
    fixture = Path(args.fixture)
    report = discover(url, fixture)
    out_dir = artifacts(cfg) / "evaluations"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "mcp_capability_v1.json"
    out_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {out_path}")
    print("verified_extraction_path:", report.get("verified_extraction_path"))
    if report.get("blockers"):
        print("blockers:", report["blockers"])


if __name__ == "__main__":
    main()
