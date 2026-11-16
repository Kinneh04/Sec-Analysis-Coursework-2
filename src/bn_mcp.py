"""Binary Ninja GUI MCP client (HTTP). Personal license: headless API fails; MCP via running GUI works."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ToolResult:
    ok: bool
    data: Any
    error: str | None
    raw: dict[str, Any]


def parse_tool_result(rpc: dict[str, Any]) -> ToolResult:
    if not rpc:
        return ToolResult(ok=False, data=None, error="empty_rpc_response", raw={})
    if "error" in rpc:
        return ToolResult(ok=False, data=None, error=str(rpc["error"]), raw=rpc)
    result = rpc.get("result") or {}
    if result.get("isError"):
        content = result.get("content") or []
        msg = content[0].get("text", "tool_error") if content else "tool_error"
        return ToolResult(ok=False, data=None, error=msg, raw=rpc)
    content = result.get("content") or []
    if not content:
        return ToolResult(ok=True, data=None, error=None, raw=rpc)
    texts = [c.get("text", "") for c in content if isinstance(c, dict)]
    combined = "\n".join(t for t in texts if t)
    if not combined:
        return ToolResult(ok=True, data=None, error=None, raw=rpc)
    stripped = combined.lstrip()
    if stripped.startswith("{"):
        try:
            return ToolResult(ok=True, data=json.loads(stripped), error=None, raw=rpc)
        except json.JSONDecodeError:
            pass
    meta = _parse_markdown_meta(combined)
    if meta:
        meta["_raw_markdown"] = combined
        return ToolResult(ok=True, data=meta, error=None, raw=rpc)
    return ToolResult(ok=True, data=combined, error=None, raw=rpc)


def _parse_markdown_meta(text: str) -> dict[str, Any] | None:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    meta: dict[str, Any] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" in line:
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return meta or None


def _parse_sse_json(raw: str) -> dict:
    for line in raw.splitlines():
        if line.startswith("data:"):
            payload = line[5:].strip()
            if payload:
                return json.loads(payload)
    return {"error": {"message": "unparseable_sse_response"}}


class BnMcpClient:
    url: str
    token: str
    session_id: str | None
    _req_id: int

    def __init__(self, url: str, token: str = "") -> None:
        self.url = url
        self.token = token
        self.session_id = None
        self._req_id = 0

    def _headers(self) -> dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def _post(self, payload: dict) -> dict:
        self._req_id += 1
        if "id" not in payload and payload.get("method") != "notifications/initialized":
            payload = {**payload, "id": self._req_id}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                if not self.session_id:
                    self.session_id = resp.headers.get("Mcp-Session-Id") or resp.headers.get(
                        "mcp-session-id"
                    )
                raw = resp.read().decode("utf-8", errors="replace").strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return {"error": {"code": e.code, "message": body[:2000]}}
        except urllib.error.URLError as e:
            return {"error": {"message": str(e)}}
        if not raw:
            return {}
        if raw.startswith("event:"):
            return _parse_sse_json(raw)
        return json.loads(raw)

    def connect(self) -> None:
        res = self._post(
            {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "sa2-malware-ml", "version": "0.2"},
                },
                "id": 1,
            }
        )
        if "error" in res:
            raise RuntimeError(res["error"])
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def list_tools(self) -> list[dict[str, Any]]:
        res = self._post({"jsonrpc": "2.0", "method": "tools/list", "params": {}})
        if "error" in res:
            raise RuntimeError(res["error"])
        return (res.get("result") or {}).get("tools") or []

    def call_tool_raw(self, name: str, arguments: dict | None = None) -> dict[str, Any]:
        return self._post(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )

    def call_tool(self, name: str, arguments: dict | None = None) -> Any:
        parsed = parse_tool_result(self.call_tool_raw(name, arguments))
        if not parsed.ok:
            raise RuntimeError(f"{name}: {parsed.error}")
        return parsed.data

    def close_item(self, handle: str) -> None:
        try:
            self.call_tool("bn_open_item_close", {"openItem": handle})
        except Exception:
            pass


def extract_triage_via_mcp(
    sample_path: Path,
    sha256: str,
    mcp_url: str | None = None,
    close_after: bool = True,
) -> dict[str, Any]:
    """Legacy v1 triage-only export (superseded by M2 structured path in fix.md)."""
    url = mcp_url or os.environ.get("BN_MCP_URL", "http://127.0.0.1:24642/mcp")
    path = sample_path.resolve().as_posix()
    client = BnMcpClient(url=url)
    client.connect()
    open_item_handle = None
    out: dict[str, Any] = {
        "sha256": sha256,
        "source": "binaryninja_mcp_triage",
        "arch": "",
        "triage": {},
        "functions": [],
        "bn_error": None,
    }
    try:
        opened = client.call_tool("bn_open_item_open", {"path": path, "setActive": True})
        if not isinstance(opened, dict):
            raise RuntimeError("open returned no data")
        oi = opened.get("openItem") or {}
        open_item_handle = oi.get("handle")
        views = opened.get("binaryViews") or []
        bv = None
        for v in views:
            if v.get("recommended") or v.get("active"):
                bv = v.get("handle")
                out["arch"] = v.get("architecture", "")
                break
        if not bv and views:
            bv = views[0].get("handle")
            out["arch"] = views[0].get("architecture", "")
        if bv:
            client.call_tool("bn_binary_view_set_active", {"binaryView": bv})
        client.call_tool("bn_analysis_update_and_wait", {})
        triage = client.call_tool("bn_binary_view_triage", {})
        if isinstance(triage, dict):
            out["triage"] = {
                k: triage.get(k)
                for k in (
                    "functionCount",
                    "segmentCount",
                    "sectionCount",
                    "symbolCount",
                    "stringCount",
                    "dataVariableCount",
                    "entryPoint",
                )
            }
            bv_meta = triage.get("binaryView") or {}
            if not out["arch"]:
                out["arch"] = bv_meta.get("architecture", "")
    except Exception as e:
        out["bn_error"] = str(e)[:2000]
    finally:
        if close_after and open_item_handle:
            client.close_item(open_item_handle)
    return out
