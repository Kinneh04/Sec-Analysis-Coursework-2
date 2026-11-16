from __future__ import annotations

import json

from src.bn_mcp import parse_tool_result


def test_parse_json_tool_result():
    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": json.dumps({"functionCount": 3})}]},
    }
    r = parse_tool_result(rpc)
    assert r.ok
    assert r.data["functionCount"] == 3


def test_parse_tool_is_error():
    rpc = {
        "result": {"isError": True, "content": [{"text": "bad function address"}]},
    }
    r = parse_tool_result(rpc)
    assert not r.ok
    assert "bad function" in (r.error or "")


def test_parse_jsonrpc_error():
    rpc = {"error": {"code": -32600, "message": "Invalid Request"}}
    r = parse_tool_result(rpc)
    assert not r.ok


def test_parse_markdown_meta():
    text = "---\ntool: bn_function_il\nlevel: mlil\ncount: 6\n---\n````mlil\nx = 1\n````"
    rpc = {"result": {"content": [{"text": text}]}}
    r = parse_tool_result(rpc)
    assert r.ok
    assert isinstance(r.data, dict)
    assert r.data.get("level") == "mlil"
