"""Parse Binary Ninja GUI MCP markdown tool responses."""

from __future__ import annotations

import re
from typing import Any


def parse_markdown_table(text: str) -> list[dict[str, str]]:
    if not text or "|" not in text:
        return []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("|")]
    if len(lines) < 2:
        return []
    headers = [h.strip() for h in lines[0].split("|")[1:-1]]
    rows: list[dict[str, str]] = []
    for ln in lines[2:]:
        if ln.replace("|", "").replace("-", "").replace(" ", "") == "":
            continue
        cells = [c.strip() for c in ln.split("|")[1:-1]]
        if len(cells) != len(headers):
            continue
        rows.append(dict(zip(headers, cells)))
    return rows


def parse_fenced_body(text: str, fence: str = "mlil") -> str:
    pat = re.compile(rf"```+{re.escape(fence)}\s*\n(.*)", re.DOTALL | re.IGNORECASE)
    m = pat.search(text)
    if not m:
        return ""
    body = m.group(1)
    body = re.sub(r"```+\s*$", "", body, flags=re.DOTALL)
    return body.strip()


def parse_outgoing_edge_count(cell: str) -> int:
    if not cell or not cell.strip():
        return 0
    parts = re.split(r"<br\s*/?>", cell, flags=re.I)
    n = 0
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if re.search(r"(TrueBranch|FalseBranch|UnconditionalBranch|IndirectBranch|Switch)", p, re.I):
            n += 1
    return n


def parse_basic_block_rows(text: str) -> list[dict[str, Any]]:
    rows = parse_markdown_table(text)
    out: list[dict[str, Any]] = []
    for r in rows:
        outgoing = r.get("Outgoing Edges") or r.get("Outgoing edges") or ""
        incoming = r.get("Incoming Edges") or r.get("Incoming edges") or ""
        flags = r.get("Flags") or ""
        out.append(
            {
                "index": r.get("Index"),
                "range": r.get("Range"),
                "flags": flags,
                "outgoing_edges": parse_outgoing_edge_count(outgoing),
                "incoming_edges": parse_outgoing_edge_count(incoming),
                "has_back_edge": "back-edge" in outgoing.lower() or "back-edge" in incoming.lower(),
                "branch_outgoing": bool(re.search(r"TrueBranch|FalseBranch", outgoing, re.I)),
            }
        )
    return out


def parse_complexity_metrics(text: str) -> dict[str, int | None]:
    rows = parse_markdown_table(text)
    out: dict[str, int | None] = {}
    key_map = {
        "Blocks": "blocks",
        "Edges": "edges",
        "Calls": "calls",
        "Variables": "variables",
        "Total Bytes": "total_bytes",
        "MLIL SSA Edge Count": "mlil_ssa_edge_count",
    }
    for r in rows:
        metric = r.get("Metric") or r.get("metric")
        val = r.get("Value") or r.get("value")
        if metric not in key_map:
            continue
        try:
            out[key_map[metric]] = int(str(val).strip())
        except ValueError:
            out[key_map[metric]] = None
    return out


def parse_function_list_addresses(text: str) -> list[str]:
    rows = parse_markdown_table(text)
    addrs: list[str] = []
    for r in rows:
        for key in ("Function", "function", "Start", "Address", "address"):
            if key in r and r[key]:
                addrs.append(r[key].strip())
                break
    if addrs:
        return addrs
    for m in re.finditer(r"\b(0x[0-9a-fA-F]+)\b", text):
        addrs.append(m.group(1))
    return list(dict.fromkeys(addrs))


MLIL_ADDR_LINE = re.compile(r"^(0x[0-9a-fA-F]+)\s+(.*)$")


def parse_mlil_instruction_lines(mlil_body: str) -> list[str]:
    lines: list[str] = []
    for raw in mlil_body.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = MLIL_ADDR_LINE.match(line)
        if m:
            lines.append(m.group(2).strip())
        elif line.startswith("if ") or line.startswith("return "):
            lines.append(line)
    return lines
