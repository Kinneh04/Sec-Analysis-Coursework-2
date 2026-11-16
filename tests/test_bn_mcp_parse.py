from __future__ import annotations

from src.bn_mcp_parse import parse_basic_block_rows, parse_mlil_instruction_lines


SAMPLE_BB = """---
count: 2
---

| Index | Range | Flags | Incoming Edges | Outgoing Edges |
| --- | --- | --- | --- | --- |
| 0 | 0x1000-0x1010 |  |  | TrueBranch #1 0x1020 |
| 1 | 0x1020-0x1030 | can-exit | TrueBranch #0 |  |
"""

SAMPLE_MLIL = """```mlil
  int64_t f()

0x1000  foo()
0x1008  if (x) then 1 else 2
```"""


def test_parse_basic_blocks():
    rows = parse_basic_block_rows(SAMPLE_BB)
    assert len(rows) == 2
    assert rows[0]["outgoing_edges"] == 1
    assert rows[0]["branch_outgoing"] is True


def test_parse_mlil_lines():
    lines = parse_mlil_instruction_lines(SAMPLE_MLIL)
    assert lines == ["foo()", "if (x) then 1 else 2"]
