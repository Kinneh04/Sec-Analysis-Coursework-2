# M1 — Binary Ninja GUI MCP capability report

**Date:** 2026-10-31 (UTC)  
**Fixture:** `C:\Windows\System32\notepad.exe` (known benign; static open only)  
**Endpoint:** `http://127.0.0.1:24642/mcp`  
**License:** Binary Ninja Personal (headless Python API not validated)

## M0 baseline

Prior v1 artifacts frozen under `artifacts/baseline_v1/` with `baseline_v1_manifest.json` (102 BN feature rows, 24 columns including mislabeled `mlil_*` regex features).

## Tool discovery

Run:

```powershell
.\.venv\Scripts\python.exe -m src.m1_mcp_discovery --config configs/local.yaml
```

Output: `artifacts/evaluations/mcp_capability_v1.json` (tool list + probe results).

### Verified tools for structured static analysis

| Tool | Structured output | Use in v2 |
| --- | --- | --- |
| `bn_function_list` | Paginated function list (markdown/meta) | Function discovery |
| `bn_function_basic_blocks` | Block index, ranges, incoming/outgoing edge labels | **Real CFG** aggregation |
| `bn_function_complexity` | Blocks, edges, calls, bytes (table) | Cyclomatic cross-check |
| `bn_function_il` | `level=mlil`, **`form=text` only** | Parse MLIL **line text** (not HLIL regex) |
| `bn_function_callees` | Callsite/callee listing | Call/target ratios |
| `bn_binary_view_triage` | Sample-level counts (not IL) | Metadata `bn_meta_*` only |

## Verified extraction path (M1 exit)

**`mcp_structured_hybrid`** — no retrain or bulk scan yet:

1. Open binary via `bn_open_item_open`; activate recommended PE view; `bn_analysis_update_and_wait`.
2. Enumerate functions (`bn_function_list`) with deterministic hash-based subset policy (M2).
3. Per function: `bn_function_basic_blocks` + `bn_function_complexity` for CFG metrics.
4. Per function: `bn_function_il` with `level=mlil` — paginate with `offset`/`limit` until `truncated=false`.
5. Aggregate operation-family counts by parsing MLIL text tokens (M2 schema), **not** HLIL cache regex.

### Blockers / limitations

- MCP does **not** expose MLIL as typed JSON objects; only text IL lines.
- Triage counts alone are **not** evidence of IL recovery (v1 mistake).
- Personal license: pipeline must keep GUI running; GUI-side exporter remains fallback if MCP transport fails.
- v1 `bn_features.py` remains for historical comparison; do not treat `mlil_*` columns as true MLIL.

## Manual spot-check (notepad `wWinMain` @ `0x1400101d8`)

- `bn_function_basic_blocks`: **38** blocks with labeled branch edges (including back-edges).
- `bn_function_complexity`: Blocks **38**, Edges **0** (tool metric definition differs from edge-table count — document in M2).
- `bn_function_il` (mlil): paginated text (e.g. `if (cond:0) then …`, assignments, calls).

## Next gate (M2 — not started here)

Implement `bn_v2_structured_il` schema, remove regex-as-MLIL from training path, add fixture tests and small balanced pilot before scaling.
