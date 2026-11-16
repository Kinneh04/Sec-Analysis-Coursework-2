# BN v2 feature dictionary (`bn_v2_structured_il`)

## Transport
- **Source:** Binary Ninja GUI MCP (`mcp_structured`)
- **CFG:** `bn_function_basic_blocks` markdown tables
- **MLIL:** `bn_function_il` with `level=mlil` (text lines, paginated)
- **Not used for training:** paths, labels, `bn_source`, raw IL text, `feature_missing_reasons_json`

## Coverage / quality
| Column | Meaning |
| --- | --- |
| `bn_func_count_discovered` | Triage/list function count |
| `bn_func_count_analyzed` | Functions in deterministic hash subset |
| `quality_func_analyzed_ratio` | analyzed / discovered |
| `quality_il_function_ratio` | functions with MLIL / analyzed |
| `bn_il_ops_total` | Sum of classified MLIL line operations |

## CFG (aggregated)
| Column | Meaning |
| --- | --- |
| `bn_cfg_blocks_sum` | Sum of basic blocks across analyzed functions |
| `bn_cfg_edges_sum` | Sum of outgoing edges parsed from MCP tables |
| `bn_cfg_cyclomatic_mean` / `p90` | Per-function E−N+2P from block graphs |
| `bn_cfg_backedge_count` | Blocks with back-edges in MCP edge text |
| `bn_cfg_branch_block_count` | Blocks with True/False branch outgoing |

## MLIL families (counts + rates)
Prefix `bn_mlil_*_count` and `bn_mlil_*_rate` (rate = count / `bn_il_ops_total`).

Families: `call`, `tailcall`, `branch_cond`, `return`, `load`, `store`, `arith`, `bitwise`, `compare`, `other`.

## Metadata (audit only)
`analysis_status`, `analysis_duration_seconds`, `architecture`, `extractor_version`, `bn_meta_*` triage counts.
