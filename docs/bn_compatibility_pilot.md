# BN v2 compatibility pilot (60 files)

## Purpose

Validate extraction engineering (coverage, MLIL/CFG, latency, cache integrity)—**not** detection accuracy.

## Commands

```powershell
# Auto-start / restart Binary Ninja and wait for MCP (:24642)
.\.venv\Scripts\python.exe -m src.ensure_bn_mcp

.\.venv\Scripts\python.exe -m src.bn_pilot_select --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.bn_compatibility_pilot --config configs/local.yaml

# Resumable small batches (recommended if MCP crashes):
.\scripts\run_pilot_batches.ps1 -BatchSize 4
# Resume after MCP drop: re-run same command (uses bn_pilot_cache/)
.\.venv\Scripts\python.exe -m src.bn_compatibility_pilot --config configs/local.yaml --verify-cache-only
```

## Cohort

| Category | N | Source |
| --- | --- | --- |
| Third-party benign | 25 | Frozen **train** only |
| Windows benign | 5 | Frozen **train** only |
| MalwareBazaar | 30 | Frozen **train** only |

Manifest: `artifacts/manifests/bn_pilot_60.parquet`

## Acceptance (engineering targets ≥90%)

See `artifacts/evaluations/bn_compatibility_pilot.json` → `acceptance`.

## After pilot

| `pilot_pass` | Action |
| --- | --- |
| true | Scale v2 extraction on frozen cohort; keep split assignments |
| false | Fix extractor/category failures before large MCP run |

## Imphash grouping

Frozen splits use imphash for malware `group_id` when available. This reduces exact-duplicate leakage but **does not** guarantee family cohesion. Document for the final paper; consider family/time metadata if available.
