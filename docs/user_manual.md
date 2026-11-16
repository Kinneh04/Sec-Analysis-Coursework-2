# User manual

## Prerequisites
- Windows, Python 3.10 venv at `.venv`
- Binary Ninja **GUI running** (Personal license; MCP at `http://127.0.0.1:24642/mcp`)
- Malware corpus path in `configs/local.yaml` (read-only)
- **Do not execute** sample binaries

## Setup
```powershell
cd C:\Users\user\Downloads\SA2
py -3.10 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

## Pipeline (full)
```powershell
.\.venv\Scripts\python.exe -m src.inventory --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.pe_features --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.bn_features --extractor v2 --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.build_dataset --config configs/local.yaml --bn-version v2
.\.venv\Scripts\python.exe -m src.train --config configs/local.yaml --output-suffix _v2
.\.venv\Scripts\python.exe -m src.evaluate --config configs/local.yaml --output-suffix _v2 --results-name test_results_v2.csv
.\.venv\Scripts\python.exe -m src.challenge_eval --config configs/local.yaml --run-id random_forest__pe_bn_v2 --mcp-bn
```

Or: `.\.venv\Scripts\python.exe -m src.run_m4_m8 --config configs/local.yaml`

## Tests
```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -q
.\.venv\Scripts\python.exe -m src.m1_mcp_discovery --config configs/local.yaml
```

## Artifacts
| Path | Content |
| --- | --- |
| `artifacts/baseline_v1/` | Frozen v1 baseline |
| `artifacts/features/bn_features_v2.parquet` | v2 BN features |
| `artifacts/evaluations/ablation_v2.json` | 3×3 test metrics |
| `artifacts/evaluations/challenge_v2.json` | POC case study |
| `artifacts/evaluations/bn_coverage_v2.json` | Extraction coverage |

## Known failures
- Headless `binaryninja.load()` fails on Personal license — use GUI MCP.
- System Python 3.15 breaks pandas — use `.venv` only.
- Small BN-matched test sets make LightGBM unstable; interpret RF/LR and challenge results cautiously.
