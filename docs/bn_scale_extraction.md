# Scaled BN v2 extraction (frozen cohort)

## Configuration (`experiment.bn_scale`)

| Parameter | Default |
| --- | --- |
| `batch_size` | 25 |
| `daily_budget_seconds` | 7200 (2h) |
| `max_retries` | 2 per failed binary |
| `per_binary_timeout_seconds` | 120 |

Cache: `artifacts/features/bn_v2_cache/`  
Progress: `artifacts/evaluations/bn_scale_progress.json`  
Coverage: `artifacts/evaluations/bn_coverage_v2.json`

## Daily run

```powershell
.\scripts\run_scale_daily.ps1
```

Or manually:

```powershell
.\.venv\Scripts\python.exe -m src.ensure_bn_mcp
.\.venv\Scripts\python.exe -m src.bn_scale_extract --config configs/local.yaml
```

Re-run daily until `pending_queue` in coverage reaches 0. **Partial / unsupported / error** samples stay in cache for bias analysis.

## Monitor

- `monitoring.extraction_success_rate.benign` vs `.malicious` (watch malware ≪ benign)
- `median_il_ops` per class
- `by_label_status` counts (`ok`, `partial`, `error`, `missing`)

## After extraction complete

```powershell
.\.venv\Scripts\python.exe -m src.build_dataset --bn-version v2
.\.venv\Scripts\python.exe -m src.train --output-suffix _v2
.\.venv\Scripts\python.exe -m src.evaluate --output-suffix _v2
.\.venv\Scripts\python.exe -m src.paired_eval --config configs/local.yaml
```

Models: LR, RF, LightGBM × PE / BN / PE+BN on **frozen splits** only. No test-set threshold tuning.

Report: TPR@1% FPR with bootstrap CIs; latency vs paired delta.
