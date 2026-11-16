# SA2 V3 Operator Guide

Static PE scoring using the **frozen V3.2** candidate model (`pe_v3`). Files are parsed with pefile only; nothing is executed.

## Quick start

```powershell
cd C:\Users\user\Downloads\SA2
.\.venv\Scripts\python.exe -m src.v3.score C:\path\to\sample.exe
```

Recursive directory scan:

```powershell
.\.venv\Scripts\python.exe -m src.v3.score --recursive C:\Suspicious\Folder
```

JSON lines output:

```powershell
.\.venv\Scripts\python.exe -m src.v3.score --recursive C:\Suspicious --output artifacts\scores.jsonl --summary
```

## Output fields

| Field | Meaning |
|------|------|
| `pe_v3_probability` | Candidate model score (0–1) |
| `pe_v3_threshold` | Frozen train-calibrated threshold (0.894 for V3.2) |
| `pe_v3_flagged` | `true` if probability ≥ threshold |
| `pe_v1s_*` | V1-equivalent baseline (same LightGBM config, 274 features) |
| `flagged` | Same as `pe_v3_flagged` (recommended arm) |

## Verify model integrity

```powershell
.\.venv\Scripts\python.exe -m src.v3.freeze --verify --cohort-tag v3.2
```

## Blind review export (false positives / false negatives)

```powershell
.\.venv\Scripts\python.exe -m src.v3.export_review --cohort-tag v3.2
```

Writes `artifacts/v3.2/blind/analyst_review.csv`.

## Temporal generalization check (2026+ MalwareBazaar, frozen model)

```powershell
.\.venv\Scripts\python.exe -m src.v3.temporal_eval --model-tag v3.2 --min-date 2026-01-01
```

Results: `artifacts/v3.3/temporal_eval/temporal_eval.json`. This does **not** retrain; it measures whether V3.2 thresholds transfer to newer malware batches.

## Evidence summary

| Evaluation | Result |
|------|------|
| V3.2 preregistered blind | TPR **73.8%** vs baseline **59.7%** at **0.63% FPR** (158 benign); rule **passed** — see `docs/v3.2_results.md` |
| V3 / V3.1 | Did not meet the same rule |

## Deployment calibration (benign gold set)

If your environment’s benign files differ from training (expected), estimate a new threshold **without retraining**:

```powershell
.\.venv\Scripts\python.exe -m src.v3.calibrate_deploy --benign-dir D:\GoldImages\CleanPE --recursive --target-fpr 0.01 --output artifacts\deploy\calibration.json
```

Use `recommended_threshold` when interpreting `pe_v3_probability` (compare manually or patch into a wrapper). The frozen pickle threshold remains unchanged for audit reproducibility.

## Recalibration warning

The V3.2 blind evaluation used 158 benign files (0.63% FPR). A 2026 temporal holdout with 246 unique benign files gave 1.63% FPR (4 false positives, all SPICE Guest Tools `WdfCoInstaller` DLLs) and 91.1% TPR on 2026 malware (`docs/temporal_eval_2026.md`). Before production use, set the threshold on benign data that matches your deployment environment:

```powershell
# Development-only: replay threshold search on an expanded pool (see src/v3/tune.py)
.\.venv\Scripts\python.exe -m src.v3.tune --cohort-tag v3.2
```

## Limits

- Trained on MalwareBazaar + local Windows/vendor PE inventory; not a global ground truth.
- Shortcuts, non-PE files, and packed samples may score incorrectly.
- Do not treat `flagged` as definitive malware; use as triage prior to sandbox or vendor verdict.
- Optional integrity check (fails after `src/v3/` code changes): add `--verify-freeze`.
