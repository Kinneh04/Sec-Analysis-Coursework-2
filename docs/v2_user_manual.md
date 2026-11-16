# SA2 V2 User Manual

## Overview

V2 adds **coverage-aware fusion (V2-A)** and **uncertainty-aware review (V2-B)** on top of existing PE/BN features. V1 pipelines, splits, caches, and results are read-only.

## Prerequisites

- Python 3.10, project `.venv`
- Completed V1 features: `artifacts/features/pe_features.parquet`, `bn_features_v2.parquet`
- Week 1 gate: `python -m src.v2.cli inspect --config configs/v2_experiment.yaml`

## Typical workflow

```powershell
cd <path-to-your-clone>   # e.g. cd Sec-Analysis-Coursework-2
.\scripts\run_v2_development.ps1
python -m src.v2.cli freeze --config configs/v2_experiment.yaml
.\scripts\run_v2_blind.ps1
python -m src.v2.cli report --config configs/v2_experiment.yaml
```

## Commands

| Command | Purpose |
|---------|---------|
| `inspect` | Integrity audit, coverage tables, V1 baseline reproduction |
| `develop` | Group-CV fusion selection, validation arms, save V2 models |
| `freeze` | Lock protocol + model hashes before any evaluation |
| `evaluate-blind` | One-shot scoring from manifest (or configured historical test replay) |
| `report` | Markdown summary under `artifacts/v2/reports/` |

## Dashboard

```powershell
.\.venv\Scripts\streamlit run src\dashboard.py
```

Shows V1 test results, V2 validation arms, and blind/replay JSON if present.

## Claims policy

- **Triage (H2):** Supported if selective error drops at reported automation coverage on validation.
- **Detection (H1):** Requires **independent** blind cohort with frozen protocol; historical V1 test replay is **not** confirmatory.
- **SOTA:** Never implied by this repo’s default configs.

## Resetting a blind run (development only)

Delete `artifacts/v2/blind/evaluation_run.lock` only on a dev machine to re-run the pipeline test.
