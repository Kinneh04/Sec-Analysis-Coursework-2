# Semantic Feature Fusion for Static PE Malware Classification (SA2)

Research prototype aligned with `plan.md`: read-only inventory, conventional PE features, Binary Ninja structural features (GUI MCP triage + optional labeler JSON cache), three classifiers, ablations, and held-out evaluation.

## Environment

- **Python:** use the project venv (Python 3.10). System Python 3.15 crashes on `import pandas`.
- **Binary Ninja:** Personal license — **headless** `binaryninja.load()` fails with `License is not valid`; keep Binary Ninja **GUI open** and use MCP at `http://127.0.0.1:24642/mcp` (see `src/bn_mcp.py`).
- **Corpus:** MalwareBazaar extracts under `E:\MalwareBazaar\extracted`; benign PE from licensed Windows components (`configs/local.yaml`).

```powershell
cd C:\Users\user\Downloads\SA2
py -3.10 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

## Commands

```powershell
.\.venv\Scripts\python.exe -m src.inventory --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.pe_features --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.bn_features --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.build_dataset --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.train --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.evaluate --config configs/local.yaml
# Full PE cohort (all inventoried samples, PE-only models):
.\.venv\Scripts\python.exe -m src.train --config configs/local.yaml --split-prefix pe_all_ --output-suffix _full
.\.venv\Scripts\python.exe -m src.evaluate --config configs/local.yaml --split-prefix pe_all_ --output-suffix _full --results-name test_results_pe_full.csv
```

Artifacts: `artifacts/manifests/`, `artifacts/features/`, `artifacts/splits/`, `artifacts/models/`, `artifacts/evaluations/`.

## Quick run (v2 pilot complete)

```powershell
.\.venv\Scripts\python.exe -m src.run_m4_m8 --config configs/local.yaml --skip-bn-extract
streamlit run src/dashboard.py
```

See `docs/conclusions.md`, `docs/user_manual.md`, `docs/feature_dictionary_v2.md`.

## Latest empirical results (this machine)

| Cohort | Test size | LightGBM PE ROC-AUC | LightGBM PE TPR@1% FPR | LightGBM PE+BN vs PE (BN-matched only) |
|--------|-----------|---------------------|-------------------------|----------------------------------------|
| BN-matched (PE+BN ablation) | 19 | 1.000 | 1.000 | PE+BN **worse** (−0.11 TPR@1% FPR on test) |
| Full PE inventory | 88 | 0.999 | 0.957 | N/A (BN on subset only) |

**SOTA / EMBER2024:** Literature reference (~0.999 ROC-AUC, ~0.98 TPR@1% FPR) is stored in `artifacts/evaluations/sota_comparison*.json` for context only. This corpus, label policy, and feature pipeline were **not** reproduced on EMBER binaries — **do not claim published SOTA superiority**.

**Hypothesis H1 (PE+BN beats PE on matched samples):** **Not supported** on the current BN-matched test split; PE-only LightGBM matched or exceeded PE+BN.

## fix.md progress (M0–M1 complete)

- **M0:** v1 artifacts frozen in `artifacts/baseline_v1/`.
- **M1:** MCP tool discovery + probes → `artifacts/evaluations/mcp_capability_v1.json`, report `docs/m1_capability_report.md`.
- **Verified path:** GUI MCP hybrid — CFG tables + MLIL text (`bn_v2_structured_il`). Run: `python -m src.bn_features --extractor v2 --fixture C:\Windows\System32\notepad.exe` (GUI open). **M4+ ablation/retrain not run yet** at scale.
- **Tests:** `.\.venv\Scripts\python.exe -m pytest tests/test_bn_mcp_protocol.py`

## Blockers logged

1. Headless BN API blocked on Personal license — MCP via running GUI is the supported path.
2. BN throughput ~10–30 s/sample — scale `experiment.max_bn_mcp_benign` for larger matched cohorts.
3. Benign System32 vs MalwareBazaar malware is highly separable on PE features; use harder benign sources and low-detection challenge sets for coursework narrative.

## Dashboard + EDR (SA2 Scan / SA2 Sentinel)

- `dashboard.setup.bat`: VT-style uploader + admin panel on http://127.0.0.1:8000 (frozen V3.2 models, static only). The console prints the admin password and EDR API key.
- `edr.setup.bat`: on-machine EDR agent + console on http://127.0.0.1:8001. Connect it under **Settings** (dashboard URL + API key → Test connection → Save). Default mode uploads only allowlisted files.

Both scripts create `.venv` and install `requirements.txt` on first run. Details, smoke-test results and limits: `dashboard_edr_plan.md` §9.
