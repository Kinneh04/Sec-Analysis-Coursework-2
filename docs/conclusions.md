# Conclusions (evidence-based, fix.md M8)

## Hypothesis H1 — PE + BN beats PE-only (v2 structured BN, matched cohort n=50, test n=9)

**Not supported** on the primary LightGBM comparator (small test; model collapsed to majority class). **Random Forest / Logistic Regression** on the same split show **perfect or near-perfect ROC-AUC** for PE, BN-only, and PE+BN — the cohort remains **too small and too easy** to show a reliable BN gain.

- `artifacts/evaluations/sota_comparison_v2.json`: LightGBM PE vs PE+BN **delta TPR@1% FPR = 0**.
- No claim of **EMBER2024 SOTA** (not reproduced on matched binaries).

## Measurement integrity (M1–M3)

- v2 uses MCP **CFG tables + MLIL text** (`bn_v2_structured_il`), not HLIL regex (`legacy_hlil_regex_*` in v1).
- Pilot coverage: `artifacts/evaluations/bn_coverage_v2.json` — 50 samples, 25/25 class balance, 44 ok / 6 partial.

## Challenge POCs (M6, qualitative)

Held out from training (`challenge_sha256.txt`). **Random Forest PE+BN** (`random_forest__pe_bn_v2`):

| Sample | Prediction | Score |
| --- | --- | --- |
| Sample1/client.exe | malicious | 0.675 |
| Sample2/out/loader.exe | benign (FN) | 0.585 |
| Sample2/out/helper.dll | benign (FN) | 0.490 |
| Sample2/out/exec.dll | benign (FN) | 0.375 |

Structured BN **did not fully recover** low-detection tradecraft samples; one POC detected, three missed.

## Full PE cohort (793 samples, separate from BN-matched ablation)

LightGBM PE-only on full test (n=145): high separability (System32 vs MalwareBazaar) — see `artifacts/evaluations/test_results_pe_full.csv`. **Not comparable** to published SOTA.

## BN compatibility pilot (60 files, train holdout)

**Complete:** `artifacts/evaluations/bn_compatibility_pilot.json` — `pilot_pass=true` (engineering ≥90% targets on extraction, MLIL, CFG, cache integrity). Proceed to frozen-cohort v2 extraction when ready.

## Recommended next steps (if extending coursework)

See **`docs/next_experiment_plan.md`** for the full runbook. In short:

1. Target **~500 matched** v2 BN rows, **harder benign** (third-party install dirs + `benign_max_per_root`).
2. **Paired PE vs PE+BN** with bootstrap CIs (`python -m src.paired_eval`); pilot test n=9 yields `insufficient_n`.
3. **Qualitative vs quantitative** challenge manifests; do not treat related POCs as generalization proof.
4. **`python -m src.investigate_fn --mcp`** on Sample2 FNs before attributing misses to BN vs model.
5. SOTA comparison remains **optional** after one larger controlled experiment.
