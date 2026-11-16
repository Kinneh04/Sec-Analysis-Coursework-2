# SA2 V2 Preregistration (locked before Week 2 development)

**Status:** Registered prior to V2 model/policy fitting.  
**Date:** 2026-11-01  
**Mode:** Developmental until an independent blind cohort is frozen and evaluated once.

## Research arms

| Arm | Description |
|-----|-------------|
| B0 | PE-only baseline (separate PE model, validation-selected threshold rule) |
| B1 | Naive PE+BN (full authorized feature set; historical comparator) |
| V2-A | Coverage-aware fusion with PE-only fallback |
| V2-B | Uncertainty-aware review on B0 and/or V2-A calibrated probabilities |
| V2-C | Optional PE-first selective BN (pre-BN signals only) |

## Permitted coverage signals (V2-A gating only)

Label-independent fields only:

- `quality_func_analyzed_ratio`
- `quality_il_function_ratio`
- `quality_il_instruction_coverage`
- `bn_il_ops_total`, `bn_il_functions_with_mlil` (derived ops/function ratio)
- Composite `eligibility_score` as defined in `src/v2/quality.py`

**Prohibited for gating or prediction:** `analysis_status`, error strings, source roots, paths, labels, SHA, imphash, group_id, split.

Zero IL operations are treated as **low/unknown coverage** (fallback to PE), not evidence of benign behavior.

## Configuration grid (finite budget)

Selection budget: **12** scored cells per outer development evaluation (see `configs/v2_experiment.yaml`).

### V2-A fusion grid

| Parameter | Values |
|-----------|--------|
| Eligibility threshold | Train-fold quantiles: **0.25, 0.50, 0.75** of `eligibility_score` |
| Interpolation weight on PE+BN calibrated prob | **0.25, 0.50, 0.75** (when eligible; else weight 0 → PE-only) |

Deterministic rule: if `eligibility_score >= threshold`,  
`p_final = (1 - w) * p_pe_cal + w * p_pebn_cal`; else `p_final = p_pe_cal`.

### V2-B review grid (one family)

Near-threshold band on **calibrated** `p_final`:

| Parameter | Values |
|-----------|--------|
| Band half-width (probability units) | **0.05, 0.10** |
| Optional disagreement trigger | `\|p_pe_cal - p_pebn_cal\| >= 0.15` (only when BN eligible) |

Reviewed samples are **undecided** for primary detection metrics; selective metrics reported separately.

## Models

- Random Forest and LightGBM (primary), Logistic Regression (transparent comparator).
- Same imputation policy as V1 (`SimpleImputer` median).
- Calibration: `CalibratedClassifierCV` with **sigmoid**, fit on inner-train only; assessment on inner-val within group CV.

## Development protocol

- **Group-aware** `GroupKFold` on original **train** split (`group_id`), 5 folds.
- Original **validation** split: single final development gate after inner-CV selection (acknowledged as non-blind).
- **No use** of V1 frozen **test** labels or scores for selection.
- Qualitative POC hashes in `challenge_qualitative_sha256.txt` excluded from all fitting and selection.

## Primary development objective

Maximize **validation malware TPR** subject to **achieved benign FPR ≤ 0.02** using thresholds fit on train-calibration subsets only. Report ROC-AUC and Brier. Do not claim operational 1% FPR when benign count does not support it (validation benign n≈89 → ~1.12% per false positive).

## Blind evaluation (Week 3+)

Required for confirmatory H1 claim. Freeze `artifacts/v2/blind/protocol_frozen.json` before any blind scoring. No arm selection after blind results.

## Explicit non-claims

- No SOTA or EMBER2024 superiority without benchmark-aligned evaluation.
- V1 frozen-test numbers (~0.926 PE vs ~0.884 PE+BN RF TPR@~1% FPR) are **historical context only**.
