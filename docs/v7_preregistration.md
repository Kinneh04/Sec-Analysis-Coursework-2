# V7 Preregistration: Binary Ninja Capability and HLIL Features Against EMBER2024

This document was written before the V7 blind cohort was sampled and before any V7 blind file was analyzed. It was not to be edited after the freeze, except through dated amendments appended at the end.

## Background

V6 and V6b (`docs/v6_results.md`) failed their development gates. The strongest development result was a stacker over the EMBER2024 logit plus V6 capability features (`cap6_*`) and V6b HLIL features (`hl6_*`). Across 10 seeds it gained a median of +10 true positives over EMBER2024 at 1% FPR, on a gate set enriched with EMBER2024-missed malware. V7 tested this candidate family once, on a fresh blind cohort with natural class composition. The cohort was smaller than ideal (a user-approved compromise of about 2 to 3 days of extraction), so V7 had limited statistical power. A negative or inconclusive result was an expected outcome and would be reported as such.

## Data

### Training pool

- The V4 training pool (`load_pool(include_v1_train=True, cohorts=train_cohorts_for_tag("v3.2"))`, 5,238 files), joined with EMBER v3 features.
- Added: the 632 V6 gate files (consumed V3.2 blind, 2026 temporal check and V4 blind cohorts). These files were used only for training and threshold setting in V7, never for evaluation.
- **Binary Ninja features:** `cap6_*` (`bn_cap_v6`, intermediate analysis) and `hl6_*` (`bn_hlil_v6b`, full analysis) for:
  - the V6 gate files,
  - a random sample of 700 additional pool files (seed 20261104, sampled without regard to any model score).
- Elsewhere, Binary Ninja features were missing (NaN), following V4 amendment A1.

### Blind cohort (`src/v7/cohort.py`, seed 20261104)

- **Benign:** files from the V4 benign roots (WinSxS, Microsoft.NET, SystemApps, the .NET assembly cache, ProgramData, per-user program folders, diagnostics), at most 2 files per directory.
- **Malicious:** files from 2026 MalwareBazaar batches.
- **Exclusions:** any file sharing a SHA-256, directory group or imphash with V1, V3, V3.1, V3.2, V4, the 2026 temporal check or the V6 gate set.
- **Target size:** up to 450 benign and 450 malicious files. The cohort was frozen (inventory and split hashes) before feature extraction.

## Arms

- **R1:** the official pretrained `EMBER2024_PE.model` on EMBER v3 features. The threshold was set at 1% FPR on the training pool.
- **R2:** the EMBER2024 LightGBM recipe (500 rounds, 64 leaves, min_data_in_leaf 100, categorical columns [2,3,4,5,6,701,702]) retrained on the V7 training pool. The threshold was set at 1% FPR on pooled 5-fold `GroupKFold` out-of-fold scores.
- **Candidate:** a LightGBM model (`lgbm__num_leaves-15_min_child_samples-20_feature_fraction-0.7`, seed 42), selected between two variants on training data only:
  - C7a: `r1_logit` + `cap6_*` + `hl6_*`
  - C7b: `r1_logit` + `cap6_*`

  The selection rule was the higher pooled group-CV out-of-fold TPR at 1% FPR. Variants within 0.005 of each other were treated as tied, and ties went to the higher out-of-fold ROC-AUC. The threshold was set at 1% FPR on pooled group-CV out-of-fold scores.

## Static Preparation

- Files over 16 MB had their overlay stripped when the PE image fit within 16 MB.
- UPX files were unpacked with `upx -d`.
- No sample code was executed.
- Analysis modes matched V6 and V6b: intermediate analysis for `cap6_*`, and full analysis for `hl6_*`.

## Decision Rule (Primary, One Shot)

The candidate beat EMBER2024 only if, on the full V7 blind cohort, at the frozen thresholds, both of the following held for each reference (R1 and R2):
1. the paired group-bootstrap 95% CI lower bound for (candidate TPR minus reference TPR) was above 0, and
2. the candidate FPR was no higher than the reference FPR.

Secondary results were descriptive only and could not change the decision:
- results within the ordinary-native stratum,
- results on files with Binary Ninja coverage,
- TPR at matched FPR.

## Limitations Known in Advance

- EMBER2024's own test and challenge sets could not be used, because they do not include binaries.
- The blind cohort was smaller than needed to detect gains of the size seen in development with high power.
- Binary Ninja ran through the GUI MCP server under a personal license, with per-file time budgets. Files that timed out had missing features.
