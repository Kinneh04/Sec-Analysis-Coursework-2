# SA2 V3 Preregistration: PE-Only Detection Improvement

**Registered:** 2026-11-01, before any V3 model fitting.
**Scope:** Static PE features only for the primary model. Binary Ninja features appear only in one fixed ablation arm.
**Data used for selection:** Frozen V1 `train` split (group-aware inner folds). The frozen V1 `val` split is used once as a development gate. The frozen V1 `test` split is not used in V3.

## 1. Feature sets (fixed)

| Name | Columns | Role |
|------|---------|------|
| `pe_v1` | 274 V1 PE columns, including 256 hashed import buckets | Baseline |
| `pe_v3` | 2,104 `pe3_*` columns (byte and byte-entropy histograms, strings, headers, sections, hashed imports/exports, resources, overlay), timestamp excluded | Primary |
| `pe_v3_bn` | `pe_v3` plus 45 authorized BN columns | Ablation only |

`pe3_hdr_timestamp` is excluded because it is a build-date and source proxy (train-only leakage report: `artifacts/v3/leakage/leakage_report.json`).

## 2. Model grid (19 configurations, selected on `pe_v3` only)

| Family | Grid | Count |
|--------|------|-------|
| LightGBM | `num_leaves` {15, 31, 63} x `min_child_samples` {5, 20} x `feature_fraction` {0.3, 0.7}; `learning_rate` 0.05; up to 1,000 trees with early stopping (50 rounds) on the inner holdout | 12 |
| Random Forest | `max_features` {sqrt, 0.1, 0.3} x `min_samples_leaf` {1, 3}; 500 trees; `class_weight` balanced_subsample; median imputation | 6 |
| Ensemble | Mean of the probabilities of the best LightGBM and best Random Forest | 1 |

No configuration outside this table is scored. The selected configuration is then applied unchanged to `pe_v1` and `pe_v3_bn` for the feature-set ablation.

## 3. Selection protocol

- Outer: `GroupKFold(5)` on `train` by `group_id`.
- Inner: within each outer training fold, a group-aware 80/20 split. The model is fit on the inner 80%. The inner 20% provides LightGBM early stopping and the decision threshold.
- Threshold rule: the highest-TPR threshold with FPR of 2% or less on the inner 20%.
- Objective: mean outer-fold TPR at that fixed threshold. Ties (within 0.005) are broken by mean outer-fold ROC-AUC.
- Fixed seed 42. All fold scores are saved.

## 4. Development gate (validation, used once)

Fit the selected configuration on `train` with the same inner 80/20 rule, then score `val` once for each feature set. Report:
- TPR and FPR at the fixed threshold
- Oracle TPR at 1% FPR (secondary, optimistic)
- ROC-AUC, PR-AUC, Brier score
- Paired group bootstrap of TPR difference against `pe_v1`

The validation result does not change the selected configuration or feature set.

## 5. Decision rules

- **Development:** `pe_v3` is carried forward if its validation fixed-threshold TPR exceeds `pe_v1` with FPR no higher. Otherwise `pe_v1` is carried forward. Either outcome is reported.
- **Confirmatory (blind cohort only):** claim improvement only if the TPR gain over the retrained PE baseline is at least 2 percentage points, the group-bootstrap 95% CI lower bound is above 0, and achieved FPR is no higher than the baseline's.

## Erratum (2026-11-01, after the search)

The `pe_v3` count in Section 1 was misstated. The correct count is 2,105 `pe3_*` columns (2,106 including the excluded timestamp). No column selection was changed.

## Amendment A1 (2026-11-01, registered after the validation gate, before any blind data)

**Reason:** The inner 20% holdout contained 19 benign training rows. "FPR of 2% or less" therefore meant zero false positives on 19 files. All three validation arms exceeded the target (FPR 6.7–11.2%). This amendment was informed by validation results, so validation is no longer independent for any threshold comparison.

**Rule:**
- Thresholds come from pooled out-of-fold scores over the whole `train` split (`GroupKFold(5)` by `group_id`, 286 benign rows), at the operational target of 1% FPR.
- The final LightGBM model is refit on all of `train` with `n_estimators` equal to the median out-of-fold early-stopping iteration.
- Model configuration and feature sets are unchanged.

**Use:**
- A1 results on validation are descriptive only.
- The blind cohort compares `pe_v3` (candidate) with `pe_v1` (baseline), both retrained under A1, using the Section 5 confirmatory rule.

## 6. Non-claims

Development and validation numbers are not confirmatory. No SOTA or EMBER comparison is implied.
