# SA2 V4 Preregistration: Binary Ninja vs the EMBER2024 Benchmark Detector

**Registered:** 2026-11-01. The V4 blind cohort was frozen before this document was written. No model in this document had been fitted with Binary Ninja V4 features at registration time, and no V4 blind label had been read.

## 1. Question

Does a detector that uses Binary Ninja static-analysis features detect more Windows PE malware than the EMBER2024 benchmark detector at a fixed, training-derived threshold, without a higher false positive rate?

EMBER2024's own test set cannot answer this question with Binary Ninja features. It contains feature vectors only, not the binaries Binary Ninja would need to analyze. The comparison is therefore run head-to-head on binaries held locally.

## 2. Data

| Set | Content |
|------|------|
| Training pool | Frozen V1 `train` plus `new_train` from cohorts v3, v3.1 and v3.2: 5,238 rows (3,162 benign, 2,076 malicious) |
| Binary Ninja training subset | Stratified sample of 1,399 pool rows (by label and origin, seed 20261105), listed in `artifacts/v4/manifests/bn_queue.csv` (role `train`) |
| V4 blind cohort | 566 files (331 benign, 235 malicious, 498 groups), frozen in `artifacts/v4/manifests/` |

- **Blind benign** files come from Windows locations not sampled in any earlier wave: WinSxS, Microsoft.NET, SystemApps, the .NET assembly cache, ProgramData and per-user program folders. At most 2 files were taken per directory.
- **Blind malicious** files come from MalwareBazaar batches dated 2026-01-01 or later. This is after the EMBER2024 collection period, so the pretrained reference is unlikely to have seen them.
- Any file whose SHA-256, directory group or imphash appeared in V1, v3, v3.1, v3.2 or the 2026 temporal check was excluded from blind.

## 3. Arms

| Arm | Description | Training rows |
|------|------|------|
| **R1** | Official pretrained `EMBER2024_PE.model` (thrember, EMBER v3 features) | None (pretrained) |
| **R2** | EMBER v3 features, LightGBM retrained on our pool with the EMBER2024 recipe (500 rounds, 64 leaves, `min_child_samples` 100, learning rate 0.05) | Full pool (5,238) |
| **C1** | LightGBM on EMBER v3 + Binary Ninja V4 features | Binary Ninja subset rows with status `ok` or `partial` |
| **C2** | LightGBM stacker on the R1 logit score + Binary Ninja V4 features | Same as C1 |

The candidate is **C1 or C2**, selected by Section 5. Only the selected candidate enters the confirmatory decision. The other is reported descriptively.

## 4. Binary Ninja V4 features (`bn4_*`)

Computed from `artifacts/v4/bn_cache/<sha256>.json` by `src/v4/bn_features.py`:

- **Whole-binary counts:** functions, strings, imports, symbols, segments, sections, data variables, image span, analysis completed.
- **Function statistics:** basic-block mean, median, 90th percentile, maximum and sum; function size mean, 90th percentile, maximum and sum; fraction of `sub_` (unnamed) functions, auto-discovered, exported and single-block functions; code coverage (function bytes divided by image span).
- **Top 32 functions by basic blocks:** mean and maximum of blocks, edges, calls, variables, bytes, MLIL SSA edges and cyclomatic complexity (edges − blocks + 2).
- **Call graph:** callsites; fractions resolving to imports, internal functions and unresolved (indirect) targets; distinct imported APIs actually called; called-to-imported ratio.
- **Hashed called APIs:** 256 MD5 buckets of `dll!function` names reached from callsites (log1p counts).
- **Hashed named functions:** 128 MD5 buckets of non-`sub_` function names (Binary Ninja signature and symbol matches).
- **Strings:** counts by type, UTF-16 fraction, length mean and maximum, and keyword counts (`http`, `.exe`, `.dll`, `cmd`, `powershell`, `hkey`, `\\`).

Files skipped by policy (over 16 MB or known Binary Ninja hang paths) or with failed analysis have all `bn4_*` features missing. They are excluded from candidate training and scored at blind time with missing Binary Ninja features. Coverage is reported.

## 5. Candidate selection (training data only)

1. `GroupKFold(5)` by `group_id` on the Binary Ninja training subset.
2. Both C1 and C2 use LightGBM with `num_leaves` 15, `min_child_samples` 20, `feature_fraction` 0.7, learning rate 0.05, `class_weight` balanced, and early stopping on a group-aware inner 20% split.
3. **Selection metric:** pooled out-of-fold TPR at the threshold that gives 1% FPR on pooled out-of-fold scores. Ties within 0.005 are broken by out-of-fold ROC-AUC.
4. The selected candidate is refit on all subset rows with the median early-stopping iteration count.

## 6. Thresholds (fixed before blind)

All arms use one rule: the threshold that gives 1% FPR on training-derived scores.
- **C1, C2, R2:** pooled out-of-fold scores on their own training rows.
- **R1:** its scores on the full training pool. R1 was never fit on our pool, so these scores are not in-sample.

## 7. Confirmatory decision rule

The candidate beats EMBER2024 only if, against **both** R1 and R2:
- TPR at the frozen threshold is higher, with the paired group-bootstrap 95% CI lower bound of the TPR difference above 0 (2,000 replicates over blind groups, seed 42), and
- candidate FPR at the frozen threshold is no higher than the reference FPR.

Otherwise the result is reported as not beating EMBER2024.

## 8. Secondary (descriptive only)

- TPR at matched 0.5% and 1% blind FPR.
- ROC-AUC and PR-AUC.
- Results on blind rows with and without Binary Ninja coverage.
- Errors by malware file type and benign source.

## Amendment A1 (2026-11-01, before any model was fitted with Binary Ninja features)

**Reason:** A training-only check of R2 showed pooled out-of-fold ROC-AUC 0.9975 and TPR 0.942 at 0.98% FPR on the full 5,238-row pool. Restricting C1 and C2 to the 1,399-row Binary Ninja subset would confound the comparison with a fourfold difference in training size. No Binary Ninja feature had been used in any model fit when this amendment was written.

**Changes:**
- **Training rows:** C1 and C2 train on the full pool, the same rows as R2. Rows outside the Binary Ninja subset have all `bn4_*` features missing. The subset was stratified by label and origin, so missingness is not label-informative by construction.
- **Selection metric:** pooled out-of-fold TPR at the 1% FPR threshold, computed on the full pool (Section 5, ties by ROC-AUC). Out-of-fold metrics restricted to Binary Ninja subset rows are reported alongside, so the contribution of Binary Ninja features is visible.
- **Unchanged:** thresholds (Section 6) and the decision rule (Section 7).

## Amendment A2 (2026-11-01, extraction limits, before any model fit)

To bound extraction time, every file (training and blind alike) is analyzed with the same limits:
- 60-second analysis timeout, followed by `bn_analysis_abort` and a `partial` status.
- At most 5,000 functions and 3,000 strings are listed. Whole-binary counts still come from triage.
- 180-second per-file limit, after which Binary Ninja is restarted and the file is recorded as an error.

Cached files that these limits would have changed (21 files) were deleted and re-extracted, so all files share identical settings.

## Amendment A3 (2026-11-01, analysis mode, before any model fit)

A timing probe found Binary Ninja's `analysis.mode` set to `intermediate` was 2.2–3.5 times faster than `full`. Function counts and complexity on two test binaries were nearly identical, but the MLIL SSA edge count was sometimes unavailable. All files are analyzed in `intermediate` mode with linear sweep on (default). Unavailable metrics are stored as missing, not zero. The cache was cleared, and every file, including those extracted earlier, is analyzed under this setting.

## 9. Known biases

- **Favouring R1:** benign Windows system files are common on VirusTotal and may be in EMBER2024's training data.
- **Favouring our arms:** the training pool and blind cohort share local sources (MalwareBazaar and this Windows installation).
- **Limits on any claim:** no claim is made about EMBER2024's own test set or about SOTA in general.
