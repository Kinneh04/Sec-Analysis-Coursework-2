# SA2 V3 Results: PE-Only Detection Improvement

**Date:** 2026-11-01
**Outcome:** The preregistered improvement criterion was not met. The expanded PE feature set (PE-v3) detected more malware on the blind cohort than the V1-equivalent baseline, but at a higher false positive rate. No improvement or SOTA claim is made.

## 1. Summary

| Blind cohort, frozen thresholds | TPR (95% Wilson CI) | FPR (95% Wilson CI) | False positives | ROC-AUC | PR-AUC |
|------|------|------|------|------|------|
| Baseline: V1-stable PE (274 features) | 0.773 (0.736–0.806) | 0.51% (0.17–1.48%) | 3 / 592 | 0.984 | 0.984 |
| Candidate: PE-v3 (2,105 features) | 0.827 (0.793–0.856) | 1.69% (0.92–3.08%) | 10 / 592 | 0.987 | 0.986 |

Paired group bootstrap (668 groups, 2,000 replicates), candidate minus baseline:
- TPR difference: +5.4 points (95% CI +1.9 to +9.0)
- FPR difference: +1.2 points (95% CI −0.2 to +3.2)

| Preregistered condition | Result |
|------|------|
| TPR gain of at least 2 points | Met (+5.4) |
| Bootstrap CI lower bound above 0 | Met (+1.9) |
| FPR no higher than baseline | Not met (1.69% vs 0.51%) |
| **Improvement supported** | **No** |

The candidate also exceeded its 1% FPR design target. The baseline stayed below it.

## 2. Blind cohort

- **Sources:** 2,357 previously unused files from the same local sources as V1: MalwareBazaar provenance (malicious) and Windows and vendor install directories (benign). Benign sampling was capped at 40 files per vendor directory. Seed 20261101.
- **Split:** Group-aware split into `new_train` (1,228 rows) and `blind` (1,129 rows: 592 benign, 537 malicious).
  - Any new file whose directory group or imphash appeared anywhere in V1 was forced into `new_train` (906 rows).
  - The blind cohort therefore contained only unseen benign directories and unseen malware imphash families.
- **Disjointness checks at evaluation:** the blind cohort had no SHA-256 or group overlap with the training pool or any V1 split, and no blind PE-v3 feature vector duplicated a training vector.
  - 14 benign blind files shared an imphash with training files.
  - Excluding them did not change either result (candidate FPR 1.73%, baseline 0.52%, TPR unchanged).
- **Limitation:** the cohort came from the same sources as V1. It tested generalization to unseen files and families, not to new sources or later time periods.

## 3. Method

1. **Phase 0 corrections:** restored the 256 import-bucket columns that the allow-list had blocked, fixed V2 review-band selection, and made fixed-threshold TPR and FPR the headline metric (see `SA2_V2_plan.md`, "Correction and re-baseline").
2. **PE-v3 features** (`src/v3/pe_features_v3.py`): byte and byte-entropy histograms, string statistics, headers, sections, hashed imports, DLLs and exports (stable MD5 buckets), resources and overlay. The header timestamp was excluded.
3. **Leakage checks on train:**
   - The label-permutation AUC was 0.48.
   - No single feature had AUC of 0.95 or more.
   - Removing the timestamp did not lower group-CV AUC (0.957 without vs 0.951 with).
   - Among benign files, PE content predicted Windows vs third-party origin with AUC 0.81. This was a corpus confound, not label leakage.
4. **Preregistered search** (`docs/v3_preregistration.md`): 19 configurations under train group-CV. The selected configuration was LightGBM (`num_leaves` 15, `min_child_samples` 20, `feature_fraction` 0.7).
5. **Validation gate:** the preregistered threshold rule did not hold FPR. The inner holdout contained only 19 benign rows. Validation FPR was 6.7% for `pe_v1` and 11.2% for `pe_v3`, so `pe_v1` was carried forward under the development rule.
   - Amendment A1 was registered after validation and before blind data. It set thresholds from pooled out-of-fold training scores at 1% FPR.
   - Validation results under A1 were descriptive only.
6. **Baseline:**
   - V1 hashed imports with Python's salted `hash()`, so V1 bucket columns could not be reproduced for new files.
   - `src/v3/pe_v1_stable.py` reused the 18 V1 scalar features unchanged (identical to V1 on all 676 overlapping rows) and replaced only the bucket hash with MD5.
7. **Retrain:** both arms used the same configuration and rule on V1 train plus `new_train` (1,745 rows, 462 groups). Out-of-fold training TPR at 0.93% FPR was 0.823 (PE-v3) and 0.772 (baseline).
8. **Freeze and blind run:**
   - Models, feature-column hashes, thresholds, preregistration, cohort manifests and `src/v3` code were hashed in `artifacts/v3/freeze/freeze_manifest.json` (no git repository was available).
   - The blind run verified the freeze, checked that the training pool matched, and wrote a run-once lock.

## 4. Error analysis (blind)

**False positives:**
- Candidate:
  - 5 LLVM command-line tools from one directory
  - 3 `WdfCoInstaller` DLLs bundled with SPICE Guest Tools
  - 1 SPICE uninstaller
  - 1 Intel network driver
- Baseline:
  - the same SPICE uninstaller
  - 2 Process Hacker binaries
- Windows OS files produced 1 candidate false positive in 377 files. Third-party files produced 9 in 215.
- False positives clustered by product. The FPR difference CI included 0, but the preregistered rule compared point estimates.

**False negatives (TPR by malware subgroup):**

| Subgroup | n | Candidate TPR | Baseline TPR |
|------|------|------|------|
| PE32 | 390 | 0.897 | 0.859 |
| PE64 | 147 | 0.639 | 0.544 |
| Packed (DIE packer detected) | 85 | 0.988 | 0.929 |
| Not packed | 452 | 0.796 | 0.743 |
| Under 100 KB | 44 | 0.545 | 0.432 |

64-bit and small unpacked samples were the weakest subgroups for both arms. The training pool contained 77 64-bit malicious files against 426 64-bit benign files, so architecture was associated with the benign class.

## 4b. Matched-FPR post-hoc (descriptive)

At fixed thresholds from training, PE-v3 had higher TPR and higher FPR. If thresholds are re-picked on the blind rows so each arm achieves the same FPR (optimistic, not confirmatory), PE-v3 had **lower** TPR than the baseline:

| Blind FPR target | Baseline TPR | PE-v3 TPR | Delta |
|------|------|------|------|
| 0.5% | 0.771 | 0.609 | −0.162 |
| 1.0% | 0.812 | 0.750 | −0.061 |

This indicates that most of the fixed-threshold TPR gain was an operating-point shift, not better low-FPR ranking. V3.1 targets calibration and class balance (see `docs/v3.1_preregistration.md`).

## 5. Interpretation

- **Ranking:** the candidate ranked samples slightly better (ROC-AUC 0.987 vs 0.984) and detected more malware in every subgroup.
- **Operating point:** at the frozen threshold it gave up false-positive control. The result therefore showed a different operating point, not a demonstrated improvement.
- **Threshold control:** small benign calibration sets were the main obstacle to holding 1% FPR throughout V2 and V3.
- **Binary Ninja features:** not evaluated on the blind cohort. New BN extraction was out of scope, and BN features lowered validation detection in every development comparison.

## 6. Possible next steps (not run; would require a new preregistration and a new blind cohort)

- Increase benign training diversity, especially third-party developer tools and driver packages.
- Set thresholds at a stricter training target (for example 0.5%), so blind FPR stays below 1% after the observed shift.
- Add 64-bit and small unpacked malware to training.
- Evaluate on a time-split or new-source cohort to test generalization beyond the V1 sources.

## 7. Artifacts

| Path | Content |
|------|------|
| `artifacts/v3/leakage/` | Leakage report and single-feature AUC |
| `artifacts/v3/development/` | Grid results, search summary, A1 validation summary |
| `artifacts/v3/manifests/` | New cohort labels, inventory, split, freeze record |
| `artifacts/v3/retrain/` | Learning curve, retrain summary |
| `artifacts/v3/freeze/freeze_manifest.json` | Frozen hashes |
| `artifacts/v3/blind/` | Blind results, per-file scores, run lock |
