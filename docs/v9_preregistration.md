# V9 Preregistration: Independent Replication of the V8 Blend

This document was written before the V9 cohort was sampled and before any V9 file was analyzed. It was not to be edited after the freeze, except through dated amendments appended at the end.

## Purpose

V8 (`docs/v8_results.md`) met its preregistered rule against the pretrained EMBER2024 PE model (R1) on one cohort of 724 files: +6 malicious detections, 0 losses, and 0 false positives for every arm among 281 benign files.

Robustness analyses (`src/v9/robustness.py`, `artifacts/v9/robustness.json`) were mixed:
- **V8 cohort:**
  - The exact McNemar test on discordant malware gave p = 0.031.
  - The ROC-AUC difference was +0.0028 (95% CI +0.0014 to +0.0044).
  - At the strictest training operating point (0.25% FPR), the candidate lost 17 R1 detections and gained 3.
  - The result was sensitive to the blend weight. w = 0.3 was best on V8, and w of 0.5 or more lost detections.
- **Consumed V7 cohort, frozen V8 model:** the candidate gained 3 detections and added 1 false positive (exact p = 0.25).

V9 tested whether the V8 improvement replicated on an independent cohort with a larger and broader benign set.

## Models (Frozen, Not Refit)

All arms were loaded unchanged from `artifacts/v8/models/`, and their hashes were verified against `artifacts/v8/freeze/freeze_manifest.json`:
- **Candidate:** `logit(R1) + 0.3 * logit(BN model)` on files with both `cap6_*` and `hl6_*` Binary Ninja features, with the frozen blend threshold. Files without coverage used R1's decision.
- **R1:** the pretrained EMBER2024 PE model at its frozen training threshold (0.31491).
- **R2:** EMBER v3 LightGBM retrained on the V7/V8 training pool, at its frozen threshold.

No weight, threshold or feature was changed after V8.

## Cohort (`src/v9/cohort.py`, seed 20261107)

- **Benign:** at most 2 files per directory, drawn from two root families:
  - **Windows component stores:** `C:\Windows\WinSxS`, `C:\Windows\Microsoft.NET`, `C:\Windows\assembly`, `C:\Windows\SystemApps`, `C:\ProgramData`, `%LOCALAPPDATA%\Programs` and `%LOCALAPPDATA%\Microsoft`.
  - **Installed applications and drivers:** `C:\Program Files`, `C:\Program Files (x86)` and `C:\Windows\System32\DriverStore`.
- **Malicious:** files from 2026 MalwareBazaar batches.
- **Exclusions:** any file sharing a SHA-256, path, directory group or imphash with V1, V3, V3.1, V3.2, V4, V7, V8, the 2026 temporal check or the V6 gate set.
- **Target size:** up to 1,000 benign and 600 malicious files. The cohort was frozen before feature extraction.
- **Feature extraction:** the same extractors and analysis modes as V7 and V8 (`bn_cap_v6` in intermediate mode, then `bn_hlil_v6b` in full mode). EMBER v3 features came from thrember.

## Primary Decision Rule (One Shot)

The V8 improvement replicated only if, on the full V9 cohort, at the frozen thresholds, against R1:
1. the paired group-bootstrap 95% CI lower bound for (candidate TPR minus R1 TPR) was above 0, and
2. the candidate FPR was no higher than R1's FPR.

The same two conditions were evaluated against R2 and reported. If the primary rule was not met, the conclusion was that the V8 improvement did not replicate, or was not demonstrated, and it was reported as such.

## Secondary Analyses (Descriptive)

The following were reported but could not change the primary decision:
- the exact McNemar test on discordant malware;
- detections gained and lost relative to R1;
- false positives added and removed;
- the ROC-AUC difference with a group-bootstrap CI;
- results at training-derived operating points of 0.25%, 0.5%, 1%, 2% and 5% FPR;
- results by benign root family, file type and malware batch month;
- a pooled V8 + V9 analysis.

## Amendment A1 (2026-11-07, before any V9 feature extraction)

The frozen V9 cohort held 955 benign files (690 Windows components, 265 installed applications) but only 208 malicious files, because few 2026 MalwareBazaar files survived the SHA-256, group and imphash exclusions. To restore statistical power, a malware-only supplement (V9s, `src/v9/supplement.py`, seed 20261108) was frozen before extraction:
- **Source:** 2025 MalwareBazaar batches (2025-01-01 to 2025-12-31), also after the EMBER2024 collection period.
- **Exclusions:** the same as V9, plus V9 itself.
- **Size:** up to 400 malicious files.

The primary decision rule applied to the union of V9 and V9s (955 benign, plus V9 and V9s malware). The 2026-only (V9) and 2025-only (V9s) malware subsets were reported separately as secondary analyses.
