# V7 Results: Binary Ninja Capability and HLIL Features Against EMBER2024

## Summary

V7 was the confirmatory test of the strongest Binary Ninja feature set found in development: V6 capability indicators (`cap6_*`) plus V6b full-analysis HLIL indicators (`hl6_*`), stacked on the EMBER2024 logit. The test followed `docs/v7_preregistration.md` and ran once on a fresh frozen blind cohort of 754 files (450 benign, 304 malicious, 716 groups).

The candidate did not beat the pretrained EMBER2024 model (R1). Its TPR was 1.3 percentage points lower (95% CI −3.7 to +1.0), at the same FPR. It did beat EMBER v3 retrained on the same training pool (R2), by +4.9 percentage points (95% CI +1.0 to +8.9) with a lower FPR. Under the preregistered rule, the result was negative: Binary Ninja features did not beat EMBER2024.

## Design

- **Training pool:** the V4 training pool plus the 632 V6 gate files, 5,864 files with EMBER v3 features (3,506 benign, 2,358 malicious).
- **Binary Ninja features in training:** available for 1,256 training files (the V6 gate files plus a seeded random sample of 700 pool files). Elsewhere they were missing (NaN).
- **Blind cohort (`artifacts/v7/manifests/`):**
  - Benign files came from the V4 benign roots, at most 2 per directory.
  - Malicious files came from 2026 MalwareBazaar batches.
  - Any file sharing a SHA-256, directory group or imphash with V1, V3, V3.1, V3.2, V4, the 2026 temporal check or the V6 gate set was excluded.
  - The cohort was frozen before feature extraction. Only 304 malicious files survived the exclusions, below the target of 450.
- **Binary Ninja coverage on the blind cohort:**

  | Feature set | Benign | Malicious |
  |------|------|------|
  | `cap6_*` | 98.0% | 89.1% |
  | `hl6_*` | 99.3% | 94.4% |

  The analysis modes matched training: intermediate for `cap6_*`, full for `hl6_*`.
- **Selection (training data only, `artifacts/v7/development/selection.json`):**
  - C7a (`r1_logit` + `cap6_*` + `hl6_*`, 115 features) reached a pooled group-CV out-of-fold TPR of 0.9368 at 0.97% FPR.
  - C7b (`r1_logit` + `cap6_*`) reached 0.9364 at the same FPR.
  - C7a was selected on the AUC tie-break.
  - For reference, R1 reached a TPR of 0.947 on the same pool at its own 1% FPR threshold.
- **Frozen thresholds (`artifacts/v7/freeze/freeze_manifest.json`):** candidate 0.8527, R2 0.9779, R1 0.3149.

## Primary Result (Fixed Training Thresholds)

| Arm | TPR (95% CI) | True positives | False positives | ROC-AUC | PR-AUC |
|------|------|------|------|------|------|
| Candidate C7a | 0.918 (0.881–0.944) | 279 / 304 | 1 / 450 | 0.9987 | 0.9981 |
| R1: pretrained EMBER2024 | 0.931 (0.897–0.954) | 283 / 304 | 1 / 450 | 0.9990 | 0.9985 |
| R2: EMBER v3 retrained on the same pool | 0.868 (0.826–0.902) | 264 / 304 | 2 / 450 | 0.9979 | 0.9971 |

| Comparison | Change in TPR (paired group bootstrap, 95% CI) | Change in FPR | Rule met |
|------|------|------|------|
| Candidate minus R1 | −0.013 (−0.037 to +0.010) | 0.000 | No |
| Candidate minus R2 | +0.049 (+0.010 to +0.089) | −0.002 | Yes |

The decision was `beats_ember2024: false`. At the frozen thresholds, the candidate detected 5 malicious files that R1 missed, and R1 detected 9 that the candidate missed.

## Secondary Results (Descriptive)

| Subset | Candidate TPR / FPR | R1 TPR / FPR | R2 TPR / FPR |
|------|------|------|------|
| Ordinary-native stratum (172 malicious, 188 benign) | 0.907 / 0.53% | 0.913 / 0.53% | 0.855 / 0.53% |
| Files with Binary Ninja coverage (271 malicious, 441 benign) | 0.915 / 0.23% | 0.930 / 0.23% | 0.867 / 0.45% |

The ordinary-native stratum was where EMBER2024 missed the most malware in development. The candidate did not outperform R1 there either.

With thresholds chosen on the blind cohort itself (for description only, not a valid operating point), the TPR at 1% blind FPR was 0.957 for the candidate, 0.977 for R1 and 0.987 for R2.

## Interpretation

- The Binary Ninja features improved a model trained on our pool (candidate versus R2). They did not add enough to the pretrained EMBER2024 model to offset the noise introduced by stacking.
- The development gain of about +10 true positives (V6b) came from a gate set enriched with EMBER2024-missed malware. It did not carry over to a cohort with natural composition, where R1 missed only 21 of 304 malicious files.
- Across V4, V5, V6, V6b and V7, no Binary Ninja feature family produced a blind result better than the pretrained EMBER2024 model.

## Follow-Up: Guarded Union (Development Only)

After the V7 one-shot evaluation, a guarded union was examined as a possible next design: flag a file when R1 is positive, or when a Binary Ninja rescue model (LightGBM over `r1_logit` + `cap6_*` + `hl6_*`) exceeds a threshold that added no benign false positives beyond R1 in out-of-fold training scores. A union cannot lose R1's detections.

- **In-sample threshold, training pool (`src/v7/dev_union.py`):** the union added a median of 16.5 true positives over R1 (455 of 531 on the rows with Binary Ninja features), with 0 extra false positives by construction.
- **Nested threshold, training pool (`src/v7/dev_union_oos.py`):** thresholds were set on half of the groups and evaluated on the other half, across 20 runs. The union added a median of 9 true positives. However, 10 of the 20 runs added at least one benign false positive (15 extra in 7,250 benign evaluations).
- **V7 blind cohort (consumed, descriptive only):** the rescue model and threshold were fit on the full training pool and applied once. The union added 0 true positives and 0 false positives.

The guarded union did not carry over out of sample. Its strict threshold either added no detections or added false positives, and any extra false positive would fail the preregistered FPR condition against R1. The design was not taken to a new confirmatory cohort.

## Limitations

- **Cohort size:** the blind cohort was modest (754 files, 304 malicious). A true gain of 1 to 2 percentage points over R1 could not have been detected with this sample.
- **Partial Binary Ninja coverage in training:** Binary Ninja features existed for only 1,256 of 5,864 training files.
- **Analysis constraints:** Binary Ninja ran through the GUI MCP server (personal license) with per-file time budgets. Files that timed out, or that exceeded 16 MB after overlay stripping, had missing features. Packers other than UPX were not unpacked, because unpacking them requires emulation or execution.
- **EMBER2024 test sets:** EMBER2024's own test and challenge sets could not be used with Binary Ninja features, because the EMBER2024 release does not include binaries.

## Artifacts

- `artifacts/v7/blind/blind_results.json` (locked by `blind_run.lock`),
- `artifacts/v7/blind/blind_scores.parquet`,
- `artifacts/v7/freeze/freeze_manifest.json`,
- `artifacts/v7/development/selection.json`,
- `artifacts/v6/cap_cache/` and `artifacts/v6/hlil_cache/`.
