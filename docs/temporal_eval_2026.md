# Temporal Holdout: 2026 MalwareBazaar (Frozen V3.2)

**Date:** 2026-11-01
**Type:** Supplementary and not confirmatory. Models and thresholds were not refit on this sample.

## Correction

The first version of this report stated an FPR of about 72% for both arms. That figure was wrong. Several SPICE Guest Tools driver DLLs exist as identical copies in many folders, and joining on duplicate SHA-256 values multiplied 4 benign files into 795 rows. `src/v3/temporal_eval.py` now removes duplicate SHA-256 values before extraction. The corrected figures below were recomputed from the saved per-file scores (`artifacts/v3.3/temporal_eval/temporal_eval_dedup.json`).

## Setup

- 450 malicious PE files with `batch_date` on or after 2026-01-01, none of them in any earlier training or blind inventory.
- 246 unique benign PE files from local install folders, with paths excluded from earlier cohorts.
- Scored with the frozen V3.2 thresholds (candidate 0.894, baseline 0.909).

## Fixed-threshold results

| Arm | TPR | FPR | False positives |
|------|------|------|------|
| Baseline (`pe_v1s`) | 80.0% | 2.03% | 5 / 246 |
| Candidate (`pe_v3`) | 91.1% | 1.63% | 4 / 246 |

- Paired TPR gain: +11.1 points (95% CI +7.5 to +14.8).
- The candidate had both higher TPR and fewer false positives than the baseline on newer malware.
- All 4 candidate false positives were `WdfCoInstaller` DLLs bundled with SPICE Guest Tools. The same family produced false positives in the V3 blind evaluation.

## Matched FPR (descriptive)

| FPR | Baseline TPR | Candidate TPR |
|------|------|------|
| 1% | 0.718 | 0.836 |
| 2% | 0.787 | 0.936 |

## Interpretation

- The frozen V3.2 candidate generalized to 2026 malware batches better than the baseline.
- Both arms exceeded 1% FPR on this benign sample. With 246 benign files, one false positive is about 0.4%, so the estimate is coarse.
- The false positives are concentrated in one product, which makes a per-product allow-list or a deployment threshold practical.
