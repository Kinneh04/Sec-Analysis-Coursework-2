# V9 Results: Replication of the V8 Blend Against EMBER2024

## Summary

The V8 improvement did not replicate under the preregistered rule (`docs/v9_preregistration.md`).

The frozen V8 blend (`logit(EMBER2024) + 0.3 * logit(BN model)`) was scored once on an independent cohort of 1,563 files (955 benign, 608 malicious, frozen before extraction):
- **Candidate:** 541 of 608 malicious files detected (TPR 0.890), with 2 false positives among 955 benign files.
- **R1 (pretrained EMBER2024):** 536 detected (TPR 0.882), with the same 2 false positives.

The TPR difference was +0.82 percentage points, but its paired group-bootstrap 95% CI (−0.33 to +1.97) included 0. The exact McNemar test on discordant malware (8 gained, 3 lost) gave p = 0.23. The rule against R2 was also not met (+2.47 percentage points, 95% CI −0.33 to +5.28).

The evidence across V7, V8 and V9 was consistent with a small, positive but unproven benefit at the 1% FPR operating point:
- higher ranking quality (ROC-AUC),
- a modest TPR gain at moderate thresholds,
- a clear loss at the strictest threshold.

Binary Ninja features were therefore not shown to make EMBER2024 reliably better.

## Cohort

- **V9 (`artifacts/v9/manifests/`, seed 20261107):**
  - 955 benign files, at most 2 per directory: 690 from Windows component stores (WinSxS, Microsoft.NET, the .NET assembly cache, SystemApps, ProgramData, per-user folders) and 265 from installed applications and drivers (Program Files, Program Files (x86), DriverStore).
  - 208 malicious files from 2026 MalwareBazaar batches.
- **V9s supplement (`artifacts/v9s/manifests/`, seed 20261108, amendment A1):** 400 malicious files from 2025 MalwareBazaar batches. It was added before any extraction, because few 2026 files survived the exclusions.
- **Exclusions:** both cohorts were disjoint by SHA-256, path, directory group and imphash from V1, V3, V3.1, V3.2, V4, V7, V8, the 2026 temporal check and the V6 gate set. V9s was also disjoint from V9.
- **Binary Ninja coverage (both `cap6_*` and `hl6_*`):** 99.6% of benign and 94.6% of malicious files. Uncovered files used R1's decision, as frozen.
- **Feature extraction:** identical to V7 and V8, with no execution.

## Frozen-Model Integrity

The V8 freeze manifest tracked the SHA-256 of every model, manifest and source file. Before the run, 9 tracked text files no longer matched:
- `docs/v8_preregistration.md`,
- the `src/v8/*.py` modules,
- `src/v7/experiment.py`,
- `src/v6/bn_capabilities.py`, `src/v6/bn_hlil.py` and `src/v6/unpack.py`.

All 9 had been rewritten on 2026-11-07 at 20:41, before the V9 cohort was sampled, with LF instead of CRLF line endings. No content had changed.
- Converting each file back to CRLF reproduced its frozen SHA-256 exactly.
- The model pickles, cohort manifests and extraction queue were byte-identical to the freeze.
- The CRLF bytes were restored, and the strict freeze verification then passed with no mismatches before the one-shot run.

## Primary Result (Frozen Thresholds)

| Arm | TPR | True positives | False positives | FPR |
|------|------|------|------|------|
| Candidate (V8 blend) | 0.8898 | 541 / 608 | 2 / 955 | 0.21% |
| R1: pretrained EMBER2024 | 0.8816 | 536 / 608 | 2 / 955 | 0.21% |
| R2: EMBER v3 retrained on the training pool | 0.8651 | 526 / 608 | 2 / 955 | 0.21% |

| Comparison | Change in TPR (95% CI) | FPR not higher | Rule met |
|------|------|------|------|
| Candidate minus R1 | +0.0082 (−0.0033 to +0.0197) | Yes | No |
| Candidate minus R2 | +0.0247 (−0.0033 to +0.0528) | Yes | No |

The decision was `v8_improvement_replicated: false`. Relative to R1, the candidate gained 8 malicious detections, lost 3, and added or removed no false positives.

## Secondary Results (Descriptive)

### Ranking Quality

The candidate's ROC-AUC was 0.9973, against 0.9957 for R1. The difference was +0.0017 (group-bootstrap 95% CI +0.0004 to +0.0033). The candidate also had the higher AUC on V8 (+0.0028, CI +0.0014 to +0.0044) and on V7 (+0.0003, CI −0.0000 to +0.0006). Ranking improvement was the most consistent finding across cohorts.

### Operating Points (Thresholds From Training Data)

| Training FPR | Candidate TP / FP | R1 TP / FP | Gained / lost | McNemar p |
|------|------|------|------|------|
| 0.25% | 474 / 1 | 491 / 1 | 2 / 19 | 0.0002 |
| 0.5% | 511 / 1 | 515 / 1 | 6 / 10 | 0.45 |
| 1% (frozen) | 541 / 2 | 536 / 2 | 8 / 3 | 0.23 |
| 2% | 557 / 2 | 553 / 2 | 7 / 3 | 0.34 |
| 5% | 583 / 7 | 574 / 10 | 9 / 0 | 0.004 |

At the strictest training operating point (0.25% FPR), the candidate was significantly worse than R1. It lost 19 detections and gained 2, the same direction observed on V8 (3 gained, 17 lost) and V7 (1 gained, 3 lost). At 5% FPR, the candidate was significantly better: 9 gained, 0 lost and 3 fewer false positives. The blend therefore helped at looser thresholds and hurt at very strict thresholds.

### Subsets at the Frozen Threshold

| Subset | Candidate TP / FP | R1 TP / FP | Gained / lost | 95% CI for change in TPR |
|------|------|------|------|------|
| 2026 malware (V9, 208) with all benign | 192 / 2 | 190 / 2 | 2 / 0 | 0.000 to +0.025 |
| 2025 malware (V9s, 400) with all benign | 349 / 2 | 346 / 2 | 6 / 3 | −0.009 to +0.024 |
| Files with Binary Ninja coverage | 515 / 2 | 510 / 2 | 8 / 3 | −0.003 to +0.021 |

Both false positives at the frozen threshold were Windows component files. Both arms flagged them, and the candidate flagged no other benign file.

By file type, `.exe` gave 524 against 518 detections (572 malicious) and `.dll` gave 16 against 17 (35 malicious). No benign `.dll` or `.sys` file was flagged by either arm.

### Pooled V8 and V9 (Descriptive Only)

| Arms | TP / 1,051 malicious | FP / 1,236 benign | Gained / lost | McNemar p | 95% CI for change in TPR |
|------|------|------|------|------|------|
| Candidate | 948 | 2 | 14 / 3 | 0.013 | +0.002 to +0.019 |
| R1 | 937 | 2 | | | |

The pooled CI excluded 0. However, the pool included V8, the cohort on which the improvement was first observed, so it could not serve as independent confirmation.

## Robustness Analyses on Earlier Held-Out Cohorts (`artifacts/v9/robustness.json`)

The frozen V8 models were applied unchanged to the V8 blind cohort and to the consumed V7 blind cohort, which was never used for training.

| Analysis | V8 cohort (724) | V7 cohort (754) |
|------|------|------|
| Gained / lost malware against R1 at the frozen threshold | 6 / 0 (McNemar p = 0.031) | 3 / 0 (p = 0.25) |
| False positives added / removed | 0 / 0 | 1 / 0 |
| Change in ROC-AUC (95% CI) | +0.0028 (+0.0014 to +0.0044) | +0.0003 (−0.0000 to +0.0006) |
| Gained / lost at 0.25% training FPR | 3 / 17 | 1 / 3 |
| Gained / lost at 5% training FPR | 3 / 0, with 11 fewer false positives | 3 / 1, with 2 fewer false positives |

**Weight sensitivity at 1% FPR** (gained / lost against R1, thresholds recalibrated on training data for each weight):

| w | V8 | V7 |
|------|------|------|
| 0.05 | 0 / 1 | 0 / 0 |
| 0.1 | 1 / 0 | 2 / 0 |
| 0.2 | 3 / 0 | 3 / 0, with 1 added FP |
| 0.3 | 6 / 0 | 3 / 0, with 1 added FP |
| 0.5 | 2 / 4 | 3 / 2 |
| 1.0 | 1 / 35 | 3 / 14 |

The benefit appeared only at low weights. It turned into losses at weights of 0.5 or more.

**Breakdowns by file type and batch month:**
- **File type (V8):** `.exe` gave 388 against 383 detections (415 malicious) and `.dll` gave 18 against 17 (27 malicious).
- **File type (V7):** `.exe` gave 273 against 270 detections (287 malicious), with 2 against 1 benign false positives.
- **Batch month:** the candidate matched or exceeded R1 in every 2026 batch month on both cohorts, by at most 2 files per month.

## Conclusion

- The V8 claim that the blend beat EMBER2024 rested on a single cohort. It was not confirmed by an independent, larger replication.
- At the preregistered 1% FPR operating point, the candidate was nominally better on V9 (+5 net detections at equal FPR), but the improvement was not statistically established.
- Across three held-out cohorts, the blend consistently ranked files slightly better than EMBER2024 (higher ROC-AUC). It was consistently worse at very strict thresholds (around 0.25% FPR) and better at looser thresholds (2% to 5%).
- The most accurate statement was that Binary Ninja features, blended at weight 0.3, gave a small improvement in ranking quality and a possible gain of under 1 percentage point in TPR near 1% FPR. At the strictest operating points, the blend reduced detection. The blend was not shown to be reliably better than the pretrained EMBER2024 model.

## Limitations

- **Statistical power:** a true gain of about 1 percentage point needs a larger cohort to establish. V9 had 608 malicious files, about 24% of which came from the 2025 supplement.
- **Malware sources:** 2026 malware was scarce after exclusions, so most V9 malware came from 2025. All malware came from MalwareBazaar.
- **Benign sources:** benign files came from a single Windows host. Few installed-application `.exe` files remained after exclusions (86 benign `.exe` files overall).
- **Binary Ninja coverage:** Binary Ninja ran through the GUI MCP server with per-file time budgets. 5.4% of malicious files lacked full coverage and used R1's decision.
- **EMBER2024 test sets:** EMBER2024's own test and challenge sets could not be used, because they do not include binaries.

## Artifacts

- `artifacts/v9/blind/replication_results.json` (locked by `replication_run.lock`),
- `artifacts/v9/blind/replication_scores.parquet`,
- `artifacts/v9/robustness.json` (V8 and V7 robustness analyses),
- `artifacts/v9/manifests/` and `artifacts/v9s/manifests/`,
- `src/v9/robustness.py`, `src/v9/cohort.py`, `src/v9/supplement.py` and `src/v9/replicate.py`.
