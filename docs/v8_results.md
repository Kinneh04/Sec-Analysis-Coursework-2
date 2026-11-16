# V8 Results: Gentle Blend of EMBER2024 With a Binary Ninja Model

## Summary

V8 tested a gentle score blend, preregistered in `docs/v8_preregistration.md`. The blend combined the pretrained EMBER2024 PE model (R1) with a LightGBM model trained only on Binary Ninja features (`cap6_*` capability indicators and `hl6_*` full-analysis HLIL indicators):

`score = logit(R1) + 0.3 * logit(BN model)`

The candidate was tested once on a fresh frozen blind cohort of 724 Windows PE files (281 benign, 443 malicious, 666 groups). At thresholds fixed on training data, it met the preregistered rule against both EMBER2024 references:
- **Against R1 (pretrained EMBER2024):** TPR 0.919 against 0.905, a difference of +1.35 percentage points (paired group-bootstrap 95% CI +0.44 to +2.59). The FPR was 0/281 for both.
- **Against R2 (EMBER v3 LightGBM retrained on the same pool):** TPR 0.919 against 0.860, a difference of +5.87 percentage points (95% CI +2.29 to +9.49). The FPR was 0/281 for both.

The candidate detected 6 malicious files that R1 missed and lost none of R1's detections. The gain was small, and it was measured on a single, modest cohort. It did not support a general state-of-the-art claim (`sota_claim_supported: false`).

## Design

- **Training pool:** identical to V7, 5,864 files with EMBER v3 features (3,506 benign, 2,358 malicious). Of these, 1,256 had both Binary Ninja feature sets. They were the V6 gate files plus a seeded random sample of 700 pool files.
- **Binary Ninja model:** LightGBM over `cap6_*` and `hl6_*` only (no EMBER inputs), trained on the 1,256 covered training rows.
- **Weight selection (training data only):** nested half-split evaluation over 10 seeds and 20 evaluations per weight.

  | w | Mean extra TP over R1 | Mean extra FP |
  |------|------|------|
  | 0.05 | +0.70 | −0.30 |
  | 0.1 | +3.05 | −0.60 |
  | 0.2 | +5.65 | −0.75 |
  | 0.3 | +6.80 | −0.95 |
  | 0.5 | +3.20 | −1.00 |

  w = 0.3 was selected by the preregistered rule.
- **Thresholds (`artifacts/v8/freeze/freeze_manifest.json`):**
  - The blend threshold was calibrated so that it flagged no more covered training benign files (out of fold) than R1 did on the same rows (9 each).
  - R1: 0.31491, at 1% FPR on the training pool.
  - R2: 0.97787, from group-CV out-of-fold scores.
  - Files without both Binary Ninja feature sets used R1's decision.
- **Blind cohort (`artifacts/v8/manifests/`, seed 20261106):**
  - **Benign:** files from `C:\Program Files`, `C:\Program Files (x86)` and `C:\Windows\System32\DriverStore`, at most 2 per directory.
  - **Malicious:** files from 2026 MalwareBazaar batches.
  - **Exclusions:** files sharing a SHA-256, path, directory group or imphash with V1, V3, V3.1, V3.2, V4, V7, the 2026 temporal check or the V6 gate set.
  - **Freezing:** the cohort was frozen before feature extraction. The models were frozen before any blind Binary Ninja feature was extracted.
- **Binary Ninja coverage on the blind cohort:** 99.6% of benign and 92.8% of malicious files.
  - `cap6_*`: 691 of 724 files usable.
  - `hl6_*`: 698 of 724 files usable.
- **Static analysis only:** files over 16 MB had their overlay stripped, and UPX files were unpacked statically with `upx -d`.

## Primary Result (Fixed Training Thresholds)

| Arm | TPR (95% CI) | True positives | False positives | ROC-AUC |
|------|------|------|------|------|
| Candidate (R1 + 0.3 × Binary Ninja model) | 0.919 (0.890–0.941) | 407 / 443 | 0 / 281 | 0.9979 |
| R1: pretrained EMBER2024 | 0.905 (0.874–0.929) | 401 / 443 | 0 / 281 | 0.9951 |
| R2: EMBER v3 retrained on the same pool | 0.860 (0.825–0.889) | 381 / 443 | 0 / 281 | 0.9995 |

| Comparison | Change in TPR (95% CI) | Change in FPR | Rule met |
|------|------|------|------|
| Candidate minus R1 | +0.0135 (+0.0044 to +0.0259) | 0 | Yes |
| Candidate minus R2 | +0.0587 (+0.0229 to +0.0949) | 0 | Yes |

The decision in `artifacts/v8/blind/blind_results.json` was `beats_ember2024: true`.

Relative to R1, the candidate gained 6 true positives and lost 0. It added and removed no false positives. On the 691 files with full Binary Ninja coverage, the TPR was 0.922 for the candidate, 0.908 for R1 and 0.854 for R2, all with 0 false positives.

## Limitations

- **Small effect:** the gain over R1 was 6 malicious files out of 443. The CI lower bound (+0.44 percentage points) was close to zero.
- **Limited benign sample:** only 281 benign files survived the exclusions, below the target of 450. No arm produced a false positive, so the 1% FPR operating point was not directly measured. The upper 95% bound on FPR with 0/281 is about 1.35%. ROC-AUC was highest for R2 (0.9995), so the advantage applied to the fixed training thresholds, not to every operating point.
- **Development disclosure:**
  - The blend design was chosen after the V7 confirmatory test failed.
  - The blend was evaluated on V7 training data and once on the consumed V7 cohort before V8 was preregistered (`docs/v8_preregistration.md`).
  - The weight and thresholds were selected on training data only, and the V8 cohort was not used before the one-shot evaluation.
  - V8 followed several unsuccessful designs (V4, V5, V6, V6b, V7, and the guarded union and band rules), so the overall search involved multiple attempts.
- **Benign distribution:** V8 benign files came from installed applications and drivers, which differed from V7's Windows component stores. Results may not transfer to other benign distributions.
- **Partial Binary Ninja coverage:** Binary Ninja features existed for 1,256 of 5,864 training files. Files without coverage fell back to R1.
- **Analysis constraints:** Binary Ninja ran through the GUI MCP server (personal license) with per-file time budgets, intermediate analysis for `cap6_*` and full analysis for `hl6_*`. Packers other than UPX were not unpacked.
- **EMBER2024 test sets:** EMBER2024's own test and challenge sets could not be used with Binary Ninja features, because the EMBER2024 release does not include binaries. The comparison was limited to locally held files.

## Earlier Negative Results

The negative results from V4 (`docs/v4_results.md`), V6 and V6b (`docs/v6_results.md`), and V7 (`docs/v7_results.md`) stood unchanged. Generic Binary Ninja features, instruction n-grams, evasion and capability indicators, function novelty, a full stacker, a guarded union and a band rule all failed to beat the pretrained EMBER2024 model. Only the gentle blend in V8 succeeded, by a small margin.

## Artifacts

- `artifacts/v8/blind/blind_results.json` (locked by `blind_run.lock`),
- `artifacts/v8/blind/blind_scores.parquet`,
- `artifacts/v8/freeze/freeze_manifest.json`,
- `artifacts/v8/models/`,
- `artifacts/v8/development/dev_v7_blend.json`,
- `src/v8/blend.py`, `src/v8/experiment.py`, `src/v8/cohort.py`.

## Replication Status

An independent replication on 1,563 files (`docs/v9_results.md`) did not confirm this result. The candidate detected 541 of 608 malicious files against 536 for R1, at equal FPR (2/955), but the 95% CI for the change in TPR (-0.33 to +1.97 percentage points) included 0. At a strict training operating point (0.25% FPR), the blend detected significantly fewer malicious files than R1 on V7, V8 and V9. The V8 result was therefore treated as unconfirmed.

