# V8 Preregistration: Gentle Blend of EMBER2024 With a Binary Ninja Model

This document was written before the V8 blind cohort was sampled and before any V8 blind file was analyzed. It was not to be edited after the freeze, except through dated amendments appended at the end.

## Background and Disclosure of Development Use

- **V7 (`docs/v7_results.md`):** a full LightGBM stacker failed against the pretrained EMBER2024 model (R1).
- **Blend evaluation on V7 training data:** a gentle score blend was first evaluated on V7 training data with nested half splits (`src/v7/dev_blend.py`, `artifacts/v7/development/dev_blend.json`). The blend was the R1 logit plus a small weight times the logit of a Binary Ninja-only model.
- **Blend evaluation on the consumed V7 cohort:** the blend was then applied once to the consumed V7 blind cohort (`src/v8/dev_v7.py`, `artifacts/v8/development/dev_v7_blend.json`):
  - The weight w = 0.3 was selected on training data.
  - The blend detected 286 of 304 malicious files, against 283 for R1, with no losses.
  - It produced 2 benign false positives against R1's 1.
  - Because the V7 cohort informed this design, it served as development data only.
- **V8 confirmation:** V8 tested the design once on a new frozen cohort.

## Data

- **Training pool:** identical to V7 (`src.v7.experiment.training_frames`): 5,864 files with EMBER v3 features. 1,256 of them had both `cap6_*` and `hl6_*` Binary Ninja features.
- **Blind cohort (`src/v8/cohort.py`, seed 20261106):**
  - **Benign:** files from `C:\Program Files`, `C:\Program Files (x86)` and `C:\Windows\System32\DriverStore`, at most 2 per directory.
  - **Malicious:** files from 2026 MalwareBazaar batches.
  - **Exclusions:** any file sharing a SHA-256, path, directory group or imphash with V1, V3, V3.1, V3.2, V4, V7, the 2026 temporal check or the V6 gate set.
  - **Target size:** up to 450 benign and 450 malicious files, frozen before feature extraction.
- **Binary Ninja features:** extracted with the same extractors and analysis modes as V7 (`bn_cap_v6` in intermediate mode, then `bn_hlil_v6b` in full mode).

## Arms

- **R1:** the pretrained `EMBER2024_PE.model`. The threshold was set at 1% FPR on the training pool (0.31491).
- **R2:** the EMBER2024 recipe retrained on the training pool, with the threshold set from group-CV out-of-fold scores. The V7 R2 bundle was refit identically.
- **Candidate (`src/v8/blend.py`):**
  - **Score:** on files with both Binary Ninja feature sets, the score was `logit(R1) + w * logit(BN)`. BN was a LightGBM model over `cap6_*` + `hl6_*` only, trained on the 1,256 covered training rows.
  - **Weight:** w was selected from {0.05, 0.1, 0.2, 0.3, 0.5} by nested half-split evaluation on training rows. The rule took the highest mean extra TP over R1 with mean extra FP ≤ 0, and ties went to the smaller w.
  - **Threshold:** the lowest blend threshold flagging no more covered training benign files (out of fold) than R1 flagged on the same rows.
  - **Fallback:** files without both Binary Ninja feature sets used R1's decision at its threshold.

## Decision Rule (Primary, One Shot)

On the full V8 blind cohort, at the frozen thresholds, the candidate beat EMBER2024 only if, against each of R1 and R2:
1. the paired group-bootstrap 95% CI lower bound for (candidate TPR minus reference TPR) was above 0, and
2. the candidate FPR was no higher than the reference FPR.

The following were reported descriptively and could not change the decision:
- the point change in TPR,
- detections gained and lost relative to R1,
- results on files with Binary Ninja coverage.

## Limitations Known in Advance

- The expected gain was small (about 1 percentage point in development), so a CI lower bound above 0 was uncertain at this cohort size.
- The benign roots differed from V7 (installed applications and drivers instead of Windows component stores).
- EMBER2024's own test and challenge sets could not be used, because they do not include binaries.
