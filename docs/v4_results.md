# SA2 V4 Results: Binary Ninja Features vs the EMBER2024 Benchmark Detector

**Date:** 2026-11-02
**Outcome:** The preregistered criterion was not met. The candidate, which used Binary Ninja features, did not beat the pretrained EMBER2024 PE detector on the frozen V4 blind cohort. It did beat the EMBER2024 recipe retrained on the same local training data.

## 1. Why EMBER2024's own test set was not used

EMBER2024 publishes feature vectors and metadata for its test and challenge sets, not the binaries. Binary Ninja features require the binary, so they cannot be computed for that test set. The comparison was therefore run head-to-head on locally held binaries, with the official pretrained model as the reference. No claim is made about performance on the EMBER2024 test set.

## 2. Confirmatory blind result (single run, frozen thresholds)

Blind cohort: 566 files (331 benign, 235 malicious, 498 groups). Binary Ninja coverage was 98.8% of benign and 90.6% of malicious files.

| Arm | TPR (95% Wilson CI) | FPR | ROC-AUC | PR-AUC |
|------|------|------|------|------|
| R1: pretrained `EMBER2024_PE.model` | **0.919** (0.877–0.948) | 0 / 331 | **0.998** | **0.997** |
| Candidate C2: EMBER2024 logit + Binary Ninja features | 0.898 (0.853–0.930) | 0 / 331 | 0.989 | 0.990 |
| R2: EMBER2024 recipe retrained on the local pool | 0.821 (0.767–0.865) | 6 / 331 | 0.967 | 0.964 |

Paired group bootstrap (2,000 replicates over 498 groups):

| Comparison | TPR difference (95% CI) | FPR difference | Result |
|------|------|------|------|
| Candidate − R1 | −2.1 points (−4.6 to +0.4) | 0.0 | Not beaten |
| Candidate − R2 | +7.7 points (+3.0 to +12.4) | −1.8 points | Beaten |

**Beats EMBER2024 (both references required): No.**

At matched blind FPR (descriptive), R1 also stayed ahead:

| Blind FPR | R1 TPR | Candidate TPR | R2 TPR |
|------|------|------|------|
| 0.5% | 0.945 | 0.915 | 0.779 |
| 1.0% | 0.966 | 0.928 | 0.804 |

## 3. Method

1. **Blind cohort:**
   - Frozen before any Binary Ninja feature was used in a model.
   - Benign files came from Windows locations never sampled in earlier waves (WinSxS, Microsoft.NET, SystemApps, the .NET assembly cache, ProgramData, per-user program folders), with at most 2 files per directory.
   - Malicious files came from 2026 MalwareBazaar batches, after the EMBER2024 collection period.
   - Files sharing a SHA-256, directory group or imphash with any earlier cohort were excluded.
2. **Binary Ninja features (`bn4_*`, 443 columns):**
   - Extracted through the Binary Ninja GUI MCP server (personal license; no headless API), static analysis only.
   - Families: whole-binary counts, function statistics, complexity of the 32 largest functions, call-graph composition (import, internal and unresolved calls), hashed APIs actually called, hashed named functions, and string statistics.
   - 1,965 files were analyzed over about 10.4 hours in intermediate analysis mode.
3. **References:**
   - R1 used the official pretrained model downloaded with `thrember`.
   - R2 retrained the published EMBER2024 recipe (500 rounds, 64 leaves, 100 minimum samples per leaf, EMBER categorical columns) on the 5,238-row local pool.
4. **Candidate selection (training data only):**
   - C1 (EMBER v3 + Binary Ninja features) reached pooled out-of-fold TPR 0.947 at 0.95% FPR.
   - C2 (R1 logit + Binary Ninja features) reached 0.967 at 0.79% FPR, so C2 was selected.
   - Both trained on the full pool, with Binary Ninja features present on 1,323 stratified rows (Amendment A1).
5. **Thresholds:** 1% FPR on training-derived scores for every arm, frozen with SHA-256 hashes of models, manifests and code before the blind run.

The preregistration (`docs/v4_preregistration.md`) records three amendments, all made before any Binary Ninja-based model was fitted:
- **A1:** the candidates trained on the full pool.
- **A2:** extraction limits.
- **A3:** intermediate analysis mode.

## 4. Error analysis

- **Candidate vs R1:** the candidate missed 7 malware files that R1 detected. All 7 had Binary Ninja features, and R1 scored them between 0.36 and 0.69. The stacker lowered them below its threshold, so Binary Ninja features overrode correct EMBER2024 evidence.
- **Missed by both:** 17 malware files, a mix of Delphi, MinGW, LLVM, Visual Basic and MSVC builds, several of them large or without Binary Ninja coverage. Binary Ninja features did not flag them either.
- **False positives:** R1 and the candidate had none. All 6 R2 false positives came from the new benign locations, consistent with R2 training on a small, source-limited pool.

## 5. Post-hoc development check (not confirmatory)

A residual design boosted from the R1 logit with Binary Ninja features only, using the consumed V4 blind cohort as a development set (`artifacts/v4/development/residual_dev.json`).

| Binary Ninja boosting rounds | Train out-of-fold ROC-AUC | Development ROC-AUC | Development TPR at matched 1% FPR |
|------|------|------|------|
| 0 (R1 alone) | 0.9988 | 0.9975 | 0.966 |
| 25 | 0.9989 | 0.9973 | 0.966 |
| 100 | 0.9991 | 0.9963 | 0.949 |
| 200 | 0.9991 | 0.9953 | 0.945 |

Each added round slightly improved training metrics and degraded the shifted development cohort. On this data the Binary Ninja features captured training-source regularities that did not transfer to new benign locations and 2026 malware.

A union design was also checked on the same development set (`artifacts/v4/development/union_dev.json`). It flagged a file if R1 flagged it at its frozen threshold, or if a strict Binary Ninja model flagged it. By construction it kept every R1 detection.

| Binary Ninja component | Strict training FPR | Extra detections over R1 | Extra false positives |
|------|------|------|------|
| Binary Ninja features only | 0.1% / 0.25% | 0 | 0 |
| Binary Ninja features only | 0.5% | 1 | 1 |
| EMBER v3 + Binary Ninja | 0.25% | 2 | 0 |
| EMBER v3 + Binary Ninja | 0.5% | 3 | 9 |

About 5 or more extra detections in distinct groups, with no added false positives, would be needed for the paired bootstrap lower bound to exceed zero. No union setting reached that level, so this design was not carried to a new blind cohort.

### Binary Ninja training coverage (development)

Binary Ninja extraction was extended to more of the training pool, and the designs were re-measured on the development set at each step (`artifacts/v4/development/coverage_curve.csv`). R1 stayed at ROC-AUC 0.998, TPR 0.966 at matched 1% FPR, and 216 detections with 0 false positives at its frozen threshold.

| Binary Ninja training rows | C2 ROC-AUC | C2 TPR at matched 1% FPR | C2 at frozen threshold (detections / false positives) | C1 ROC-AUC | Union extra detections / false positives (0.25%) |
|------|------|------|------|------|------|
| 1,324 | 0.990 | 0.923 | 211 / 0 | 0.946 | 2 / 0 |
| 2,277 | 0.992 | 0.945 | 210 / 0 | 0.966 | 1 / 2 |
| 3,982 | 0.992 | 0.953 | 218 / 3 | 0.942 | 1 / 0 |

C2 ranking improved from 1,324 to 2,277 rows and then plateaued, still below R1. At 3,982 rows it detected 2 more files than R1 at its frozen threshold, but added 3 false positives. Extraction was stopped with 3,982 of 5,238 training files covered, because the trend no longer pointed toward beating R1.

### Instruction-level Binary Ninja features (V5 pilot, development)

Disassembly mnemonics from the 32 largest functions per file were extracted for the development set and 600 training files (hashed unigrams and bigrams, instruction-class fractions, mnemonic entropy; `src/v5/bn_insn.py`). A preregistered development gate required at least 5 more detections than R1 at frozen thresholds with no added false positives (`artifacts/v5/dev_gate.json`).

| Design | Detections (of 235) | False positives | ROC-AUC | TPR at matched 1% FPR |
|------|------|------|------|------|
| R1 | 216 | 0 | 0.998 | 0.966 |
| R1 logit + whole-file Binary Ninja features | 218 | 2 | 0.992 | 0.957 |
| R1 logit + instruction features | 209 | 0 | 0.997 | 0.966 |
| R1 logit + both | 218 | 3 | 0.991 | 0.953 |

No design passed the gate, so no new blind cohort was drawn for this design. Instruction features changed R1's ranking least, but they did not add detections at a fixed threshold.

### Pretrained EMBER2024 on earlier local cohorts (descriptive)

| Cohort | Files (benign / malicious) | EMBER2024 at frozen threshold (TPR / false positives) | EMBER2024 ROC-AUC | Best local model on the same files |
|------|------|------|------|------|
| V3.2 blind | 158 / 409 | 0.885 / 2 (threshold from the V3.2 training pool) | 0.983 | V3.2 `pe_v3`: 0.738 / 1, ROC-AUC 0.982 |
| 2026 temporal check | 241 / 450 | 0.951 / 0 | 0.999 | V3.2 `pe_v3`: 0.911 / 4, ROC-AUC 0.996 |

On every local cohort, the pretrained EMBER2024 detector matched or exceeded the best local model.

## 6. Interpretation

- **No improvement over the pretrained EMBER2024 detector:** neither feature fusion (C1), stacking (C2), residual correction nor a union with a strict Binary Ninja detector produced a usable gain.
- **Gain over the retrained recipe:** the candidate clearly beat the EMBER2024 recipe retrained on the same 5,238 local rows (R2). Most of that gain came from the pretrained EMBER2024 score inside the stacker, not from Binary Ninja: R1 alone was stronger than the candidate.
- **Training scale dominated:** R1 trained on about 3.2 million files and R2 on 5,238. Binary Ninja features from 1,323 training files did not close or extend that gap.

## 7. Limitations

- **Small malicious sample:** 235 malicious blind files give TPR intervals of about ±4 to ±5 points.
- **Possible bias in favour of R1:** benign Windows system files are common on VirusTotal and may be in EMBER2024's training data.
- **Partial training coverage:** Binary Ninja features covered 25% of the training pool, and intermediate analysis mode and the extraction limits may have reduced their quality.
- **Narrow candidate design:** the candidates used one LightGBM configuration. Richer Binary Ninja representations, such as IL instruction n-grams or function embeddings, were not evaluated.

## 8. Artifacts

| Path | Content |
|------|------|
| `artifacts/v4/manifests/` | Frozen blind cohort and Binary Ninja queue |
| `artifacts/v4/bn_cache/` | Raw Binary Ninja results (1,965 files) |
| `artifacts/v4/features/ember_v3.parquet` | EMBER v3 features (9,170 files) |
| `artifacts/v4/development/selection.json` | Training-only candidate selection |
| `artifacts/v4/freeze/freeze_manifest.json` | Frozen models, thresholds and hashes |
| `artifacts/v4/blind/blind_results.json`, `blind_scores.parquet` | Confirmatory run (locked) |
| `artifacts/v4/development/residual_dev.json` | Post-hoc residual check |
