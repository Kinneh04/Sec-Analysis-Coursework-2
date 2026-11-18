# V10 Preregistration: Larger Replication of the V8 Blend Using All 2026 MalwareBazaar Data

This document was written before the V10 cohort was sampled and before any V10 file was analyzed. It was not to be edited after the freeze, except through dated amendments appended at the end.

## Purpose

V8 (`docs/v8_results.md`) met its rule against the pretrained EMBER2024 PE model (R1) on 724 files: 6 detections gained and 0 lost. V9 (`docs/v9_results.md`, 1,563 files) did not confirm it:
- The candidate gained 8 detections and lost 3, at equal FPR.
- The TPR difference was +0.82 percentage points (95% CI −0.33 to +1.97).

A power estimate based on V9 (about 1.8% of malicious files discordant, about 73% of them favoring the candidate) indicated that about 2,000 or more malicious files were needed for a reasonable chance of a CI lower bound above 0. V10 was sized for that and used newly downloaded 2026 MalwareBazaar data.

## Models (Frozen, Not Refit)

The models were identical to V9:
- **Candidate:** the frozen V8 blend, `logit(R1) + 0.3 * logit(BN model)` on files with both `cap6_*` and `hl6_*` features, at the frozen blend threshold. Files without coverage used R1's decision.
- **R1:** the pretrained EMBER2024 PE model at 0.31491.
- **R2:** the frozen EMBER v3 retrained model.

All arms were loaded from `artifacts/v8/models/`, and their hashes were verified against `artifacts/v8/freeze/freeze_manifest.json` before the run.

## Data

### Malware

- **Source:** all 2026 MalwareBazaar daily archives available on 2026-11-10 (2026-01-01 to 2026-11-08), downloaded to `E:\MalwareBazaar\daily`.
- **Ingest:** statically by `src/v10/mb_ingest.py`. Only members with PE extensions (exe, dll, sys, scr, ocx, cpl) of at most 50 MB were eligible. Each member was checked for a SHA-256 matching its name and an MZ header.
- **Candidate selection:** members whose SHA-256 appeared in the existing `analysis.csv` corpus or in any prior cohort were excluded. A seeded random candidate set was then extracted (seed 20261110).

### Benign

Files from the V9 root families, at most 2 per directory:
- **Windows component stores:** WinSxS, Microsoft.NET, the .NET assembly cache, SystemApps, ProgramData, and the per-user Programs and Microsoft folders.
- **Installed applications and drivers:** Program Files, Program Files (x86) and DriverStore.

### Exclusions

Any file sharing a SHA-256, path, directory group or imphash with V1, V3, V3.1, V3.2, V4, V7, V8, V9, V9s, the 2026 temporal check or the V6 gate set was excluded.

### Diversity Rule (New in V10)

At most 3 malicious files were kept per imphash group, chosen at random with the cohort seed. In earlier cohorts, large imphash groups contributed many near-identical files.

### Target Size and Freezing

- At least 2,000 malicious files (target 2,500).
- As many benign files as the roots allowed, up to 2,000.
- The cohort was frozen (`src/v10/cohort.py`, seed 20261111) before feature extraction.

### Features

The same extractors and modes as V7 to V9:
- EMBER v3 (thrember),
- `bn_cap_v6` in intermediate mode,
- `bn_hlil_v6b` in full mode.

## Primary Decision Rule (One Shot)

The V8 improvement was confirmed only if, on the full V10 cohort, at the frozen thresholds, against R1:
1. the paired group-bootstrap 95% CI lower bound for (candidate TPR minus R1 TPR) was above 0, and
2. the candidate FPR was no higher than R1's FPR.

The same two conditions were evaluated against R2 and reported. If the primary rule was not met, the result was reported as not confirmed.

## Secondary Analyses (Descriptive)

The following were reported but could not change the primary decision:
- the exact McNemar test on discordant malware;
- detections gained and lost relative to R1;
- false positives added and removed;
- the ROC-AUC difference with a group-bootstrap CI;
- results at training-derived operating points of 0.25%, 0.5%, 1%, 2% and 5% FPR;
- results by benign root family, file type and malware month;
- a pooled analysis of V8, V9 and V10. V8 was the discovery cohort, so the pooled analysis was descriptive only.
