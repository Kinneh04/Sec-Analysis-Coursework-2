# V10 Results: Large Replication of the V8 Blend Against EMBER2024

## Summary

The V8 improvement was confirmed under the preregistered rule (`docs/v10_preregistration.md`). The candidate detected 2331 of 2500 malicious files, against 2301 for R1. The TPR difference was +1.20 percentage points (95% CI +0.69 to +1.69). The candidate produced 3 false positives, against 4 for R1, among 2000 benign files.

The comparison against R2 (EMBER v3 retrained on the same pool) gave a TPR difference of +11.16 percentage points (95% CI +9.54 to +12.81). The rule against R2 was not met.

## Cohort

- **Malicious files:** 2500 from the 2026 MalwareBazaar daily archives (2026-01-01 to 2026-11-08), downloaded in full (312 days, size-verified) and ingested statically (`src/v10/mb_ingest.py`). At most 3 files were kept per imphash group.
- **Benign files:** 2000 from Windows component stores and installed applications, at most 2 per directory.
- **Groups:** 4089. The cohort was frozen on 2026-11-10 (`artifacts/v10/manifests/`, seed 20261111). It was disjoint by SHA-256, path, directory group and imphash from all prior cohorts.
- **Binary Ninja coverage (both feature sets):** 77.8% of benign and 71.8% of malicious files. Uncovered files used R1's decision, as frozen.
- **Feature extraction:** EMBER v3 and Binary Ninja features used the same extractors and analysis modes as V7 to V9. No sample was executed.
- **Dropped:** 0 files lacked EMBER features.

## Primary Result (Frozen V8 Thresholds, No Refitting)

| Arm | TPR | True positives | False positives | FPR |
|------|------|------|------|------|
| Candidate (V8 blend) | 0.9324 | 2331 / 2500 | 3 / 2000 | 0.15% |
| R1: pretrained EMBER2024 | 0.9204 | 2301 / 2500 | 4 / 2000 | 0.20% |
| R2: EMBER v3 retrained | 0.8208 | 2052 / 2500 | 1 / 2000 | 0.05% |

| Comparison | Change in TPR (95% CI) | FPR not higher | Rule met |
|------|------|------|------|
| Candidate minus R1 | +1.20 (+0.69 to +1.69) | Yes | Yes |
| Candidate minus R2 | +11.16 (+9.54 to +12.81) | No | No |

Relative to R1, the candidate gained 35 malicious detections and lost 5. It added 0 false positives and removed 1. The exact McNemar test on discordant malware gave p = 1.38e-06.

## Secondary Results (Descriptive)

The candidate's ROC-AUC was 0.9980, against 0.9975 for R1. The difference was +0.0005 (group-bootstrap 95% CI +0.0002 to +0.0010).

| Training FPR | Candidate TP / FP | R1 TP / FP | Gained / lost | False positives added / removed | McNemar p |
|------|------|------|------|------|------|
| 0.25% | 2084 / 0 | 2111 / 2 | 16 / 43 | 0 / 2 | 0.000584 |
| 0.5% | 2223 / 3 | 2199 / 3 | 41 / 17 | 0 / 0 | 0.00223 |
| 1% | 2331 / 3 | 2301 / 4 | 35 / 5 | 0 / 1 | 1.38e-06 |
| 2% | 2392 / 6 | 2366 / 6 | 28 / 2 | 0 / 0 | 8.68e-07 |
| 5% | 2454 / 11 | 2435 / 9 | 19 / 0 | 2 / 0 | 3.81e-06 |

| Subset | Candidate TP / FP | R1 TP / FP | Gained / lost | 95% CI for change in TPR |
|------|------|------|------|------|
| benign_components | 2331 / 0 | 2301 / 1 | 35 / 5 | +0.70 to +1.73 |
| benign_applications | 2331 / 3 | 2301 / 3 | 35 / 5 | +0.72 to +1.72 |
| bn_covered | 1692 / 3 | 1662 / 4 | 35 / 5 | +1.00 to +2.38 |

By file type: `.cpl`: 0 against 0 of 0 malicious, with 0 against 0 of 6 benign; `.dll`: 98 against 92 of 126 malicious, with 0 against 1 of 1716 benign; `.exe`: 2231 against 2208 of 2369 malicious, with 3 against 3 of 229 benign; `.ocx`: 0 against 0 of 0 malicious, with 0 against 0 of 2 benign; `.scr`: 0 against 0 of 0 malicious, with 0 against 0 of 4 benign; `.sys`: 2 against 1 of 5 malicious, with 0 against 0 of 43 benign.

By malware month, the candidate detected more malicious files than R1 in 11 of 11 months and fewer in 0.

| Pooled (descriptive) | Candidate TP / FP | R1 TP / FP | Gained / lost | McNemar p | 95% CI for change in TPR |
|------|------|------|------|------|------|
| pooled_v9_v10 | 2872 / 5 | 2837 / 6 | 43 / 8 | 6.87e-07 | +0.68 to +1.60 |
| pooled_v8_v9_v10 | 3279 / 5 | 3238 / 6 | 49 / 8 | 2.72e-08 | +0.73 to +1.58 |

The V9 + V10 pool excluded V8, the cohort on which the improvement was first observed. The V8 + V9 + V10 pool included it, so that pool was not independent confirmation.

## Conclusion

On this larger independent cohort, the frozen V8 blend met the preregistered confirmation rule against R1. The gain remained small (+1.20 percentage points at the frozen 1% FPR threshold). The ROC-AUC difference was +0.0005 (95% CI +0.0002 to +0.0010). At the strictest training operating point (0.25% FPR), the candidate gained 16 detections and lost 43. At 5% FPR, it gained 19 and lost 0. The most accurate claim is therefore a modest, confirmed detection gain near 1% FPR on local MalwareBazaar 2026 data, with the same caveats as earlier waves: possible degradation at very strict thresholds, single-host benign sampling, and no evaluation on EMBER2024's own binaries (which are not released).

## Limitations

- Pass 2 (HLIL) was stopped early at 3584 of 4500 queued files to obtain a timely decision. Uncovered files used R1's decision, as preregistered; fuller Binary Ninja coverage could change secondary operating-point results but the primary rule was evaluated on the locked one-shot run.
- All malware came from MalwareBazaar, and all benign files came from a single Windows host. Benign files were mostly Windows component files; few were installed-application executables.
- Binary Ninja ran through the GUI MCP server with per-file time budgets. Files without full coverage used R1's decision.
- EMBER2024's own test and challenge sets could not be used, because they do not include binaries.

## Artifacts

- `artifacts/v10/blind/replication_results.json` (locked by `replication_run.lock`),
- `artifacts/v10/blind/replication_scores.parquet`,
- `artifacts/v10/manifests/`,
- `artifacts/v10/mb2026_index.parquet` and `artifacts/v10/mb2026_extracted.parquet`,
- `src/v10/` (ingest, cohort, watchdog, chain, replicate and report).
