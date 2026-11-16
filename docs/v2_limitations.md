# SA2 V2 Limitations (draft)

- **Source confounding:** MalwareBazaar vs installed Windows/third-party benign roots may correlate with labels and BN coverage.
- **BN coverage imbalance:** Benign and malicious samples differ in extraction success rates; missing BN is not equivalent to numeric zero.
- **Low FPR resolution:** Validation (~89 benign) and V1 test (~103 benign) limit interpretability of 1% FPR operating points.
- **V1 test examined:** Frozen test results were observed in V1; they cannot serve as a blind confirmatory endpoint for V2.
- **No blind cohort yet:** Until `artifacts/v2/blind/manifest.json` exists and protocol is frozen, V2 remains **developmental/retrospective**.
- **No SOTA claim:** EMBER2024 and other benchmarks are not matched for data, labels, or metrics.

Negative V2 outcomes (PE-only preferred) are valid scientific results.

## Current V2 outcomes (2026-11-01)

| Setting | Finding |
|---------|---------|
| Validation (RF, ~1% FPR target) | **V2-B triage** lowers selective error vs full-auto PE (~13.5% vs ~14.5%) at ~89% automation |
| Validation detection | **V2-A fusion** did not beat PE-only; **B1 naive PE+BN** had highest TPR on val (development only) |
| Historical test replay (frozen V2 protocol, **not confirmatory**) | B0 **0.884**, V2-A **0.857**, B1 **0.836** TPR@~1% FPR; V2-A below PE-only |
| Confirmatory detection (H1) | **Not demonstrated** — independent blind cohort still required |

Historical replay uses thresholds calibrated on train only; V1 reported test numbers used validation-derived thresholds, so point estimates are not directly comparable row-for-row.
