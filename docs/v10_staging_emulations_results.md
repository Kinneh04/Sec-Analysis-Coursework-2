# Staging Emulations Check: V8 Blend vs EMBER2024

## Summary

On these staging emulation PE samples, the frozen V8 blend matched pretrained EMBER2024 (84 of 87 detected). Binary Ninja coverage was 100.0%.

This set contained only malicious labels, so false-positive rate could not be compared. It is a descriptive check, not a replacement for the V10 confirmation rule.

## Data

- Source: `staging-emulations.zip` (87 PE files scored; non-PE/MSI excluded from the PE model comparison).
- Binary Ninja coverage (both feature sets): 100.0% (87 / 87). Uncovered files used R1's decision.
- Dropped for missing EMBER features: 0.

## Primary Comparison (Frozen V8 Thresholds)

| Arm | Detections | TPR |
|------|------|------|
| Candidate (V8 blend) | 84 / 87 | 0.9655 |
| R1: pretrained EMBER2024 | 84 / 87 | 0.9655 |
| R2: EMBER v3 retrained | 40 / 87 | 0.4598 |

Gained 0 detections and lost 0 relative to R1. Exact McNemar p = 1.

## By Scenario

| Scenario | N | Candidate | R1 | R2 | BN covered |
|------|------|------|------|------|------|
| banker-form-mock | 6 | 6 | 6 | 1 | 6 |
| c2-beacon | 7 | 7 | 7 | 3 | 7 |
| cryptominer-stub | 6 | 6 | 6 | 3 | 6 |
| dll-sideload | 6 | 5 | 5 | 4 | 6 |
| downloader | 6 | 6 | 6 | 2 | 6 |
| dropper | 5 | 5 | 5 | 2 | 5 |
| keylogger-stub | 5 | 4 | 4 | 4 | 5 |
| mutex-gate | 7 | 7 | 7 | 4 | 7 |
| persistence-reg | 4 | 4 | 4 | 2 | 4 |
| process-hollow-stub | 7 | 7 | 7 | 4 | 7 |
| ransomware-sim | 6 | 6 | 6 | 4 | 6 |
| rat-heartbeat | 6 | 6 | 6 | 1 | 6 |
| stealer-sim | 6 | 6 | 6 | 2 | 6 |
| trojan-fake-installer | 5 | 5 | 5 | 2 | 5 |
| worm-copy-stub | 5 | 4 | 4 | 2 | 5 |

## Artifacts

- `artifacts/v10/staging_emulations/eval/`
