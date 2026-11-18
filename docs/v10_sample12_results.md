# Sample1 / Sample2 Check: V8 Blend vs EMBER2024

## Summary

On Sample1/Sample2, the V8 blend detected fewer files than EMBER2024 (1 against 2 of 7).

These are qualitative course POC holdouts (expected malicious). This is not a powered confirmation test.

## Results (Frozen V8 Thresholds)

| File | R1 score | Candidate score | R2 score | R1 | Candidate | R2 | BN cap/hlil |
|------|------|------|------|------|------|------|------|
| `Sample1/client.exe` | 0.9957 | 6.6920 | 0.0351 | mal | mal | ben | ok/ok |
| `Sample2/out/loader.exe` | 0.3762 | -0.6318 | 0.9992 | mal | ben | mal | ok/ok |
| `Sample2/out/helper.dll` | 0.0321 | -1.5175 | 0.7461 | ben | ben | ben | ok/ok |
| `Sample2/out/exec.dll` | 0.1514 | -1.9603 | 0.9458 | ben | ben | ben | ok/ok |
| `Sample2/out/protect.dll` | 0.1730 | -1.6773 | 0.9530 | ben | ben | ben | ok/ok |
| `Sample2/out/read_write.dll` | 0.0567 | -2.5447 | 0.9471 | ben | ben | ben | ok/ok |
| `Sample2/out/open.dll` | 0.0814 | -2.0429 | 0.9586 | ben | ben | ben | ok/ok |

- Candidate gained 0 and lost 1 relative to R1.
- Binary Ninja coverage: 100%.

## Artifacts

- `artifacts/v10/sample12/`
