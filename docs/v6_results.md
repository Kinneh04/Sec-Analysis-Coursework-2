# V6 Results: Binary Ninja Capability and Evasion Indicators

## Summary

V6 tested whether code-level indicators extracted with Binary Ninja could detect malware that the pretrained EMBER2024 PE model missed. The work stopped at the development gate. Both gate criteria failed, so no preregistration was written, no new blind cohort was frozen, and no confirmatory evaluation was run. The goal of beating EMBER2024 with Binary Ninja features was not met by V6.

## Hypothesis

EMBER v3 features describe file structure: headers, sections, the import table, byte histograms and printable strings. Several evasion techniques are visible only in code:
- dynamic API resolution through `GetProcAddress`,
- API-name hashing,
- walking the PEB loader list and parsing export directories,
- stack strings,
- byte-wise XOR loops,
- direct system calls,
- behavior assembled from APIs inside a single function (injection, keylogging, screen capture, anti-debugging).

The working hypothesis was that Binary Ninja disassembly of all functions would expose these techniques in the malware that EMBER2024 missed.

## Where EMBER2024 Missed Malware

The consumed cohorts (V3.2 blind, the 2026 temporal check and V4 blind) were pooled as development data only. They were scored with the pretrained EMBER2024 model at the V4 frozen threshold (0.3537). Strata were computed with pefile, identically for both classes.

| Stratum (pefile traits) | Malicious files | Missed by EMBER2024 | Miss rate |
|------|------|------|------|
| Ordinary native (no CLR header, no packer section names, max section entropy below 7.2, 20 or more imports) | 526 | 65 | 12.4% |
| Packed or minimal-import (packer section names, 8 or fewer imports, or entropy of 7.2 or higher) | 399 | 17 | 4.3% |
| .NET | 142 | 0 | 0.0% |
| Other native | 27 | 0 | 0.0% |

EMBER2024 detected packed and minimal-import malware well. Its misses were concentrated in structurally ordinary native programs. The primary target stratum was therefore changed from "packed" to "ordinary native" before any capability feature was examined.

## Method

- **Extractor:** `src/v6/bn_capabilities.py` (version `bn_cap_v6`).
  - All functions were disassembled, largest first, with a 120-second disassembly budget, a 90-second analysis timeout and up to 5,000 functions per file. Binary Ninja ran in intermediate analysis mode.
  - Per-function summaries were cached in `artifacts/v6/cap_cache/`. Each summary held the APIs called (resolved through the IAT, jump thunks and registers loaded from the IAT), the referenced strings, and the instruction indicators.
  - The file-level features (`cap6_*`, 58 columns) were derived from these cached summaries.
- **Static preparation (`src/v6/unpack.py`):** no sample code was executed.
  - Files larger than 16 MB had their overlay removed when the PE image itself fit within 16 MB (12 files).
  - UPX-packed files were unpacked with `upx -d` (4 files unpacked, 2 failures).
- **Gate set:** `artifacts/v6/manifests/gate_queue.csv` held 632 files:
  - all 82 EMBER2024-missed malware,
  - 200 randomly sampled detected malware,
  - 350 randomly sampled benign files.

  Of these, 607 were analyzed (506 complete, 101 partial), 18 were skipped as too large, and 7 failed.

## Gate A: Indicator Signal

The criterion required that at least 30% of the missed malware fire a strong indicator or a capability rule, while 3% or fewer of the benign files did.

| Group | Files analyzed | Strong indicator | Strong indicator or capability rule |
|------|------|------|------|
| Malware missed by EMBER2024 | 76 | 13.2% | 42.1% |
| Malware detected by EMBER2024 | 197 | 7.6% | 32.5% |
| Benign | 334 | 4.5% | 11.1% |

Gate A failed. In the ordinary native stratum, 14.2% of benign files (27 of 190) fired an indicator or rule, compared with 45.0% of missed malware (27 of 60).

Selected indicator rates (missed malware, detected malware, benign):
- PEB access and export parsing in one function: 3.9%, 1.5%, 0.6%.
- Known ROR13 or CRC32 API-hash constants: 0%, 0%, 0%.
- Sensitive API names resolved dynamically: 2.6%, 0.5%, 0%.
- Indirect call after `GetProcAddress` in the same function: 31.6%, 22.3%, 11.4%.
- Rotate-and-compare loop: 30.3%, 28.4%, 13.5%.
- Anti-debugging API in a function: 26.3%, 15.2%, 7.8%.
- Screen-capture API pair: 9.2%, 8.6%, 0.3%.
- Injection API set: 0%, 1.5%, 0%.
- Overlay stripped (file inflation): 10.5%, 2.0%, 0%.

The techniques expected to separate the classes most clearly (PEB walking, API hashing and dynamic resolution of sensitive APIs) appeared in under 4% of the missed malware. The more common indicators (rotate loops, indirect calls after resolution, anti-debugging APIs) also appeared in a substantial share of benign software.

## Gate B: Model Gain over EMBER2024

The criterion required a gain of at least 5 true positives over R1 (the pretrained EMBER2024 model) with no extra false positives. The stacker was a LightGBM model over the R1 logit plus `cap6_*` features, trained with 5-fold `StratifiedGroupKFold` on the gate set. Both models were compared at a threshold of 1% FPR on their own out-of-fold benign scores (3 false positives each). R1 detected 219 of 282 malicious files at that threshold.

| Feature set | Gain in true positives over R1 across 10 seeds | Median | Seeds with gain of 5 or more |
|------|------|------|------|
| All `cap6_*` (58) | −51, 8, 10, 0, 6, −18, 9, 11, 10, 7 | +7.5 | 7 of 10 |
| Generic counts only (9) | −54, 3, 12, 0, 5, 1, 4, 5, 3, −6 | +3.0 | 3 of 10 |
| Evasion and capability indicators only (49) | −46, 11, 2, 2, 11, −21, 2, 9, 1, −6 | +2.0 | 3 of 10 |

Gate B failed. The gain was unstable across seeds, and most of it came from generic size and call-composition counts, not from the evasion and capability indicators. The gate set was also enriched with EMBER2024-missed malware (82 of 282 malicious files, compared with about 8% in the natural cohorts), so these gains overstated what a natural blind cohort would show.

## Follow-Up: Function Novelty

`src/v6/dev_novelty.py` tested whether missed malware contained more functions never seen in benign software.
- **Function fingerprint:** instruction count, called APIs and referenced strings, using only functions of 12 or more instructions.
- **Novelty fraction:** the share of a file's functions whose fingerprint did not occur in any benign file from other grouped CV folds.

| Group | Files | Median novel-function fraction |
|------|------|------|
| Malware missed by EMBER2024 | 76 | 0.144 |
| Malware detected by EMBER2024 | 196 | 0.119 |
| Benign | 306 | 0.128 |

The novelty fraction did not separate missed malware from benign files (ROC-AUC 0.553). A stacker of the R1 logit plus the novelty fraction lost 3 to 9 true positives relative to R1 on all 10 seeds (median −7). This check was also negative.

## Follow-Up: Full-Analysis HLIL Indicators (V6b)

`src/v6/bn_hlil.py` (version `bn_hlil_v6b`) ran Binary Ninja in full analysis mode and parsed HLIL for every non-library function (name `sub_*`), largest first, within a 150-second budget. Functions named by Binary Ninja signatures were treated as library code. Extracted indicators:
- constant API names passed to `GetProcAddress`,
- resolution results stored to globals,
- `LoadLibrary` and `GetModuleHandle` module names,
- stack strings rendered as `__builtin_strcpy` and similar calls,
- string literals passed to known APIs,
- the V6 capability rules, re-evaluated on HLIL call sets.

All 632 gate files were processed. 603 were usable (75 missed malware, 195 detected malware, 333 benign), at a median of roughly one minute per file.

| Group | Strong HLIL indicator (sensitive API resolved by name, or API/DLL name built on the stack) | Strong indicator or capability rule |
|------|------|------|
| Malware missed by EMBER2024 | 5.3% | 50.7% |
| Malware detected by EMBER2024 | 10.8% | 43.6% |
| Benign | 1.2% | 11.1% |

Gate A failed again (benign rate above 3%). The most specific HLIL rules (keylogging, clipboard and screen-capture API use in user code) fired in 8% to 11% of missed malware and 0% of benign files. They fired at similar rates in detected malware, so they added little beyond EMBER2024.

| Stacker over the R1 logit plus | Gain in true positives over R1 across 10 seeds | Median | Seeds with gain of 5 or more | Negative seeds |
|------|------|------|------|------|
| `hl6_*` only | 8, 0, −1, −1, −5, −5, −1, −8, −2, −3 | −1.5 | 1 | 8 |
| `hl6_*` and `cap6_*` | 10, 16, 11, 4, 12, −5, 7, 8, 10, 14 | +10.0 | 8 | 1 |

R1 detected 215 of the malicious files at the matched 1% FPR threshold. Gate B, as defined for V6b (HLIL features with a gain of 5 or more on every seed), failed. The combined HLIL and V6 feature set was the strongest development result in the project (median +10). It was only modestly better than V6 features alone (median +7.5), however, and it was measured on a gate set enriched with EMBER2024-missed malware. With the natural miss rate of about 8%, the expected gain on a natural blind cohort is a few true positives per several hundred malicious files. Showing a 95% CI lower bound above 0 for that gain would need a blind cohort far larger than earlier waves, plus both extractors run on a full training pool, at about two minutes per file.

## Interpretation

- The malware EMBER2024 missed in these cohorts did not, in most cases, use the code-level evasion techniques that a disassembler exposes uniquely. PEB walking, API hashing and dynamic resolution of sensitive APIs were rare.
- Most missed samples were ordinary native programs (MSVC, Delphi, MinGW, LLVM and Visual Basic builds) with large import tables. Their maliciousness was not expressed through distinctive code patterns at the level these indicators capture.
- File inflation was more common among the missed malware (10.5%) than among detected malware (2.0%) or benign files (0%). This is a structural trait that does not need Binary Ninja to detect.

## Limitations

- The development set was small (76 analyzed missed malware) and pooled from cohorts already used for evaluation.
- V6 indicators came from intermediate-mode disassembly text. V6b added full-analysis HLIL text, but not cross-function data flow, so API names computed at runtime or decrypted before use were not recovered.
- Packers other than UPX were not unpacked, because doing so requires emulation or execution, which the project rules excluded.
- EMBER2024's own test and challenge sets could not be used with Binary Ninja features, because the EMBER2024 release does not include binaries. No EMBER2024 metadata was downloaded for hash matching.

## Status

No confirmatory claim was made. The goal of beating EMBER2024 with Binary Ninja features remained unmet after V6. Artifacts:
- `artifacts/v6/dev_gate.json`,
- `artifacts/v6/dev_ablation.json`,
- `artifacts/v6/dev_novelty.json`,
- `artifacts/v6/dev_gate_hlil.json`,
- `artifacts/v6/hlil_cache/`,
- `artifacts/v6/manifests/gate_queue.csv`,
- `artifacts/v6/cap_cache/`.
