# SA2 Feature-Value and Leakage Audit — Implementation Plan

**Status:** Ready for implementation  
**Scope:** Existing frozen SA2 cohort and v2 extracted features only  
**Primary goal:** Determine whether Binary Ninja (BN) structured features contribute information beyond conventional PE features, and whether dataset artifacts or analysis coverage explain the observed lack of improvement.  
**Not a goal:** Claim SOTA superiority, re-extract binaries, change frozen splits, or optimize on the frozen test set.

## 0. Background and immutable facts

Prior completed experiment (reported values, **not** to be silently recomputed/replaced):

- Frozen inventory: 978 rows (478 benign / 500 malicious); PE-extractable cohort: 968.
- Frozen split assignments already exist; maintain their SHA-256 and group assignments exactly.
- BN extraction on PE-ok cohort: benign 420 `ok`, 28 `partial`, 11 `skipped`, 19 `error`; malicious 442 `ok`, 0 `partial`, 35 `skipped`, 13 `error`.
- Frozen test: approximately 292 samples. RF at 1% FPR: PE-only ~0.926 TPR, PE+BN ~0.884, BN-only ~0.16. Paired delta (PE+BN minus PE): ~-0.042, bootstrap 95% CI roughly [-0.107, +0.032]. LightGBM also favors PE-only in point estimates.
- Sample1/Sample2 related POCs are **qualitative holdouts** and must remain outside all model selection and quantitative analysis.
- These results do **not** prove BN is harmful or that a published SOTA result has been beaten.

**Inputs expected in repository** (inspect rather than assume exact schemas):

- `configs/local.yaml`
- `artifacts/manifests/corpus_inventory.parquet`
- `artifacts/manifests/split_assignments.parquet`
- `artifacts/manifests/cohort_frozen.json`
- `artifacts/manifests/frozen_{train,val,test}_sha256.txt`
- `artifacts/manifests/challenge_qualitative_sha256.txt`
- `artifacts/manifests/challenge_quantitative_sha256.txt` (may be empty)
- `artifacts/features/pe_features.parquet`
- `artifacts/features/bn_features_v2.parquet`
- existing `src/build_dataset.py`, `src/train.py`, `src/paired_eval.py`, `src/common/` and model artifacts.

No direct inspection of the current working copy is implied by this plan; the agent must confirm column names and available saved model configurations before implementation.

## 1. Guardrails — non-negotiable

1. **Do not invoke Binary Ninja, MCP, any sample, or the extraction pipeline.** Read existing parquet/JSON/CSV artifacts only. Do not execute malware. Do not modify local sample files.
2. **Do not re-inventory, re-freeze, regenerate labels, alter the PE/BN feature schema, or reassign splits.** Treat the frozen SHA files as authoritative; verify they agree with `split_assignments.parquet` and `cohort_frozen.json`. Fail closed on inconsistency.
3. **Do not inspect frozen test labels, predictions, or feature–label associations to select features, preprocessing, model settings, thresholds, or reported conclusions about which approach to deploy.** Existing previously reported frozen-test results may appear in a separately labeled *historical context* section, but no new test-guided decisions.
4. **Only train partition may fit imputers, encoders, scalers, feature filters, models, or feature statistics used for transforms.** Use validation for comparing predefined candidates and selecting thresholds at specified FPR. Never fit preprocessing on train+val before validation decisions.
5. **Do not use `label`, `sha256`, sample paths, source labels, installation root, imphash, group IDs, split name, timestamps, analyst notes, cache identifiers, extraction status or error messages as predictors in the primary model.** Status/coverage may be audited as diagnostics. Some pure coverage metrics (e.g., IL count) can be tested in a *separate, explicitly labeled exploratory arm* only, with methodological justification.
6. **No test-time dropping of failures just to obtain attractive scores.** Keep a full-cohort analysis with a documented missingness policy. Report complete-case results only as a secondary selection-biased sensitivity analysis.
7. **Reproducibility:** deterministic sorting by SHA-256, fixed random seed, hashes of input artifacts/config, complete candidate list, library versions, and immutable outputs. Do not overwrite prior experimental outputs.
8. **No claims of SOTA or confirmed improvement** without independent appropriate evidence. If hypotheses fail, report negative results faithfully.

## 2. Output structure and proposed modules

Implement the following standalone, read-only analysis pipeline under `src/audit/` (or integrate into existing utilities if cleaner). Keep all new outputs under `artifacts/feature_audit/`:

```text
src/audit/
  __init__.py
  inputs.py                  # read/verify frozen SHA and feature tables
  schema.py                  # allow/deny lists, feature families, dtypes
  diagnostics.py             # coverage, missingness, distribution, drift
  leakage.py                 # leakage checks, source-label confounding
  contribution.py            # validation-only feature-value experiments
  report.py                  # HTML/Markdown + JSON summaries
  cli.py                     # single orchestrator

tests/test_feature_audit.py
artifacts/feature_audit/
  run_manifest.json
  schema_report.json
  split_integrity.json
  coverage_by_class_source.csv
  feature_quality.csv
  source_label_confounding.json
  redundancy_groups.csv
  validation_ablation.csv
  validation_ci.json
  error_analysis_validation.csv
  audit_summary.json
  audit_report.md
```

CLI (suggested):

```powershell
cd C:\Users\user\Downloads\SA2
.\.venv\Scripts\python.exe -m src.audit.cli --config configs/local.yaml --output artifacts/feature_audit --seed 42
.\.venv\Scripts\python.exe -m pytest tests/test_feature_audit.py -q
```

Add `--dry-run` to check schemas, input availability, split integrity, and feature candidates without fitting models. Add `--strict` to error on unexpected label/provenance/predictor columns. Keep diagnostic outputs free of raw malware content or personally identifying file paths where practical.

## 3. Milestone A — Freeze and validate inputs (first priority)

### A1. Snapshot and provenance

- Record paths, sizes, SHA-256 hashes and modification timestamps of all parquet, frozen-split, JSON and config inputs actually used.
- Record Python, pandas, scikit-learn, LightGBM and other dependency versions; random seed and Git commit, if available.
- Confirm one row per SHA in each feature table. On duplicates: stop and report; **do not** silently pick first.
- Verify labels are consistent across inventory and any joined tables. Predictor matrices must not contain labels or path-derived metadata.
- Verify frozen train/val/test are disjoint, their SHA counts and membership match the authoritative manifest, and qualitative POCs are excluded.
- Record PE rows with no BN record, BN extraction states and analysis coverage; do not silently inner join for the primary analysis.

### A2. Alignment

- Join feature data to the frozen manifest with `validate='one_to_one'` (or equivalent), using SHA as key.
- Create one aligned **train**, **validation**, and **test** index. For this audit, materialize only train and validation predictors/labels for modeling and importance checks; test membership/hash counts may be checked without reading test labels into selection code.
- Define and save exact PE feature columns, BN feature columns, and exclusions with reasons.
- Detect overlapping/conflicting names, encoded labels, constant or all-missing columns, nonnumeric features, and potentially leaked metadata.

**Gate A PASS:** no label mismatch, duplicate SHA, split or group overlap, qualitative challenge contamination, unauthorized predictor or unexplained join loss. Otherwise STOP.

## 4. Milestone B — Audit extraction availability and possible confounding

Use frozen **train + validation only** for any analysis that could influence feature/model choices; also produce separate *descriptive-only* overall coverage counts from the completed extraction ledger without affecting decisions.

### B1. Coverage and failure taxonomy

- Per split and class: `ok`, `partial`, `skipped`, `error`, missing record; include denominators.
- Per source family/root, architecture, file-size bands and PE sections: the same coverage statuses, with small-cell safeguards.
- Quantify MLIL instruction counts, recovered function counts, analyzed-function fraction, CFG coverage, zero-IL frequency, missing BN feature fraction and analysis latency (median/p90) where available.
- Separate **no code recovered** from **analysis failed** from **legitimately zero operations** and **policy-skipped**; preserve exact original status in diagnostics.
- Check whether simple conditions such as file size >4 MB, architecture or software origin explain skips.

### B2. Quantify missing-not-at-random risk

- Compare BN availability by class with counts and proportion differences plus uncertainty intervals; do not interpret a p-value alone.
- Compute simple associations of availability with file size, source root and class. A diagnostic logistic regression predicting **extraction success** from nonlabel covariates is allowed; it is **not** a malware classifier.
- Determine whether `bn_status`, error/skip reason, latency or feature completeness accidentally enters predictive columns.
- Explicitly flag if malware and benign missingness differs materially or complete-case selection changes class/source composition.

**Gate B PASS:** status/coverage can be audited without accidentally serving as model targets or source/label proxies. If any leakage exists, remove it from predictor matrices and document affected prior results as potentially biased; do not silently rewrite previous experiments.

## 5. Milestone C — Feature quality and redundancy

Perform descriptive feature analysis primarily on **training data**. Validation distributions may be compared for robustness but not to fit transformations.

For each PE/BN candidate feature record:

- feature name, family, dtype, source definition, allowed/disallowed predictor status;
- missing count and percentage overall/by class (train only);
- finite-value rate; zero rate, near-constant rate, approximate unique values;
- median, 1st/99th percentiles, range and high-outlier flags;
- consistency with schema, normalization and expected units;
- possible confounding by software source, architecture or file size.

Specific checks:

1. Constant and >95%-missing BN features; propose *train-fitted* filters, not automatic deletion across all splits.
2. BN metrics that proxy file size or code volume (counts vs ratios), and duplicated metadata already present in PE features.
3. Pairwise rank correlations on **training only**; flag pairs with |Spearman rho| >= 0.95. Identify feature clusters; do not automatically claim correlation means uselessness for trees.
4. If MLIL/CFG features are missing, confirm semantics of imputed value and presence/absence indicators. `0` must not mean extraction failure unless explicitly defined and tested.
5. Distribution shift train -> validation, particularly source roots, PE sizes and BN coverage.
6. Diagnostic feature importance must distinguish *predictive value* from *true malicious behavior*. Do not interpret SHAP/correlation as causal proof.

Write `feature_quality.csv`, `redundancy_groups.csv`, and a concise ranked list of suspect columns with remediation reasons.

## 6. Milestone D — Measure incremental BN value without touching test

### D1. Define fixed candidate arms **before** comparing validation metrics

All candidates use the same frozen train/validation SHA set and the same target labels. Missing BN rows must remain represented in the primary arms.

- **P0 PE baseline:** existing PE features only.
- **P1 PE + all authorized BN numeric features:** no status, path, source or failure codes as predictors.
- **P2 PE + BN quality-filtered features:** train-only variance/missingness filter; list derived only from training data.
- **P3 PE + BN residual/redundancy-reduced features:** train-only removal of strongly redundant BN columns or preregistered groups; retain transparent rationale.
- **P4 BN-only diagnostic:** to understand informativeness, not a recommended deployment model.
- **P5 Optional coverage/status-only diagnostic:** explicitly marked **non-deployable leakage-risk probe**, trained on training data and evaluated on validation only. Its role is to expose dataset artifact predictability, never to enhance deployed classification.

If time is short, run P0/P1/P2/P4 first. Avoid a combinatorial search across BN subsets.

### D2. Fixed models, pipelines and metrics

- Primary: existing Random Forest and LightGBM settings (load saved configuration; no retuning on test).
- Coursework comparability: include Logistic Regression if practical, with training-fitted imputation/scaling.
- Use identical feature-table version, train/val partitions, and target construction for every arm.
- Choose imputation suitable for each model; document the train-fitted transform and how missing BN rows behave. Consider a consistent indicator when differentiating failure from true zero, but make this a diagnostic because status itself may encode corpus artifacts.
- Pre-register primary metric: **validation TPR at a threshold chosen to meet <=1% FPR on a disjoint threshold-calibration subset of training**, not on the validation/test set. Since class counts are small, additionally report ROC-AUC and PR-AUC, recall/precision/F1 with full confusion matrices and intervals.
- Better approach to avoid tiny calibration resolution: repeated **group-aware cross-validation within the training partition** for comparative feature-value analysis; keep the original validation partition for a single final comparison. Save all folds and the threshold rule. Calibration resolution must be reported honestly.
- Specify whether a given FPR threshold is interpolated on an ROC curve or derives from an attainable integer false-positive count; never report interpolated rates as operationally guaranteed.
- Predefine a practical difference margin (e.g. +2 percentage points TPR at fixed FPR) and extraction-latency cost; this is a decision criterion, not a p-value threshold.

### D3. Paired uncertainty

- Evaluate predictions for identical validation SHA records; compute deltas for P1/P2/P3 vs P0.
- Use **paired group-aware bootstrap** over independent sample groups, stratifying by class where possible; refit thresholds within each replicate only if the method and calibration partition are prespecified and the sample sizes support it.
- Report 95% interval, bootstrap method, seed, number of resamples, group-level sample sizes, and fraction of resamples favoring PE+BN. Small validation benign count implies poor precision at 1% FPR—state this prominently.
- If uncertainty cannot be estimated reliably, emit `insufficient_resolution` rather than a misleading precise interval.
- Keep paired predictions and detailed false-negative analysis **validation-only**; do not use qualitative POCs for optimization.

### D4. Permutation and grouped importance (validation only)

- On the frozen validation subset, use permutation importance for **feature families**: PE metadata, imports, section statistics, BN CFG, BN MLIL, BN coverage-derived numeric features (diagnostic), etc.
- Prefer group-wise permutation to mitigate misleading single-feature importance from correlated variables.
- Repeat with fixed seeds, confidence intervals, and limited repeats; compare changes in ROC-AUC or other continuous metrics rather than TPR@1% FPR alone because the latter is coarse.
- Optional SHAP on trained trees for interpretation; disclose that SHAP importance is associative and can be unstable under correlated features.
- Investigate wrong predictions on validation, stratified by class, size, BN coverage and third-party benign root. No payload-level execution or new binary analysis.

**Gate D PASS:** results are paired, reproducible and explicitly confined to train/validation; comparisons distinguish utility, redundancy and dataset artifact risk. A non-positive outcome is valid.

## 7. Milestone E — Decision table (without test tuning)

Choose **one** conclusion using train/validation only:

| Outcome | Meaning | Decision |
|---|---|---|
| BN gives clear, stable validation lift across source/size strata and confidence intervals support improvement | Possible incremental value | Freeze selected feature arm and parameters; a **new independent blind test** is required for a fresh generalization claim because old test results are already known |
| BN is indistinguishable from PE after controlling missingness and redundancy | No supported incremental value | Recommend PE-only operational model; retain BN as analyst-enrichment research artifact |
| BN harms validation performance, especially on coverage-poor subgroups | Representation/missingness likely problematic | Recommend PE-only; document failure modes |
| Success depends on BN extraction status, source, size or label proxies | Spurious artifact | Reject the apparent lift; document leakage/confounding and correct the feature pipeline |
| Validation too small or contradictory | Inconclusive | Report uncertainty; avoid new tuning or SOTA language |

Do **not** select a feature arm because it performs best on previously seen frozen test metrics. No additional old-test evaluation is necessary for this audit.

## 8. Milestone F — Report and artifact requirements

Generate a self-contained `audit_report.md` with:

1. Scope, existing frozen cohort and precise analysis partitions.
2. Data provenance and immutable run hashes.
3. Feature-family dictionary and explicit prohibited columns.
4. BN extraction coverage by class/source/size, including failures and policy skips.
5. Feature missingness, redundancy, quality and leakage-risk findings.
6. Train/validation ablation table (PE vs PE+BN vs selected subsets), uncertainty and honest FPR-resolution caveats.
7. Group-level importance and validation error analysis.
8. Recommendation for deployment and next research step.
9. Historical **frozen-test** numbers in a clearly separated, non-decision-making appendix, only if included at all.
10. Limitations: dataset source confounding, sample-family grouping by imphash, small benign validation/test groups at low FPR, coverage imbalance, already-observed test results, no benchmark-compatible SOTA comparison.

Also generate a concise `audit_summary.json` with machine-readable fields:

```json
{
  "input_integrity": "pass|fail",
  "leakage_risk": "none_detected|suspected|confirmed",
  "bn_missingness_by_class": {},
  "high_redundancy_features": [],
  "candidate_arms": [],
  "primary_validation_metric": "TPR_at_precalibrated_1pct_FPR",
  "conclusion": "incremental_value_supported|not_supported|artifact_driven|inconclusive",
  "sota_claim_supported": false,
  "test_used_for_selection": false,
  "extraction_performed": false
}
```

Populate values from real outputs; never fabricate results or silently translate missing fields into zeros.

## 9. Tests and acceptance criteria

Implement automated tests with small synthetic DataFrames; run tests before running the whole audit.

- [ ] Split verification rejects duplicated SHA, label inconsistencies, overlap and qualitative challenge contamination.
- [ ] Join cardinality checks fail on duplicate or unexpectedly missing feature records; absent BN rows remain explicit.
- [ ] Predictor allow-list excludes SHA, labels, source roots, file paths, imphash/group IDs, split, status/error and cache metadata.
- [ ] Train-only feature filtering and transformations are proven not to fit on validation/test.
- [ ] Frozen-test features/labels are not read by contribution/selection modules (enforce with mock or guard).
- [ ] Missing BN features distinguish unavailable analysis from valid numeric zero.
- [ ] Group-aware resampling and paired comparisons align on SHA; reproducible fixed seed.
- [ ] Coverage denominators and class-specific status proportions are correct.
- [ ] FPR threshold calculations disclose finite-sample resolution (e.g. when only 89 benign validation samples are available).
- [ ] Incomplete or invalid inputs produce actionable errors, not apparently successful empty artifacts.
- [ ] No calls to `src.bn_features`, Binary Ninja MCP, executable binaries, or raw malware extraction.
- [ ] Report clearly states whether BN contributed validation lift; SOTA remains `false`.

**Final acceptance:** one command produces a deterministic audit bundle, all tests pass, no extraction occurs, no frozen split changes, no feature/model selection on test, and the narrative reflects the observed data rather than a desired win.

## 10. Fast execution schedule

1. **Input integrity + no-test-access guard:** implement first; stop if failure.
2. **Coverage/leakage report:** analyze class/source/size and predictor allow-list.
3. **Feature quality:** missingness, constants, redundancy, normalization and coverage dependence.
4. **Small preregistered validation ablation:** P0/P1/P2/P4 with RF and LightGBM; add LR if quick.
5. **Paired uncertainty + interpretation:** group-aware bootstrap and family importance on validation.
6. **Report and sign-off:** synthesize findings; archive input hashes and scripts.

Do not hold up report completion for computationally expensive optional SHAP or more model variants.

## 11. Exact handoff instructions for coding agent

> Implement this file as a **read-only audit** of the existing SA2 experiment. Start by inspecting the actual parquet and split schemas. Do not run Binary Ninja, call MCP, execute malware, re-inventory, re-freeze, or modify existing experiment outputs. Do not use frozen test data to select features, tune thresholds, or choose models. Build reusable `src/audit` modules, tests, and an audit report under `artifacts/feature_audit/`. First enforce input/split/label integrity and an explicit predictor exclusion list, then quantify BN coverage and possible label/source confounding, then evaluate a small preregistered PE versus PE+BN ablation on training/validation with paired uncertainty. Preserve negative findings and avoid SOTA claims. Run tests and provide exact commands, artifacts, and evidence-backed conclusions.
