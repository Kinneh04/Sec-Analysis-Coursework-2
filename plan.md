# Implementation Plan: Binary Ninja–Enhanced Static Malware Classification

## 0. Instructions for the implementing LLM

Build a **reproducible research prototype**, not merely a presentation or mock dashboard. Implement and validate each milestone before advancing. Do not fabricate results, labels, timings, benchmark wins, or Binary Ninja API capabilities. Record unknowns as issues and test them empirically.

**Primary local corpus:** `E:\MalwareBazaar\extracted` (Windows). This directory exists on the user's machine, **not** in this LLM's environment unless explicitly mounted. Make corpus paths configurable; never assume access or claim to have scanned the directory without doing so.

The pipeline is **static analysis only**. Do not run, detonate, load as an executable, or dynamically invoke malware samples. Do not disable AV/EDR or modify host security settings. Do not generate new malicious payloads. Handle untrusted input conservatively, cap resource usage, and log failures without stopping the entire job. Prefer an isolated analysis VM with no access to sensitive credentials and read-only sample storage. All automated parsing/disassembly must treat files as hostile.

The intended deliverable is a Python application and research evidence demonstrating whether structural/semantic features recovered through Binary Ninja improve Windows PE malware classification compared with conventional static features.

## 1. Research framing

### Working title
**Semantic Feature Fusion for Static Detection of Low-Detection Windows Malware Using Binary Ninja and Machine Learning**

### Central research question
Do structural and semantic features extracted using Binary Ninja improve the detection of *previously unseen* Windows PE malware compared with conventional static PE features, at fixed false-positive rates?

### Hypotheses
- **H1:** Combined PE + Binary Ninja features improve detection against the PE-only baseline on an independent test set.
- **H2:** Selected code-operation relationship features provide incremental value beyond simple instruction and CFG statistics.
- **H3:** Any improvement remains useful after accounting for extraction latency, failure rates, and model inference cost.

These are hypotheses to test, **not claims of demonstrated performance**. “Low detection” based on AV-vendor detections is a sample-selection attribute, not a ground-truth malware label or a guarantee of evasiveness against an ML model.

### Coursework alignment
ICT3214 Coursework 2 requires development and comparison of **three ML/AI models** for security anomaly detection/forensics; rationales, data collection and preprocessing, performance evaluation, dashboard, reproducibility/user manual. Possible bonus criteria: innovative solution; experimentally outperform published SOTA; real-time detection; generated/simulated datasets. No criterion or bonus score is guaranteed.

### In scope
- Windows native PE `.exe` and `.dll` files, x86/x64 when supported.
- Binary-level static PE extraction, Binary Ninja analysis, tabular feature generation.
- Three models: Logistic Regression, Random Forest, LightGBM.
- Ablation studies and held-out testing.
- Dashboard/report with traceable model predictions and limitations.
- Optional package-aware aggregation of known-associated EXE/DLL artifacts only after core system works.

### Out of scope initially
- Detonation, behavioral sandboxing, execution-based telemetry, C2 activity, live blocking.
- Unpacking arbitrary protectors, decryption, or exhaustive analysis of shellcode/raw blobs.
- Malware-family attribution or claims of specific ATT&CK techniques without validated evidence.
- Deep-learning CFG/GNN architectures until baselines and datasets are validated.
- Treating VirusTotal vendor detection count alone as labels.

## 2. Dataset strategy and integrity rules

### 2.1 Inventory the local corpus first
Create a **read-only** corpus inventory over `E:\MalwareBazaar\extracted`. It may contain extracted binaries, archives, nested directories, or other files; **do not assume its layout**.

For each candidate file, record:
- SHA-256 and size, normalized relative path and file extension.
- Magic bytes/file type, PE validity, machine architecture, EXE vs DLL.
- Extraction/inventory status, exceptions, source metadata pointer.
- File source (MalwareBazaar or otherwise), and any reliable label/first-seen/family metadata that can be joined using SHA-256.
- Sample grouping identifiers (exact duplicates, near duplicates, shared package/bundle or common source/build project where known).

Default to nonrecursive archive handling; do **not** unpack recursively without explicit, bounded design and validation. Avoid opening suspicious documents/scripts for execution. Put corrupt or unsupported inputs in a manifest with a reason rather than silently dropping them.

Suggested manifest fields:
`sha256, relative_path, file_size, file_type, is_pe, machine, is_dll, source, label, label_source, first_seen_utc, family, group_id, inventory_status`.

### 2.2 Crucial: MalwareBazaar does not provide benign examples
The directory is expected to be malware-oriented. Do **not** train a benign-vs-malicious binary classifier using only MalwareBazaar files. Obtain a **separate, independently sourced and properly licensed benign PE corpus** with verifiable provenance. Avoid treating all unseen or AV-undetected files as benign.

Prefer a curated known-benign dataset or authorized signed software binaries with documented acquisition and labels. Signatures alone do not establish benignness. Maintain source provenance and licensing restrictions. Avoid uploading binaries to third-party services without authorization.

### 2.3 Label policy
- `malicious` from credible dataset provenance and independent validation.
- `benign` from a separately curated benign source, with documented checks.
- `unknown`/uncertain: exclude from supervised training and report count.
- Store AV detection count and scan timestamp, when legitimately available, as **evaluation metadata**, not as a training label or input feature.
- Never infer that a sample is safe because it has zero detections.

### 2.4 Leakage-resistant splitting
- Compute SHA-256 before any split; remove exact duplicates.
- Identify near-duplicates and shared code/projects using available metadata, fuzzy hashing or similarity heuristics where feasible.
- Keep all related samples/build variants/components in the **same split**.
- Use 60/20/20 train/validation/test as a starting ratio; adjust based on corpus and groups.
- Prefer a chronological evaluation with first-seen dates when reliable, and also report any group-disjoint split.
- Fit imputers, scalers, feature selection, and hyperparameter searches **only on training/validation**.
- Choose decision thresholds on validation; keep test untouched until final evaluation.
- Reserve the user's low-detection POCs and closely related artifacts as **case studies**, not training examples if their independence is uncertain.
- Document AV-scan date, labeling provenance, family imbalance, and dataset shifts.

### 2.5 Data milestones
1. Inventory first (no ML), publish class counts and architecture breakdown.
2. Verify at least one trustworthy benign source.
3. Establish representative sample quotas only after measuring Binary Ninja throughput.
4. Target a small proof-of-feasibility corpus, then expand as compute permits; do not promise arbitrary sample counts.
5. Use substantially more benign test files to estimate FPR of 0.1% reliably. With only 500 benign test files, that target is not measurable with useful resolution.

## 3. Extractor architecture

```text
Config (corpus directories + analysis budgets)
                  |
         Read-only inventory
                  |
         SHA-256 dedup + labels
                  |
     Validated PE files only
             /          \
   Conventional PE      Binary Ninja
   feature extractor    semantic extractor
             \          /
          Feature store (key: SHA-256)
                   |
             Quality checks
                   |
      Group-aware dataset builder
                   |
     3 models x feature-set ablations
                   |
        Evaluation and dashboard
```

Use Python (version pinned), `pefile` or equivalent for PE parsing, Binary Ninja's **official supported Python API** for static analysis, `pandas`/`pyarrow`, `scikit-learn`, `lightgbm`, and a simple `Streamlit` dashboard. Confirm installed API version and license availability before implementation. Start with a small read-only test file. Do not invent or assume API symbol names; inspect official docs and test individual calls.

### 3.1 Conventional baseline features (PE)
Suggested numeric/categorical features:
- File size and general PE metadata.
- Machine architecture and subsystem, DLL flag.
- Section count, size statistics, executable/writeable flags, RWX section count.
- Section byte entropy: mean, maximum, standard deviation.
- Import counts, imported DLL counts, export counts, resource counts.
- String counts/statistics where feasible without embedding raw sensitive content.
- Optional EMBER-style conventional features, including stable hashed imports/strings, **only with identical extraction in comparisons**.

Do not use names/paths, dataset IDs, MalwareBazaar source flag, family labels, AV detection counts, or split indicators as model features.

### 3.2 Binary Ninja structural features
Start with architecture-independent aggregated numeric statistics, with clear denominators:
- Recovered function count; minimum/mean/median/max function sizes.
- Basic block counts and distribution per function.
- CFG edges, connected/reachable regions, back edges, approximate loop counts.
- Cyclomatic complexity distribution, with clearly defined calculation for each CFG.
- Call counts: direct, indirect, resolved, unresolved; indirect-call ratio.
- MLIL operation histograms normalized by analyzed MLIL instruction count.
- Loads/stores, arithmetic, bitwise operations, comparisons, branch/call operations.
- Constant diversity and distributions; optionally operand categories.
- Distinct referenced call targets and cross-function edges.
- Recovered-code coverage: analyzed executable bytes / eligible executable bytes (estimate clearly documented).
- Analysis error codes, timeout status and missing-feature indicators.

Some metrics may be inaccurate if analysis misses packed, dynamically resolved, unsupported or obfuscated code. Label them as **recovered static features**, not definitive runtime facts.

### 3.3 Optional semantic relationship features
Only after baseline extraction works, implement small, **defensive and descriptive** data-flow summaries to evaluate their ML value, e.g.:
- Count of recovered flows from local transformations into later memory operations.
- Memory-access/call/indirect-transfer patterns within a recovered function.
- Resolved argument-type/value-category statistics for selected calls.
- Interprocedural call-graph and import-use summaries where confidently recoverable.

For each feature specify its operational definition, constraints, false-positive failure modes, and analysis budget. Features should characterize recovered relationships, **not automatically assert malicious intent**. If too ambiguous or expensive, defer these features and report limitations.

### 3.4 Feature schema and robustness
- One feature vector per SHA-256, plus extractor version and configuration hash.
- Distinguish `0` (observed absence) from `null` (missing/failed analysis).
- Keep extraction status, elapsed seconds, total attempts, warnings, analyzed architecture, BN version.
- Preserve separate feature families: `pe_*`, `cfg_*`, `mlil_*`, `relation_*`, `quality_*`.
- Log JSON Lines and persist a compact Parquet feature store; avoid retaining disassembly or full code in dashboards by default.
- Reuse cached results based on hash + extractor/config version; never silently mix incompatible features.
- Apply per-file time and memory budgets; stop cleanly on a timeout; never count a timed-out file as an analyzed benign sample.
- Bound number of functions/IL operations and sample size if needed; record any truncation.
- Parallelize cautiously within the capacity of the licensed Binary Ninja installation, memory, and machine.

## 4. Models and experiments

### 4.1 Three mandatory classifiers
1. **Logistic Regression:** interpretable linear baseline; scale/impute only using fit on training split.
2. **Random Forest:** nonlinear bagging comparator.
3. **LightGBM:** gradient-boosted trees, likely candidate for best tabular feature performance but must be tested.

Keep random seeds, package versions, tuning budgets and CV methodology reproducible. Use class weights/sample weighting if justified by prevalence. Calibrate probabilities on validation data when necessary, and do not tune on test.

### 4.2 Feature ablations (3 x 3 = 9 core experiments)
- **A: PE-only** — conventional static features.
- **B: BN-only** — Binary Ninja structure and MLIL aggregates (with quality features reported separately).
- **C: PE + BN** — combined feature set.

Optional fourth set:
- **D: PE + BN + relationships** — tests incremental benefit of semantic relations.

For a clean comparison train all variants on exactly the **same intersection of samples** with valid extraction. Separately report coverage/failure statistics and evaluate a practical fallback policy for unanalyzable samples; never hide dropped difficult files.

### 4.3 Essential baselines and SOTA language
- **Internal baseline:** identical LightGBM configuration using PE-only features vs PE+BN.
- **External baseline:** reproduce an available published model/implementation on a **matching** dataset, feature setup, label rules and split. Candidate sources to evaluate include EMBER2024 and SOREL-20M.
- **Important limitation:** EMBER-style *precomputed feature tables* cannot be used to recover MLIL/CFG. The raw PE binaries are required for BN features. A matched raw-binary benchmark subset is not equivalent to reproducing full published SOTA numbers.
- Report differences in datasets, versions, time windows, architecture and metrics; do not claim SOTA superiority if not directly comparable.

### 4.4 Metrics
Primary:
- True-positive rate (recall) at validation-selected **1% FPR**.
- If benign test sample size permits: TPR at **0.1% FPR** with confidence intervals.
- Recall on an independently defined low-detection/challenge subset.

Secondary:
- Precision, recall, F1, PR-AUC, ROC-AUC and confusion matrices.
- Per-class and per-architecture performance.
- Binary Ninja analysis coverage and failure/timeout rate.
- Extraction throughput and latency (median/p95), feature-building time, model inference time, end-to-end time.
- Model sizes, reproducibility and interpretability (permutation importance or SHAP, if feasible).

When comparing models on the same test cases, provide bootstrap confidence intervals (group-respecting if possible) and paired statistics where applicable. Mark exploratory subgroup findings as such.

### 4.5 Error analysis
Inspect a manageable set of false positives, false negatives, timeouts and extraction failures. Categorize by sample group and observables such as PE layout, imports, analyzed-code coverage, or architecture. Report whether BN semantics helped or hurt relative to PE-only. Do not infer specific malware behavior from weak static evidence.

## 5. Dashboard

Build a simple interactive dashboard once extraction and experiments work, not before. Suggested pages:
- **Dataset:** provenance, label balance, architectures, family groupings, date coverage, duplicates, parsing failures.
- **Benchmark:** model/feature configuration table, ROC/PR curves, TPR@FPR with uncertainties, latency and coverage.
- **Prediction explorer:** select SHA-256, show label, score, threshold, model, feature highlights, extraction status. Avoid direct sample execution or one-click malware launch.
- **Ablation:** compare PE, BN, fused and optional relations features on matched test samples.
- **Limitations:** unreliable labels, static-analysis gaps, failed disassembly, unrepresentative challenge set, and domain shift.

Display unambiguous units and the source experiment ID on every chart. Clearly label sample counts and whether results are validation or held-out test.

## 6. Proposed repository layout

```text
project/
  README.md
  plan.md
  pyproject.toml
  configs/
    local.example.yaml
    experiments.yaml
  docs/
    dataset_provenance.md
    feature_dictionary.md
    methodology.md
    threat_model.md
    user_manual.md
  src/
    inventory.py
    pe_features.py
    bn_features.py
    relations.py            # optional
    build_dataset.py
    train.py
    evaluate.py
    report.py
    dashboard.py
    common/
  tests/
    test_inventory.py
    test_pe_features.py
    test_bn_features.py
    test_schema.py
    test_splitting.py
    test_metrics.py
  artifacts/                  # generated, gitignored
    manifests/
    features/
    splits/
    models/
    evaluations/
    figures/
  logs/                       # generated, gitignored
```

Never commit malware samples, credentials, raw personal data, or proprietary binaries. Keep root/corpus paths in local configuration, not source code.

Example configuration (adjust if necessary):

```yaml
paths:
  malware_corpus: 'E:\MalwareBazaar\extracted'
  benign_corpus: null   # MUST be set before supervised training
  artifacts_dir: './artifacts'
analysis:
  static_only: true
  max_seconds_per_file: 120
  max_file_size_mb: 100
  cache_by_sha256: true
  parallel_jobs: 1
models:
  random_seed: 42
  algorithms: ['logistic_regression', 'random_forest', 'lightgbm']
  feature_sets: ['pe', 'bn', 'pe_bn']
evaluation:
  primary_fpr: 0.01
  secondary_fpr: 0.001
```

## 7. Milestones and gates (4-week target)

### Week 1 — Corpus inventory, baseline and Binary Ninja API feasibility
- [x] Confirm Binary Ninja Python API availability, license type, API version, and headless analysis constraints. **BN 6.0.10905 Personal; headless `load()` fails; GUI MCP at :24642 works.**
- [x] Inventory `E:\MalwareBazaar\extracted` without execution. **Implemented `src/inventory.py`; 500-sample pilot + 496 PE-valid rows in artifacts.**
- [ ] Verify PE parsing, metadata coverage, duplicate prevalence, timestamps, labels and group links.
- [ ] Obtain defensible benign PE dataset; document provenance.
- [ ] Validate BN extraction of a *small, bounded* benign/reference sample set.
- [ ] Produce a stable feature dictionary and first Parquet output.

**Gate 1:** A reproducible inventory plus working BN extraction on supported binaries, no sample execution, and evidence of both classes. If no benign set is available, do not begin binary supervised training.

### Week 2 — Batch feature extraction and dataset design
- [ ] Implement robust PE and BN feature extraction with caching, timeouts and logs.
- [ ] Extract representative benign and malicious subsets.
- [ ] Create group-disjoint train/validation/test splits and leakage tests.
- [ ] Produce missingness, coverage, and throughput diagnostics.
- [ ] Train a PE-only Logistic Regression and LightGBM smoke-test baseline.

**Gate 2:** Same samples yield deterministic schema; no label leakage; baseline trains and evaluates with plausible metrics; failed files are tracked.

### Week 3 — Three classifiers, ablations and benchmarking
- [ ] Train Logistic Regression, Random Forest and LightGBM across A/B/C.
- [ ] Tune on validation only and freeze the selected configurations.
- [ ] Report TPR@1% FPR, precision/recall/F1, PR-AUC, ROC-AUC, runtimes and missingness.
- [ ] Add a published matched benchmark if feasible; otherwise limit claim to the internally controlled PE-only comparison.
- [ ] Evaluate low-detection samples as a separately described subset, without using detection count as training feature.
- [ ] Optionally add relation features after core experiments are stable.

**Gate 3:** Reproducible 3x3 experiment matrix, matched test cohorts, valid threshold selection and no unsupported SOTA claims.

### Week 4 — Validation, dashboard, report and handoff
- [ ] Freeze held-out test set; run final evaluation once.
- [ ] Create dashboard and exported figures/tables with run IDs.
- [ ] Document ablation results, ablation uncertainty, errors and extraction overhead.
- [ ] Build a user manual with exact install/setup/run steps and known failure modes.
- [ ] Produce results discussion and short demo walkthrough.
- [ ] Validate a fresh run on an independent machine/environment where possible.

**Gate 4:** New evaluator can reproduce preprocessing, feature extraction, training and reported figures without relying on undocumented manual steps.

## 8. Suggested command-line interface (to implement)

These are *target interfaces*, not claims that commands already exist:

```powershell
python -m src.inventory --config configs/local.yaml
python -m src.pe_features --config configs/local.yaml
python -m src.bn_features --config configs/local.yaml
python -m src.build_dataset --config configs/local.yaml
python -m src.train --config configs/local.yaml
python -m src.evaluate --config configs/local.yaml
streamlit run src/dashboard.py
```

Every command should offer `--help`, a `--limit`/small-sample mode where meaningful, a progress log, and a deterministic output path/run manifest. Provide an obvious way to resume without re-analyzing completed hashes.

## 9. Acceptance criteria

The implementation is complete only when:
- [ ] The malware directory is inventoried; unsupported inputs and errors are reported.
- [ ] Benign labels and malware labels have documented provenance.
- [ ] No binary was executed as part of the pipeline.
- [ ] PE and BN feature extractors produce a versioned, machine-readable feature table.
- [ ] The three required ML models and at least three ablations run on identical grouped splits.
- [ ] Duplicate, group, source and timestamp leakage risks are audited.
- [ ] All metrics, thresholds and runtime values come from actual saved experiment results.
- [ ] The dashboard visualizes real results, not illustrative or fabricated values.
- [ ] Independent test results and extraction failure/coverage rates are reported.
- [ ] Claims are calibrated: incremental feature benefit is separate from SOTA superiority.
- [ ] README, feature dictionary, methodology, user manual, and reproducibility metadata are included.

## 10. Questions to resolve during implementation (do not silently assume)

1. Is Binary Ninja installed and licensed for headless/background analysis? Which API version?
2. How many PE files are inside `E:\MalwareBazaar\extracted`? What is the architecture and file-format distribution?
3. Where are source labels, first-seen times and AV-count metadata stored, if anywhere?
4. What benign corpus is accessible and legally usable?
5. Are there known groups of samples built from the same code/project, which must stay in one split?
6. What are actual per-file Binary Ninja analysis timings and failure rates on representative samples?
7. Which raw binaries can be matched to published benchmarks without misrepresenting comparability?
8. What end-to-end latency qualifies as “real-time” for the intended use case? Do not claim this bonus based solely on an API endpoint.

## 11. First task for the implementing LLM

**Do not start by creating a model or dashboard.** Start by inspecting the project environment and producing an **inventory-only, read-only program** that examines `E:\MalwareBazaar\extracted`, validates PE signatures, calculates SHA-256, records duplicates and file types, and outputs `artifacts/manifests/corpus_inventory.parquet` plus a summary report. Make it resumable and robust to corrupt files. Then inspect Binary Ninja availability and demonstrate a minimal, safe extractor on known-benign PE samples. Present the actual inventory statistics and blockers before proceeding to ML.

At every stage: implement, test, show real outputs, update progress in `plan.md`, and refrain from claiming performance gains until validated experimentally.
