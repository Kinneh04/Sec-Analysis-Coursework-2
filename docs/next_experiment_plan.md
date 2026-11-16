# Next experiment plan (aligned with coursework strategy)

## Primary goal (not SOTA-first)
Demonstrate whether **structured BN features** add information beyond **PE-only** features on a **larger, more realistic** benign/malware mix — with uncertainty and latency reported.

SOTA comparison remains an **optional stretch** after one controlled experiment is complete.

## Phase A — Benign inventory (do this before large BN extraction)

| Step | Command |
| --- | --- |
| Expand inventory | `python -m src.inventory --config configs/local.yaml` |
| PE features | `python -m src.pe_features` |
| Audit acceptance checks | `python -m src.audit_dataset` → `dataset_audit.json` |
| Freeze splits | `python -m src.freeze_cohort` → `split_assignments.parquet`, `cohort_frozen.json` |

**Do not** scale BN until `dataset_audit.json` reports `ready_for_bn_pilot: true` (except BN coverage, which comes after a small MCP pilot).

### FPR reporting note

500 benign + 500 malicious is a **development milestone** (~1000 total). With a 20% test holdout, expect ~100 benign test rows. **TPR at 0.1% FPR is not precisely estimable** at that scale; report bootstrap CIs at **primary_fpr (1%)** and treat 0.1% FPR as exploratory only.

## Phase B — Scale matched BN cohort (~500 target)

| Step | Command / artifact |
| --- | --- |
| Inventory 500+500 | `python -m src.inventory --config configs/local.yaml` |
| PE features | `python -m src.pe_features` |
| v2 BN (GUI open) | Set `analysis.max_bn_mcp_calls: 500`; `python -m src.bn_features --extractor v2` |
| Coverage audit | `artifacts/evaluations/bn_coverage_v2.json` (per-class status + latency) |

Use **balanced** selection (already in `bn_features` v2 pilot logic). Expect **hours** of MCP time; cache is resumable under `artifacts/features/bn_v2_cache/`.

## 2. Harder benign sources

Edit `configs/local.yaml` `benign_roots` using `configs/local.example.yaml` as a template. Prefer **installed third-party** PE binaries you are licensed to use. `inventory` caps per root via `experiment.benign_max_per_root` to avoid System32 dominating.

## 3. Sample2 false-negative audit

```powershell
.\.venv\Scripts\python.exe -m src.investigate_fn --config configs/local.yaml --mcp
```

Output: `artifacts/evaluations/sample2_fn_audit.json` — BN recovery (`analysis_status`, IL ops, blocks) and distance to benign BN centroid.

**Interpretation:** FN may be (a) BN did not recover relevant code, (b) features look like benign, or (c) model/threshold on easy training distribution.

## 4. PE vs PE+BN with uncertainty

Same matched test rows:

```powershell
.\.venv\Scripts\python.exe -m src.paired_eval --config configs/local.yaml --model-a random_forest__pe --model-b random_forest__pe_bn --suffix _v2
```

Output: `paired_pe_vs_pebn_v2.json` — bootstrap CI for TPR@1% FPR and **paired delta** (PE+BN minus PE).

Prefer **Random Forest / Logistic Regression** on small tests; treat LightGBM as secondary until n is larger.

## 5. Extraction-time tradeoff

Compare `bn_coverage_v2.json` → `latency_seconds` (median/p90) vs PE-only throughput (seconds per file from inventory + `pe_features` logs). Report **recall gain per minute of BN analysis** only if paired delta CI excludes zero.

## Challenge sets (methodology)

| File | Purpose |
| --- | --- |
| `challenge_qualitative_sha256.txt` | Sample1/Sample2 POCs — **case studies only** |
| `challenge_quantitative_sha256.txt` | Future larger holdout for numeric challenge metrics |

Detecting one related POC while missing others **does not** prove generalization.

## SOTA vs distinctive contribution (decision)

| Path | When to choose |
| --- | --- |
| **Benchmark-compatible raw binaries** (EMBER-style reproduction) | Defensible SOTA bonus; heavy dataset alignment work |
| **Low-detection / tradecraft focus** | Stronger fit for BN semantic value; report honestly with challenge + FN audit |

**Recommendation:** Finish **one 500-sample controlled experiment** with harder benign + paired CIs **before** architecture changes or SOTA claims.
