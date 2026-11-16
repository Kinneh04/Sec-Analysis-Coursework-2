# Dataset audit checklist (pre–BN scale)

Run after inventory expansion and before large MCP extraction:

```powershell
.\.venv\Scripts\python.exe -m src.inventory --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.pe_features --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.freeze_cohort --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.audit_dataset --config configs/local.yaml
```

| Check | Acceptance | Artifact |
| --- | --- | --- |
| Dataset diversity | ≥3 third-party `software_source` values + Windows OS roots | `dataset_audit.json` → `dataset_diversity` |
| Deduplication | 0 duplicate SHA-256 | `deduplication` |
| Label quality | MalwareBazaar provenance; benign from declared install paths | `label_quality` |
| Split integrity | 0 `group_id` leaks across train/val/test | `split_integrity`, `split_assignments.parquet` |
| Challenge isolation | Qualitative POC hashes excluded from train/val/test | `cohort_frozen.json` |
| PE extraction | ≥95% `pe_status == ok` | `pe_extraction` |
| BN coverage | Documented after MCP pilot | pending |
| Feature comparison | Paired PE vs PE+BN on frozen test | after BN cohort |

## FPR reporting

With ~100 benign test rows (20% of ~478 benign), **do not** treat TPR at **0.1% FPR** as a precise headline metric. Use **1% FPR** (`evaluation.primary_fpr`) with bootstrap CIs from `src.paired_eval`.

## Frozen artifacts

- `artifacts/manifests/split_assignments.parquet` — authoritative split column
- `artifacts/manifests/frozen_{train,val,test}_sha256.txt` — SHA lists
- `artifacts/manifests/cohort_frozen.json` — counts and challenge exclusion

`src.build_dataset` respects frozen assignments when the parquet file exists.
