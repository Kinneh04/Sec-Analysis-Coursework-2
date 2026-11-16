# Methodology summary

## Task
Static PE malware vs benign classification with three models (Logistic Regression, Random Forest, LightGBM) and ablations: PE-only, BN-only, PE+BN.

## Data
- **Malicious:** MalwareBazaar extracts (`E:\MalwareBazaar\extracted`), label from corpus provenance.
- **Benign:** Windows PE components (System32, SysWOW64, Accessories) — documented limitation: easy separation risk.
- **Challenge holdout:** Sample1/Sample2 POC SHA-256 listed in `artifacts/manifests/challenge_sha256.txt`; excluded from training splits.

## BN v2 features
Structured MCP extraction (`bn_v2_structured_il`); see `docs/feature_dictionary_v2.md`. Legacy v1 `legacy_hlil_regex_*` features are not true MLIL.

## Evaluation
- Group-aware 60/20/20 splits on matched BN cohort for ablation; full PE cohort reported separately.
- Primary operating point: TPR at 1% FPR (validation threshold, frozen for test).
- No claim of EMBER2024 SOTA without matched reproduction.
