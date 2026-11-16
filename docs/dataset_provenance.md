# Dataset provenance

## Malicious

- **Source:** MalwareBazaar daily extracts on local disk (`E:\MalwareBazaar\extracted`).
- **Label:** `malicious` from MalwareBazaar sample provenance (not AV vote counts).
- **Metadata join:** `E:\MalwareBazaar\analysis.csv` for paths, imphash grouping, batch dates.
- **Handling:** Read-only hashing and PE parsing; no execution.

## Benign

- **Source:** Microsoft Windows PE files under paths listed in `configs/local.yaml` (System32, SysWOW64, Accessories).
- **Label:** `benign` as OS component inventory — not a guarantee of safety outside this research scope.
- **Rationale:** MalwareBazaar corpus contains no benign class; a separate benign source is required for supervised binary classification.

## Low-detection challenge (manual)

Course POC binaries under `Sample1/` and `Sample2/out/` should be scored with frozen models as case studies, not mixed into training without independence review.
