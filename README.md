# SA2: Static PE Malware Classification, Scan Dashboard and EDR

Static analysis of Windows PE files with the frozen **V8 blend** (pretrained EMBER2024 + Binary Ninja feature model). Files are hashed and parsed, never executed.

| Part | Role | Port |
|---|---|---|
| **SA2 Scan** (`src/webscan/`) | Upload or search files, read the verdict and its reasoning, track results on a dashboard | 8000 |
| **SA2 Sentinel** (`src/edr/`) | Endpoint agent and console; uploads selected executables to SA2 Scan | 8001 |
| **Research pipeline** (`src/`) | Feature extraction, training, experiments V1–V10 | – |

## Quick start (Windows 10/11, Python 3.11–3.13)

1. Double-click `dashboard.setup.bat`. Note the password and EDR API key it prints.
2. Double-click `edr.setup.bat` (as administrator for full visibility).
3. In the EDR Settings page set Dashboard URL `http://127.0.0.1:8000` and the API key, then **Test connection** and **Save**.

Tests: `.\.venv\Scripts\python.exe -m pytest -q`

Full documentation (architecture, training, evaluation, configuration, troubleshooting): [docs/manual.md](docs/manual.md).
