# SA2: Static PE Malware Classification, Scan Dashboard and EDR

ICT3214 Coursework 2. This repository holds three things:

| Part | What it is | Where |
|---|---|---|
| **SA2 Scan** | VirusTotal-style analyst console: upload or search files, read a report that explains *why* each verdict was reached, and track past results and correlations on a dashboard. Scores Windows PE files with the frozen **V8 blend**: the pretrained EMBER2024 model plus a Binary Ninja feature model, falling back to EMBER2024 alone when Binary Ninja features are unavailable. | `src/webscan/`, port **8000** |
| **SA2 Sentinel** | On-machine EDR agent with a Carbon-Black-style console. Watches processes, network connections and downloads, then sends selected executables to SA2 Scan. | `src/edr/`, port **8001** |
| **Research pipeline** | Static PE + Binary Ninja feature extraction, the classifiers, and the V1–V9 experiments behind the model (V10 is documented in `docs/`). | `src/`, `docs/` |

Everything is **static analysis**: files are hashed and parsed, never executed. The EDR detects only; it never kills or blocks anything.

![SA2 Scan report](docs/screenshots/scan_report_zcode.png)

> The screenshots in `docs/screenshots/` were taken with the earlier V3.2 model. The layout is the same, but engine names, scores and the Model page now differ.

---

## Quick start (Windows 10/11)

**You need:**
- Windows 10 or 11.
- [Python 3.11, 3.12 or 3.13](https://www.python.org/downloads/), with the `py` launcher (the installer default).
- Git.
- About 700 MB of disk space for the virtual environment.
- Internet access on the first run: `pip` installs from pypi.org and installs `thrember` (the EMBER2024 feature extractor, not on PyPI) from a pinned GitHub zip; the dashboard then downloads the pretrained EMBER2024 model once (3.7 MB, Hugging Face, SHA-256 checked) into `artifacts/ember2024/`.
- Optional: Binary Ninja with its MCP server, for the full V8 blend. Without it every verdict is EMBER2024 alone. Read [Binary Ninja at scan time](#binary-ninja-at-scan-time) first.

```powershell
git clone https://github.com/Kinneh04/Sec-Analysis-Coursework-2.git
cd Sec-Analysis-Coursework-2
```

1. **Start the dashboard.** Double-click **`dashboard.setup.bat`**. The first run creates `.venv`, installs `requirements.txt` (1–3 minutes) and downloads the EMBER2024 model. The browser then opens http://127.0.0.1:8000. Keep the console window open: it shows the **sign-in password**, the **EDR API key** and whether Binary Ninja will be used. Every page requires sign-in; only the `/api/v1/*` endpoints use the API key instead.
2. **Start the EDR.** Double-click **`edr.setup.bat`**. To see every process and connection, right-click it and choose *Run as administrator*. The browser opens http://127.0.0.1:8001/settings.
3. **Connect them.** On the EDR Settings page:
   - Dashboard URL: `http://127.0.0.1:8000`.
   - API key: paste it from the dashboard console, or from **Admin → Sensors & API key**.
   - Press **Test connection**, then **Save**.

   Within 30 s the sensor shows as *Online* in the admin panel.
4. **Try it.**
   - **Upload:** on the home page (http://127.0.0.1:8000) choose any Windows `.exe` or `.dll`, or drop it anywhere. The report shows the verdict, the decision path (V8 blend or EMBER2024-only fallback, with the reason), the component scores, a plain-English assessment and DETECTION / REASONING / SIGNALS / DETAILS / ORIGIN / RAW tabs, with JSON / CSV / PDF export and an analyst decision (confirmed / false positive / benign).
   - **Dashboard:** http://127.0.0.1:8000/dashboard shows past results and correlations: detections over time, score history, engine agreement on Binary-Ninja-covered files (scatter + Pearson r), decision paths and fallback reasons, signal co-occurrence with flag rates, a heatmap of which factor groups drive the highest scores, and the review queue.
   - **EDR transport:** the EDR starts in **Allowlist only** mode. Under Settings → Allowlist, add the full path of a benign `.exe`, then Save. The file is uploaded, scanned, and listed in the EDR's Binary Search and on the dashboard. A worked example is in `dashboard_edr_plan.md` §9.
   - **Normal monitoring:** switch the EDR to **Rules** mode. It then uploads any PE whose rule score is ≥ 2, for example an unsigned file in a user-writable folder.

Both scripts take an optional port (`dashboard.setup.bat 8010`). Without `.bat` files:

```powershell
.\.venv\Scripts\python.exe -m src.v8.deploy --download-model   # downloads the model if missing, replaces it if its hash is wrong
.\.venv\Scripts\python.exe -m src.webscan.app --port 8000
.\.venv\Scripts\python.exe -m src.edr.app --port 8001
```

### Settings and environment variables

Set these before starting the dashboard. The Settings page shows the Binary Ninja values in effect.

| Variable / flag | Effect |
|---|---|
| `SA2_ADMIN_PASSWORD` | Admin password. If unset, one is generated on first run and printed at every start. |
| `SA2_BN=0` | Disable Binary Ninja. Every verdict is then EMBER2024 alone. |
| `SA2_BN_MCP_URL` | Binary Ninja MCP endpoint (default `http://127.0.0.1:24642/mcp`). |
| `SA2_BN_PROBE_TIMEOUT` | Seconds to wait when checking that the MCP endpoint answers with a valid MCP initialize response (default 1.0). |
| `SA2_BN_CONNECT_TIMEOUT` | Seconds allowed for opening the MCP session before each pass (default 30); longer counts as a timeout. |
| `SA2_BN_LOCK` | Path of the lock file that lets only one process use Binary Ninja at a time (default `sa2scan_bn.lock` in the temp folder). |
| `SA2_BN_MODE_SWITCH` | `restart` (default): restart Binary Ninja in the analysis mode each pass needs, as the research did. `off`: use whatever mode it is in (a deviation from the frozen method, recorded in the report). |
| `SA2_BN_EXE` | Path to `binaryninja.exe` (default: the per-user install path). |
| `SA2_UPX` | Path to `upx.exe`, used to unpack UPX files before Binary Ninja (default `tools/upx/...`, then `PATH`). |
| `SA2_EMBER_DOWNLOAD=0` | Never download the EMBER2024 model. Start-up and `--download-model` (run by `dashboard.setup.bat`) then only verify the file and fail if it is missing or has the wrong hash. |
| `SA2_NO_BROWSER=1` | Setup scripts do not open a browser. |
| `SA2_NO_PAUSE=1` | Setup scripts do not pause on error (for unattended runs). |
| `src.webscan.app --host 0.0.0.0` | Serve the dashboard on the network so an EDR on another machine can connect. Use only on a trusted lab network: this is Flask's development server. |

The EDR console always binds to `127.0.0.1`. Its settings (dashboard URL, key, allow/watch lists, poll interval, watched folders, rules) are edited in its web UI and stored in `artifacts/edr/edr.db`.

### Binary Ninja at scan time

When Binary Ninja's MCP server answers, each new file goes through two extraction passes (capabilities in intermediate analysis mode, HLIL in full mode) and the blend decides. Results are cached per SHA-256 in `artifacts/dashboard/bn_cache/`.

With the default `SA2_BN_MODE_SWITCH=restart` on Windows, **each scan that needs Binary Ninja force-closes `binaryninja.exe`**, rewrites `%APPDATA%\Binary Ninja\settings.json` (backup kept as `settings.json.sa2scan_backup`), relaunches it in intermediate mode, then in full mode, then restores the settings and relaunches it. This closes any open Binary Ninja session and takes minutes per file. It mirrors how the research enforced analysis modes. If the dashboard is stopped mid-scan, the next start restores the backup.

**Only one process should use Binary Ninja at a time.** Two dashboards, or a dashboard and the command-line scorer, would otherwise restart each other's Binary Ninja and its settings. A lock file enforces this (`sa2scan_bn.lock` in the user's temp folder; `SA2_BN_LOCK` sets another path). A process that finds the lock held does not wait: that file is scored by EMBER2024 alone and the report gives the reason `bn_busy`. The same happens inside one process while an earlier Binary Ninja analysis that timed out is still running, so two analyses never overlap. The operating system releases the lock if its owner crashes. Press **Reanalyze** on `bn_busy` files later to get the blend.

Use `SA2_BN_MODE_SWITCH=off` to keep Binary Ninja open in its current mode, or `SA2_BN=0` to skip it. If Binary Ninja is disabled, busy with another scan, unreachable, times out, fails, or the file is over 16 MB after overlay stripping, the verdict is EMBER2024's own decision and the report says why.

This live path reuses the research extractors but **has not been tested against a running Binary Ninja**. The test suite uses stubs.

### Troubleshooting

| Problem | Fix |
|---|---|
| `Python 3.11, 3.12 or 3.13 was not found` | Install Python from python.org with the `py` launcher, then re-run. |
| `pip install failed` | The first install needs pypi.org and github.com (for `thrember`). Check the proxy or firewall. |
| `The EMBER2024 model is not usable` | The `[error]` line above it says which case. *Missing* with `SA2_EMBER_DOWNLOAD=0`: unset it, or copy the file in. *Wrong hash*: run `python -m src.v8.deploy --download-model` (or `dashboard.setup.bat`) to replace it; the dashboard never replaces it on its own. *Download failed*: the download needs huggingface.co; or copy `EMBER2024_PE.model` into `artifacts\ember2024\models\artifacts\ember2024\models\` (the SHA-256 is checked). |
| `Missing model file: artifacts\v8\models\...` | The clone is incomplete. Run `git pull`; the V8 pickles and result files are tracked. |
| `V8 freeze verification failed` | A model pickle under `artifacts/v8/models/` was changed. Restore it with `git checkout -- artifacts/v8/models`. |
| `Port 8000 is already in use` | Close the other program, or run `dashboard.setup.bat 8010` and use that URL in the EDR settings. |
| Reports say *EMBER2024 only: Binary Ninja busy* | Another dashboard or CLI scorer was using Binary Ninja, or an earlier analysis that timed out was still running. Run one process at a time and press **Reanalyze** later. |
| Reports say *EMBER2024 only: Binary Ninja not reachable* | Start Binary Ninja with its MCP server, or check `SA2_BN_MCP_URL`. This is the expected fallback, not an error. |
| Binary Ninja closes during a scan | Expected with `SA2_BN_MODE_SWITCH=restart`. Set it to `off`, or `SA2_BN=0`. |
| Binary Ninja settings look wrong after a crash | Start the dashboard once (it restores `settings.json.sa2scan_backup`), or copy that file back over `settings.json` yourself. |
| EDR shows **limited visibility** | Run `edr.setup.bat` as administrator. |
| EDR shows **Unauthorized** | The key was rotated or mistyped. Copy it again from Admin → Sensors & API key. |
| Start fresh | Stop both apps and delete `artifacts/dashboard/` and `artifacts/edr/`. A new admin password and API key are generated. |

### Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

`tests/test_webscan.py` and `tests/test_edr.py` cover upload, scan and report; both decision paths, engine disagreement, old V3.2 reports and exports; API-key and admin auth; non-PE rejection; dedup; heartbeat; the EDR rules; the CSRF/host guard; and an end-to-end benign transport from the EDR to a live dashboard. Verdict UI tests use **stub** engines; no malware is used, and no test needs Binary Ninja. `tests/test_v8_deploy.py` checks the V8 scorer. Tests that need the downloaded EMBER2024 model, `notepad.exe` or research artifacts that are not in git **skip** when those are absent. Measured on the Linux VM used for this change (2026-11-18): 155 passed, 9 skipped, 1 failed. The failure, `test_edr.py::test_motw_and_rules`, relies on Windows case-insensitive paths and passes only on Windows. With `SA2_TEST_BENIGN_PE` and `SA2_TEST_PE` pointing at a benign Windows PE, the real-engine tests also run and pass (159 passed, 5 skipped, the same 1 failed). The Windows counts were not re-measured.

---

## How the verdict is made

- **Engines.** `ember2024` is the pretrained EMBER2024 PE model (LightGBM, Apache-2.0, by the EMBER2024 authors) over the 2,568-dimension EMBER v3 feature vector. The BN model is a LightGBM over 114 Binary Ninja features (`cap6_*` capabilities, `hl6_*` HLIL), trained on 1,256 training files with Binary Ninja features and extracted at scan time.
- **Decision (`v8_blend`).** With Binary Ninja features: margin `m = logit(EMBER2024) + 0.3 · logit(BN) − t_blend`. Without them: EMBER2024's own decision, `m = logit(EMBER2024) − logit(thr_R1)`; this fallback is part of the preregistered protocol. Malicious when `m ≥ 0`.
- **Score.** The displayed score is `sigmoid(m + logit(thr_R1))`, so one threshold, `thr_R1 = 0.3149`, applies to every file. On fallback files it equals EMBER2024's score. It is not a calibrated probability.
- **Borderline.** Scores below the threshold but at or above EMBER2024's 5% training-FPR operating point are shown as borderline. This is a triage aid, not a measured operating point of the blend.
- **Explanation (REASONING tab):** a score waterfall by factor group and the top SHAP contributions, translated into plain English and compared with typical benign / malware values (`artifacts/v8/feature_reference.json`).
- **Context (SIGNALS tab):** facts shown as context: signature validity and signer (EMBER2024 reads the signature's structure but never checks validity), installer/packer format, API capability groups, structural anomalies, EDR origin.
- **Assessment:** a heuristic note correlating the reasons with the signals. It never changes the model verdict.
- **Limits:** static features only. Packed or obfuscated payloads may be missed. Treat verdicts as triage, not ground truth.

### Evidence

The blend was frozen after V8 and scored once, without refitting, on two later independent cohorts:

| Evaluation | Files (benign / malware) | Blend TPR | EMBER2024 TPR | TPR change (95% CI) | Preregistered rule |
|---|---|---|---|---|---|
| V8 blind | 281 / 443 | 0.919 | 0.905 | +1.35 pp (+0.44 to +2.59) | met |
| V9 replication | 955 / 608 | 0.890 | 0.882 | +0.82 pp (−0.33 to +1.97) | not met |
| V10 replication | 2000 / 2500 | 0.932 | 0.920 | +1.20 pp (+0.69 to +1.69) | met |

V9 did not confirm the gain; V10, the largest cohort, did. The gain is small. At the strictest operating point (0.25% training FPR) the blend was worse than EMBER2024 on V10 (16 detections gained, 43 lost). On the course Sample1/Sample2 files the blend flagged 1 of 7 and EMBER2024 alone flagged 2 of 7. Without Binary Ninja the verdict is the pretrained EMBER2024 model alone. Sources: `artifacts/v8/blind/blind_results.json`, `artifacts/v9/blind/replication_results.json`, `artifacts/v10/blind/replication_results.json`, `docs/v8_results.md`, `docs/v9_results.md`, `docs/v10_results.md`, `docs/v10_sample12_results.md`. The Model page shows the same numbers, read from those files.

---

## Research pipeline (needs the private corpus)

The experiments need `E:\MalwareBazaar\extracted` (not distributed), a benign PE corpus, and Binary Ninja. On a Personal license, keep the GUI open and use MCP at `http://127.0.0.1:24642/mcp`. Paths go in `configs/local.yaml` (template: `configs/local.example.yaml`). Generated data goes to `artifacts/` and is not committed, apart from the V3.2 and V8 bundles and the V8–V10 result files.

```powershell
.\.venv\Scripts\python.exe -m src.inventory --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.pe_features --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.bn_features --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.build_dataset --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.train --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.evaluate --config configs/local.yaml
# Score files with the deployed V8 blend from the command line (--no-bn: EMBER2024 fallback only):
.\.venv\Scripts\python.exe -m src.v8.deploy --recursive C:\path\to\folder --no-bn --summary
# Legacy V3.2 scorer (research record; no longer used by the dashboard):
.\.venv\Scripts\python.exe -m src.v3.score --recursive C:\path\to\folder --summary
```

Results by stage:
- **V1:** PE+BN did not beat PE-only.
- **V2, V3, V3.1:** no confirmed gain.
- **V3.2:** met its preregistered rule (the dashboard model until this switch).
- **V8:** the EMBER2024 + BN blend met its rule against EMBER2024.
- **V9:** the gain did not replicate (CI included zero).
- **V10:** a larger replication confirmed a small gain (+1.20 pp TPR near 1% FPR).

No SOTA claim is made. See `docs/conclusions.md` (V1 only), `docs/v3.2_results.md`, `docs/v8_results.md`, `docs/v9_results.md` and `docs/v10_results.md`. The V10 documents (`docs/v10_*.md`) are copied unchanged from the research export; they cite `src/v10/` and `artifacts/v10/` paths that are not in this repository. Plans: `plan.md` (V1), `SA2_V2_plan.md` (V2+), `fix.md`, `feature_audit_plan.md`, `dashboard_edr_plan.md` (this deployment layer). Operator notes: `docs/operator_guide.md`.

`src/dashboard.py` is the earlier Streamlit results page. SA2 Scan supersedes it, and `streamlit` is not in `requirements.txt`.

## Repository layout

```
dashboard.setup.bat, edr.setup.bat   one-click start (scripts/ensure_venv.bat builds .venv)
requirements.txt                     pinned runtime (lightgbm/scikit-learn match the frozen pickles; pefile/signify/thrember fix EMBER features)
src/webscan/                         SA2 Scan (Flask): app.py, scanner.py, explain.py (reasons/signals/assessment), reference.py, templates/, static/
src/v8/                              deployed V8 blend: deploy.py (scorer + CLI), bn_live.py (Binary Ninja at scan time), ember_map.py; plus V8 research code
src/edr/                             SA2 Sentinel (Flask + agent): app.py, core.py, rules.py, client.py
src/common/                          shared helpers (hashing, sqlite, Authenticode)
src/v3/                              V3.2 feature extractors + legacy scorer (research record)
src/ (other), src/v2 … src/v9        research pipeline
artifacts/v8/                        frozen V8 models, freeze manifest, blind results, feature reference (tracked)
artifacts/v9/, artifacts/v10/        replication results (tracked)
artifacts/v3.2/, artifacts/deploy/   frozen V3.2 bundle (tracked, legacy)
artifacts/ember2024/                 downloaded EMBER2024 model (not tracked)
docs/                                methodology, results, preregistrations, operator_guide.md, ui_refs/, screenshots/ (V3.2-era)
tests/                               pytest suite
```
