# SA2 Manual

# Part 1: Overview for management

## Summary

SA2 is a malware screening system for Windows programs. It answers one question about any program file: **is it safe or malicious?** It reaches an answer without ever running the file, so screening cannot infect anything. SA2 has two programs that work together:

| Program | In one sentence | Used by |
|---|---|---|
| **SA2 Scan** | A website where an analyst uploads a file and gets a verdict (malicious, borderline or benign) with a plain-English explanation. | Security analysts |
| **SA2 Sentinel** | A small watcher that runs on a computer, notices new or suspicious programs, and sends them to SA2 Scan automatically. | IT / security operations |

Sentinel finds candidate files. Scan judges them. Sentinel only reports; it never deletes, blocks or stops anything, so it cannot disrupt a user's work.

## How it decides

Each file is examined by two automated "inspectors", both machine-learning models trained on thousands of known-good and known-malicious programs:

1. **Inspector 1** is an established, publicly released detector (EMBER2024). It reads about 2,500 measurements of the file: its structure, what it imports, how scrambled its contents look, and similar signals.
2. **Inspector 2** is a model built in this project. A disassembler (Binary Ninja) reads the program's code, and the model scores what the code is able to do, such as modifying the registry or injecting into other programs.

The final verdict combines the two, with Inspector 1 carrying most of the weight. If Inspector 2's tool is not available, Inspector 1 decides alone, and the report says so.

Every report shows the verdict, a score, and the reasons behind it in plain language, so an analyst can see why a file was flagged and make the final call.

## How well it works

The combined detector was tested on files it had never seen, in three rounds, with its settings locked beforehand so they could not be tuned to flatter the results.

| Test | Files tested | Malware caught (combined) | Malware caught (Inspector 1 alone) |
|---|---|---|---|
| Round 1 | 724 | 91.9% | 90.5% |
| Round 2 | 1,563 | 89.0% | 88.2% |
| Round 3 (largest) | 4,500 | 93.2% | 92.0% |

In the largest round, 3 of 2,000 harmless files were wrongly flagged (0.15%). The combined detector consistently catches slightly more malware than the established detector alone. Round 2's improvement was too small to be statistically certain; Rounds 1 and 3 were clear.

## Using SA2 Scan (analyst)

1. **Start it.** Double-click `dashboard.setup.bat`. The first start installs everything it needs (a few minutes, internet required) and opens the site at http://127.0.0.1:8000. A console window shows the sign-in password; keep that window open.
2. **Scan a file.** On the home page choose a Windows program file (`.exe`, `.dll`, `.sys`) or drop it onto the page.
3. **Read the report.**
   - **Verdict:** malicious, borderline (worth a human look) or benign, with a score.
   - **Reasoning tab:** the factors that raised or lowered the score, in plain English.
   - **Signals tab:** facts such as whether the file is digitally signed, how it was packaged, and where it came from.
   - Reports can be exported as PDF, CSV or JSON.
4. **Delete if needed.** The **Delete** button on a report removes the file's record, its submissions, its stored copy and its cached analysis from the database (it asks for confirmation). Submitting the same file again scans it afresh.
5. **Record a decision.** Mark the file confirmed malicious, false positive or benign. This keeps the analyst's judgement on record and does not change the model's verdict.
6. **Review history.** The **Dashboard** page shows detections over time, files awaiting review and how often the two inspectors agree. The **Model** page shows the test results above.

## Using SA2 Sentinel (IT operations)

1. **Start it.** Double-click `edr.setup.bat` on the computer to be watched. Right-click and choose *Run as administrator* for full visibility. It opens its console at http://127.0.0.1:8001.
2. **Connect it to SA2 Scan.** On the Settings page enter the SA2 Scan address (`http://127.0.0.1:8000` when on the same machine) and the access key shown in SA2 Scan's console window, then press **Test connection** and **Save**. Within 30 seconds the sensor shows as *Online*.
3. **Choose how selective it is.**
   - **Allowlist only** (default): sends only files you name. Safest for a trial.
   - **Rules:** sends any program that looks suspicious by the rules below.
4. **Review results.** Sentinel's console lists every program it has seen, the verdict returned, and an alert for each file not judged benign. Analysts mark each alert resolved or false positive.

**What Sentinel watches:**
- Programs that start running (ignoring those in Windows and Program Files).
- Programs that connect to the internet on unusual ports.
- Files that appear in the Downloads, Temp and AppData folders.
- Local web servers (for example `python -m http.server`): Sentinel reads the server's file listing and downloads every `.exe`, `.dll`, `.sys`, `.scr`, `.ocx` and `.cpl` it offers, exactly as a browser would. These files are sent to SA2 Scan automatically in any mode, within about 5 seconds of being hosted. Extra server ports can be added in Settings.

**What makes a file worth sending (Rules mode):** it sits in a user-writable folder, it was downloaded from the internet, it has no valid digital signature, its program connects out on an unusual port, or it is on the analyst's watchlist. Two or more of these (the watchlist counts double) triggers an upload.

**Notifications.** Whenever Sentinel sends a file to SA2 Scan, Windows shows a notification at the bottom right. Clicking it opens that file's report in the browser. It can be switched off in Settings.

**Try it:** run `python -m http.server 9000` in a folder containing an `.exe` or `.dll`. A notification appears within seconds.

**What Sentinel does not do:** it does not capture network packets, so it cannot see files from other machines' servers or from encrypted (HTTPS) traffic; it finds files on web servers running on the same computer. It does not run, delete or block anything.

## Safety and data handling

- Files are only read and measured, never run.
- Uploaded files are kept read-only on the SA2 Scan machine and are never served back to users.
- SA2 Scan requires sign-in; Sentinel authenticates with an access key.
- Everything runs locally; no file or result is sent to an outside service. The one download is the public EMBER2024 model on first install.

## Scope

SA2 inspects Windows program files by static analysis. Verdicts are triage guidance for analysts, with the reasoning shown for each.

---

# Part 2: Technical reference

## Abstract

SA2 classifies Windows PE files (`.exe`, `.dll`, `.sys`) as malicious or benign by static analysis: files are parsed and hashed, never executed. Two engines score every file:

- **EMBER2024**, the pretrained EMBER2024 PE model (LightGBM, Apache-2.0) over the 2,568-dimension EMBER v3 feature vector.
- **Binary Ninja model**, a LightGBM over 114 Binary Ninja features (`cap6_*` capabilities, `hl6_*` HLIL indicators), trained on 1,256 files.

The **V8 blend** combines them. It was frozen before testing and then scored once, with no refitting, on three independent cohorts.

| Evaluation | Files (benign / malware) | Blend TPR | EMBER2024 TPR | TPR change (95% CI) |
|---|---|---|---|---|
| V8 blind | 281 / 443 | 0.919 | 0.905 | +1.35 pp (+0.44 to +2.59) |
| V9 replication | 955 / 608 | 0.890 | 0.882 | +0.82 pp (−0.33 to +1.97) |
| V10 replication | 2000 / 2500 | 0.932 | 0.920 | +1.20 pp (+0.69 to +1.69) |

V10 false positives: 3 of 2000 (blend), 4 of 2000 (EMBER2024). V10 ROC-AUC: 0.9980 (blend), 0.9975 (EMBER2024).

## Components

| Part | Role | Location | Port |
|---|---|---|---|
| SA2 Scan | Analyst console: upload or search files, read verdict and reasoning, dashboard of results and correlations | `src/webscan/` | 8000 |
| SA2 Sentinel | Endpoint agent and console: watches processes, connections and downloads; uploads selected executables to SA2 Scan. Reports only; never kills or blocks | `src/edr/` | 8001 |
| Scorer | `python -m src.v8.deploy`: the blend as a command-line tool | `src/v8/` | – |
| Research pipeline | Feature extraction, training, experiments V1–V10 | `src/`, `artifacts/` | – |

## How a verdict is made

1. **Features.** `thrember` extracts the EMBER v3 vector. If Binary Ninja is reachable, two passes extract capabilities (intermediate analysis) and HLIL indicators (full analysis); results are cached per SHA-256 in `artifacts/dashboard/bn_cache/`.
2. **Blend.** With Binary Ninja features: `m = logit(EMBER2024) + 0.3 · logit(BN) − t_blend`. Without them: `m = logit(EMBER2024) − logit(thr_R1)`. The file is malicious when `m ≥ 0`.
3. **Score.** Displayed as `sigmoid(m + logit(thr_R1))`; one threshold, `thr_R1 = 0.3149`, applies to every file. Scores at or above EMBER2024's 5% training-FPR point but below the threshold are *borderline* and queued for review.
4. **Decision path.** Every report states `V8 blend` or `EMBER2024 only`, with the reason: `bn_disabled`, `bn_busy`, `bn_unreachable`, `bn_too_large`, `bn_timeout`, `bn_error`, `bn_unusable`.
5. **Explanation.** REASONING tab: score waterfall by factor group and top SHAP contributions in plain English against typical benign/malware values (`artifacts/v8/feature_reference.json`). SIGNALS tab: signature validity and signer, installer/packer format, API capability groups, structural anomalies, EDR origin. The assessment note never changes the verdict.

## Training

- **Pool:** 5,864 files with EMBER v3 features (3,506 benign, 2,358 malware); 1,256 also have both Binary Ninja feature sets.
- **BN model:** LightGBM on `cap6_*` and `hl6_*` only, trained on the 1,256 covered files.
- **Blend weight:** w = 0.3, chosen by nested half-split evaluation over 10 seeds on training data only.
- **Thresholds:** frozen in `artifacts/v8/freeze/freeze_manifest.json`. `thr_R1` = 0.3149 (1% FPR on the training pool); the blend threshold admits no more covered training benign files than EMBER2024 does.
- **Cohorts:** every evaluation cohort was frozen before feature extraction and is disjoint by SHA-256, path, directory group and imphash from all earlier cohorts. Malware comes from MalwareBazaar; benign files from Windows component stores, Program Files and DriverStore.
- **Integrity:** `python -m src.v8.deploy --verify-freeze` checks the deployed models and modules against the freeze manifest; the dashboard refuses to start if a model pickle differs.

## Installation (Windows 10/11)

Requires Python 3.11–3.13 with the `py` launcher, Git, ~700 MB disk, and internet on first run (pypi.org, github.com for `thrember`, huggingface.co for the 3.7 MB EMBER2024 model, SHA-256 checked). Binary Ninja with its MCP server is optional.

```powershell
git clone https://github.com/Kinneh04/Sec-Analysis-Coursework-2.git
cd Sec-Analysis-Coursework-2
```

1. Run **`dashboard.setup.bat`**. It builds `.venv`, installs `requirements.txt`, downloads the model and opens http://127.0.0.1:8000. The console prints the sign-in password and EDR API key.
2. Run **`edr.setup.bat`** (as administrator for full visibility). It opens http://127.0.0.1:8001/settings.
3. In EDR Settings: Dashboard URL `http://127.0.0.1:8000`, paste the API key (also under Admin → Sensors & API key), **Test connection**, **Save**. The sensor shows *Online* within 30 s.

Both scripts accept a port (`dashboard.setup.bat 8010`). Stop SA2 Scan before re-running a setup script; a running app locks files in `.venv`.

Without the scripts:

```powershell
.\.venv\Scripts\python.exe -m src.v8.deploy --download-model
.\.venv\Scripts\python.exe -m src.webscan.app --port 8000
.\.venv\Scripts\python.exe -m src.edr.app --port 8001
```

## Using SA2 Scan

- **Upload:** home page, or drop a file anywhere. Report tabs: DETECTION, REASONING, SIGNALS, DETAILS, ORIGIN, RAW. Export JSON, CSV or PDF. Record an analyst decision (confirmed, false positive, benign); it never changes the model verdict.
- **Dashboard** (`/dashboard`): detections over time, score history, engine agreement, decision paths, signal co-occurrence, factor-group heatmap, review queue.
- **Model** (`/model`): live numbers read from the V8, V9 and V10 result files.
- **Reanalyze** re-scores a file (use after a `bn_busy` or `bn_unreachable` fallback). **Settings → Re-analyse all files** forces a full re-scan.

## Using SA2 Sentinel

Modes (Settings):

- **Allowlist only** (default): uploads only the listed paths. Add the full path of an `.exe`, **Save**; it is uploaded, scanned and listed under Binary Search and on the dashboard.
- **Rules:** uploads any PE with rule score ≥ 2 (for example unsigned and in a user-writable folder).

Settings are stored in `artifacts/edr/edr.db`. The console binds to `127.0.0.1` only.

## Configuration

| Variable | Effect |
|---|---|
| `SA2_ADMIN_PASSWORD` | Admin password (generated and printed at start if unset) |
| `SA2_BN=0` | Disable Binary Ninja; every verdict is EMBER2024 |
| `SA2_BN_MCP_URL` | MCP endpoint (default `http://127.0.0.1:24642/mcp`) |
| `SA2_BN_PROBE_TIMEOUT` / `SA2_BN_CONNECT_TIMEOUT` | Probe (default 1 s) and session-open (default 30 s) timeouts |
| `SA2_BN_LOCK` | Lock-file path (default `sa2scan_bn.lock` in temp) |
| `SA2_BN_MODE_SWITCH` | `off` (default): Binary Ninja stays open and is used in its current analysis mode (leave it in `full`); recorded in the report. `restart`: close and relaunch Binary Ninja in the mode each pass needs, as the research did |
| `SA2_BN_EXE`, `SA2_UPX` | Paths to `binaryninja.exe` and `upx.exe` |
| `SA2_EMBER_DOWNLOAD=0` | Verify the model only; never download |
| `SA2_NO_BROWSER=1`, `SA2_NO_PAUSE=1` | Setup scripts do not open a browser / pause on error |
| `--host 0.0.0.0` | Serve SA2 Scan on the network (Flask dev server; trusted networks only) |

## Binary Ninja

By default (`SA2_BN_MODE_SWITCH=off`) Binary Ninja stays open and every scan runs through its MCP connection in whatever analysis mode it is in; keep it in `full` (its default). Reports note that the research's per-pass analysis modes were not enforced. With `SA2_BN_MODE_SWITCH=restart`, each scan closes `binaryninja.exe`, rewrites `%APPDATA%\Binary Ninja\settings.json` (backup `settings.json.sa2scan_backup`), relaunches in intermediate mode, then full mode, then restores the settings; save your work first and expect minutes per file. If SA2 Scan stops mid-scan in that mode, the next start restores the backup. One process at a time uses Binary Ninja, enforced by a lock file; a second process scores with EMBER2024 and reports `bn_busy`. Files over 16 MB after overlay stripping are scored by EMBER2024; UPX files are unpacked with `upx -d` first.

## Command line

```powershell
.\.venv\Scripts\python.exe -m src.v8.deploy C:\path\file.exe
.\.venv\Scripts\python.exe -m src.v8.deploy --recursive C:\dir --no-bn --summary
.\.venv\Scripts\python.exe -m src.v8.deploy --recursive C:\dir --output scores.jsonl
.\.venv\Scripts\python.exe -m src.v8.deploy --verify-freeze --no-bn --summary C:\path\file.exe
```

## Research pipeline

Needs the MalwareBazaar corpus, a benign PE corpus and Binary Ninja. Paths go in `configs/local.yaml` (template `configs/local.example.yaml`).

```powershell
.\.venv\Scripts\python.exe -m src.inventory --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.pe_features --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.bn_features --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.build_dataset --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.train --config configs/local.yaml
.\.venv\Scripts\python.exe -m src.evaluate --config configs/local.yaml
```

Experiment history: V1–V7 tested PE-only, structured BN, stackers and guards against EMBER2024; V3.2 met its rule and was the earlier dashboard model; V8 introduced the blend; V9 and V10 are the independent replications above. Result files: `artifacts/v8/blind/blind_results.json`, `artifacts/v9/blind/replication_results.json`, `artifacts/v10/blind/replication_results.json`. The V3.2 scorer remains available (`python -m src.v3.score`).

## Layout

```
dashboard.setup.bat, edr.setup.bat   one-click start (scripts/ensure_venv.bat builds .venv)
requirements.txt                     pinned runtime (lightgbm 4.7.0, scikit-learn 1.7.2, numpy 2.2.6, pefile 2024.8.26, signify 0.7.1, thrember)
src/webscan/                         SA2 Scan (Flask)
src/edr/                             SA2 Sentinel (Flask + agent)
src/v8/                              deployed blend: deploy.py, bn_live.py, ember_map.py
src/common/                          hashing, sqlite, Authenticode helpers
src/v2 … src/v10                     research code
artifacts/v8/                        frozen models, freeze manifest, blind results, feature reference
artifacts/v9/, artifacts/v10/        replication results
docs/manual.md                       this manual
tests/                               pytest suite
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `pip install failed` / `Could not install packages due to an OSError` | Stop SA2 Scan and SA2 Sentinel (they hold `.venv` DLLs open), then re-run. If it is a network failure, check access to pypi.org and github.com |
| `Python 3.11, 3.12 or 3.13 was not found` | Install Python from python.org with the `py` launcher |
| `The EMBER2024 model is not usable` | Run `python -m src.v8.deploy --download-model`, or copy `EMBER2024_PE.model` into `artifacts\ember2024\models\artifacts\ember2024\models\` |
| `Missing model file: artifacts\v8\models\...` | `git pull`; the V8 pickles are tracked |
| `V8 freeze verification failed` | `git checkout -- artifacts/v8/models` |
| `Port 8000 is already in use` | Close the other program or pass another port |
| `bn_busy` | Another process holds Binary Ninja; press **Reanalyze** later |
| `bn_unreachable` | Start Binary Ninja with its MCP server, or check `SA2_BN_MCP_URL` |
| Binary Ninja settings wrong after a crash | Start SA2 Scan once, or copy `settings.json.sa2scan_backup` over `settings.json` |
| EDR shows *limited visibility* | Run `edr.setup.bat` as administrator |
| EDR shows *Unauthorized* | Re-copy the API key from Admin → Sensors & API key |
| Start fresh | Stop both apps; delete `artifacts/dashboard/` and `artifacts/edr/` |

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Covers upload, scan and report, both decision paths, engine disagreement, exports, API-key and admin auth, non-PE rejection, dedup, heartbeat, EDR rules, CSRF/host guard, an EDR-to-dashboard transport test, and the V8 scorer. Tests that need the downloaded model, `notepad.exe` or untracked research artifacts skip when those are absent.
