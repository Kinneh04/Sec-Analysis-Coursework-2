# SA2 Scan operator guide (V8 deployment)

Updated 2026-11-18 for the switch from the V3.2 model to the V8 blend. The V3.2 commands are at the end.

## What decides a verdict

Two engines run on every file:

- `ember2024`: the pretrained EMBER2024 PE model (Apache-2.0) on the EMBER v3 feature vector.
- `v8_blend`: decides the verdict. When Binary Ninja features are available, it adds `0.3 · logit(BN model)` to EMBER2024's logit and compares the sum with `t_blend`. When they are not, it uses EMBER2024's own decision.

The score shown is on one display scale with one threshold, 0.3149 (`thr_R1`). On fallback files it is EMBER2024's raw score. It is not a calibrated probability.

Every report states its decision path: **V8 blend** or **EMBER2024 only**, with the reason (`bn_disabled`, `bn_busy`, `bn_unreachable`, `bn_too_large`, `bn_timeout`, `bn_error`, `bn_unusable`). `bn_busy` means another SA2 process was using Binary Ninja, or an earlier analysis in this process timed out and was still running; the file was not sent to Binary Ninja. When the two engines disagree, the report says so and which term moved the decision: the Binary Ninja term, the blend's fixed threshold offset (`logit(thr_R1) - t_blend`, +0.142 log-odds), or both together.

## Start-up

1. Run `dashboard.setup.bat`. The first run installs packages and downloads the EMBER2024 model (internet needed once). Later runs verify it and replace it if its hash is wrong. With `SA2_EMBER_DOWNLOAD=0` the script only verifies it and stops with a message if it is missing or wrong.
2. Read the console banner: password, API key, threshold, and whether Binary Ninja will be used.
3. If an earlier scan was interrupted while Binary Ninja's settings were changed, start-up restores them and says so (unless another SA2 process is using Binary Ninja at that moment; that process restores them itself).

## Binary Ninja

- Default (`SA2_BN_MODE_SWITCH=restart`): each scan that needs Binary Ninja closes and restarts it twice, then restores your settings. Save your work in Binary Ninja first. Expect minutes per file.
- `SA2_BN_MODE_SWITCH=off`: Binary Ninja stays open in its current mode. The report records this as a deviation from the frozen method.
- `SA2_BN=0`: no Binary Ninja; every verdict is EMBER2024 alone.
- Only one process should use Binary Ninja at a time: one dashboard, or the command-line scorer, not both. A lock file (`sa2scan_bn.lock` in the temp folder, or `SA2_BN_LOCK`) enforces it. A second process does not wait: its files fall back to EMBER2024 with reason `bn_busy`. Press **Reanalyze** later to get the blend.
- The Settings page shows the configuration in effect and whether the MCP endpoint answers.
- This path has not been tested against a live Binary Ninja. Check the first few reports (pass statuses, time) before relying on it.

## Triage

- **Malicious:** at or above the threshold. Read the decision path and the reasons before acting.
- **Borderline:** below the threshold but at or above EMBER2024's 5% training-FPR operating point. Not flagged; listed in the review queue. This band is a triage aid, not a measured operating point of the blend.
- **Benign:** below the borderline band.
- Record your decision on the report (confirmed, false positive, benign). It never changes the model verdict.

## Known limits

- The blend's gain over EMBER2024 is small: +1.20 percentage points TPR (95% CI +0.69 to +1.69) on V10 at the frozen threshold. V9 did not confirm it; V10 did.
- At the strictest operating point the blend did worse than EMBER2024 (V10, 0.25% training FPR: 16 detections gained, 43 lost).
- On the course Sample1/Sample2 files the blend flagged 1 of 7; EMBER2024 alone flagged 2 of 7.
- Static analysis only. Packed or compressed payloads may be missed. Use verdicts for triage, not as ground truth.

## Old reports

Reports made with the V3.2 model are re-scanned automatically at start-up. Until then they are marked as old V3.2 reports and their scores are not compared with the new threshold. **Settings → Re-analyse all files** forces a re-scan.

## Command line

```powershell
.\.venv\Scripts\python.exe -m src.v8.deploy --download-model                       # fetch if missing, replace if wrong hash
.\.venv\Scripts\python.exe -m src.v8.deploy C:\path\file.exe                        # uses Binary Ninja if reachable
.\.venv\Scripts\python.exe -m src.v8.deploy --recursive C:\dir --no-bn --summary    # EMBER2024 fallback only
.\.venv\Scripts\python.exe -m src.v8.deploy --recursive C:\dir --output scores.jsonl
```

## Legacy V3.2 commands (research record)

The V3.2 bundle (`artifacts/v3.2/`, `artifacts/deploy/`) no longer drives verdicts but still works:

```powershell
.\.venv\Scripts\python.exe -m src.v3.score --recursive C:\Suspicious\Folder --summary
.\.venv\Scripts\python.exe -m src.v3.freeze --verify --cohort-tag v3.2
```

Its evidence is in `docs/v3.2_results.md` and `docs/temporal_eval_2026.md`.
