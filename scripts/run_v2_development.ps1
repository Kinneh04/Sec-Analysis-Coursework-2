# Week 1 + future development driver (does not modify V1 artifacts).
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

$py = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "Missing .venv; create Python 3.10 venv first." }

& $py -m pytest tests/test_v2_v1_guard.py tests/test_v2_inputs.py tests/test_v2_week1_gate.py -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $py -m src.v2.cli inspect --config configs/v2_experiment.yaml
$code = $LASTEXITCODE
if ($code -ne 0) {
    Write-Host "Week 1 gate FAILED — fix integrity before develop."
    exit $code
}

& $py -m src.v2.cli develop --config configs/v2_experiment.yaml
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $py -m src.v2.cli report --config configs/v2_experiment.yaml
Write-Host "Week 2 develop complete. See artifacts/v2/reports/development_report.md"
exit 0
