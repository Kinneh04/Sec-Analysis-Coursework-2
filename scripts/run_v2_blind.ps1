# Blind evaluation (blocked until protocol frozen and manifest present).
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

$py = ".\.venv\Scripts\python.exe"
& $py -m src.v2.cli evaluate-blind --config configs/v2_experiment.yaml
exit $LASTEXITCODE
