# One daily scale batch (25 binaries, respects 2h cumulative budget in progress file).
Set-Location (Join-Path $PSScriptRoot "..")
$py = ".\.venv\Scripts\python.exe"
& $py -m src.ensure_bn_mcp --wait 240
if ($LASTEXITCODE -ne 0) { exit 1 }
& $py -m src.bn_scale_extract --config configs/local.yaml
exit $LASTEXITCODE
