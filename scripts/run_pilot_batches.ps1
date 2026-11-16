# Resumable BN compatibility pilot with auto-start/restart of Binary Ninja.
param(
    [int]$BatchSize = 4,
    [int]$MaxBatches = 20,
    [int]$PauseSeconds = 8
)

Set-Location (Join-Path $PSScriptRoot "..")

$py = ".\.venv\Scripts\python.exe"
for ($b = 1; $b -le $MaxBatches; $b++) {
    Write-Host "=== pilot batch $b (max-new $BatchSize) ==="
    & $py -m src.ensure_bn_mcp --wait 240
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "ensure_bn_mcp failed; waiting ${PauseSeconds}s before retry"
        Start-Sleep -Seconds $PauseSeconds
        continue
    }
    & $py -m src.bn_compatibility_pilot --config configs/local.yaml --max-new $BatchSize
    $report = Get-Content "artifacts\evaluations\bn_compatibility_pilot.json" -Raw | ConvertFrom-Json
    Write-Host "pending=$($report.pending_mcp) complete=$($report.pilot_complete) pass=$($report.pilot_pass)"
    if ($report.pilot_complete -eq $true) {
        Write-Host "PILOT COMPLETE"
        exit 0
    }
    Start-Sleep -Seconds $PauseSeconds
}
Write-Warning "Stopped after $MaxBatches batches; re-run to continue."
exit 1
