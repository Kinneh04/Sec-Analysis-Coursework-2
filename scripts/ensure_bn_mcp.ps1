# Start Binary Ninja GUI if needed and wait for MCP HTTP endpoint.
param(
    [string]$BnExe = "$env:LOCALAPPDATA\Programs\Vector35\BinaryNinja\binaryninja.exe",
    [string]$McpUrl = "http://127.0.0.1:24642/mcp",
    [int]$WaitSeconds = 180
)

function Test-McpUp {
    param([string]$Url)
    try {
        $body = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sa2","version":"1"}}}'
        $r = Invoke-WebRequest -Uri $Url -Method POST -ContentType "application/json" -Body $body -TimeoutSec 5 -UseBasicParsing
        return ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500)
    } catch {
        return $false
    }
}

$proc = Get-Process -Name "binaryninja" -ErrorAction SilentlyContinue
if (-not $proc) {
    if (-not (Test-Path $BnExe)) {
        Write-Error "Binary Ninja not found at $BnExe"
        exit 1
    }
    Write-Host "Starting Binary Ninja: $BnExe"
    Start-Process -FilePath $BnExe
    Start-Sleep -Seconds 8
} else {
    Write-Host "Binary Ninja already running (pid $($proc.Id))"
}

$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ((Get-Date) -lt $deadline) {
    if (Test-McpUp $McpUrl) {
        Write-Host "MCP ready at $McpUrl"
        exit 0
    }
    Start-Sleep -Seconds 3
}

Write-Error "MCP did not become ready within ${WaitSeconds}s. Enable MCP in Binary Ninja / Cursor integration."
exit 1
