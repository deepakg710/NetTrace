# NetTrace Shutdown Script for Windows (PowerShell)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$PidFile = Join-Path $ProjectDir ".running_pids.json"

Write-Host "Stopping NetTrace services..." -ForegroundColor Cyan

if (Test-Path $PidFile) {
    try {
        $pids = Get-Content $PidFile | ConvertFrom-Json
        if ($pids.BackendPid) {
            Stop-Process -Id $pids.BackendPid -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped Backend (PID $($pids.BackendPid))" -ForegroundColor Gray
        }
        if ($pids.FrontendPid) {
            Stop-Process -Id $pids.FrontendPid -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped Frontend (PID $($pids.FrontendPid))" -ForegroundColor Gray
        }
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "Could not cleanly terminate via PID file: $_" -ForegroundColor Yellow
    }
}

# Fallback kill on ports 8000 and 5173 if still bound
Get-NetTCPConnection -LocalPort 8000,5173 -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
}

Write-Host "NetTrace services stopped." -ForegroundColor Green
