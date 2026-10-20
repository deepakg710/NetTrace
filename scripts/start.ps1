# NetTrace Startup Script for Windows (PowerShell)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$BackendDir = Join-Path $ProjectDir "backend"
$FrontendDir = Join-Path $ProjectDir "frontend"
$PythonExe = Join-Path $BackendDir ".venv\Scripts\python.exe"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " NetTrace: Starting Local Toolkit        " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Check if venv exists
if (-not (Test-Path $PythonExe)) {
    Write-Host "Virtual environment not detected. Running setup first..." -ForegroundColor Yellow
    & (Join-Path $ScriptDir "setup.ps1")
}

# 1. Start Backend in separate process
Write-Host "Starting FastAPI Backend on http://127.0.0.1:8000..." -ForegroundColor Green
$BackendProc = Start-Process -FilePath $PythonExe -ArgumentList "-m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload" -WorkingDirectory $BackendDir -PassThru

# 2. Start Frontend in separate process
Write-Host "Starting React Frontend on http://127.0.0.1:5173..." -ForegroundColor Green
$FrontendProc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c npm.cmd run dev" -WorkingDirectory $FrontendDir -PassThru

# Save PIDs to stop.ps1
$PidFile = Join-Path $ProjectDir ".running_pids.json"
@{
    BackendPid = $BackendProc.Id
    FrontendPid = $FrontendProc.Id
} | ConvertTo-Json | Set-Content $PidFile

Write-Host ""
Write-Host "NetTrace is running!" -ForegroundColor Cyan
Write-Host " - Frontend Dashboard : http://127.0.0.1:5173" -ForegroundColor White
Write-Host " - Backend API Docs   : http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host " - Health Check       : http://127.0.0.1:8000/api/v1/health" -ForegroundColor White
Write-Host ""
Write-Host "To stop both processes, run: .\scripts\stop.ps1" -ForegroundColor Yellow
