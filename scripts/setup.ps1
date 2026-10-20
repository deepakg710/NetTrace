# NetTrace Setup Script for Windows (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " NetTrace Setup: Environment & Runtime " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$BackendDir = Join-Path $ProjectDir "backend"
$FrontendDir = Join-Path $ProjectDir "frontend"
$VenvDir = Join-Path $BackendDir ".venv"

# 1. Setup Backend Virtual Environment
Write-Host "[1/4] Setting up Python virtual environment..." -ForegroundColor Yellow
if (-not (Test-Path $VenvDir)) {
    python -m venv $VenvDir
    Write-Host "Created virtual environment at $VenvDir" -ForegroundColor Green
} else {
    Write-Host "Existing virtual environment found." -ForegroundColor Gray
}

$PipExe = Join-Path $VenvDir "Scripts\pip.exe"
$PythonExe = Join-Path $VenvDir "Scripts\python.exe"

Write-Host "[2/4] Installing backend dependencies..." -ForegroundColor Yellow
& $PipExe install -r (Join-Path $BackendDir "requirements.txt")

# 2. Generate Deterministic Samples
Write-Host "[3/4] Generating lab sample captures..." -ForegroundColor Yellow
$SampleGen = Join-Path $ProjectDir "samples\generate_samples.py"
& $PythonExe $SampleGen

# 3. Setup Frontend Node modules
Write-Host "[4/4] Installing frontend npm packages..." -ForegroundColor Yellow
Push-Location $FrontendDir
try {
    npm.cmd install
} finally {
    Pop-Location
}

Write-Host "==========================================" -ForegroundColor Green
Write-Host " Setup Complete! Run .\scripts\start.ps1  " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
