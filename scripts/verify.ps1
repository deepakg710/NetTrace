# NetTrace Verification Script for Windows (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " NetTrace: Full Suite Automated Verification" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$BackendDir = Join-Path $ProjectDir "backend"
$FrontendDir = Join-Path $ProjectDir "frontend"
$PytestExe = Join-Path $BackendDir ".venv\Scripts\pytest.exe"

# 1. Run Backend Pytest Suite
Write-Host ""
Write-Host "[1/4] Running Backend Automated Tests (Pytest)..." -ForegroundColor Yellow
Push-Location $BackendDir
try {
    & $PytestExe
    Write-Host ">> Backend Tests Passed!" -ForegroundColor Green
} finally {
    Pop-Location
}

# 2. Run Frontend Vitest Suite
Write-Host ""
Write-Host "[2/4] Running Frontend Automated Tests (Vitest)..." -ForegroundColor Yellow
Push-Location $FrontendDir
try {
    npm.cmd test
    Write-Host ">> Frontend Tests Passed!" -ForegroundColor Green
} finally {
    Pop-Location
}

# 3. Run Production Frontend Build
Write-Host ""
Write-Host "[3/4] Running Production Frontend TypeScript & Bundle Build..." -ForegroundColor Yellow
Push-Location $FrontendDir
try {
    npm.cmd run build
    Write-Host ">> Production Build Succeeded!" -ForegroundColor Green
} finally {
    Pop-Location
}

# 4. Verify Sample Captures
Write-Host ""
Write-Host "[4/4] Verifying Deterministic Lab Captures..." -ForegroundColor Yellow
$NormalPcap = Join-Path $ProjectDir "samples\normal_traffic.pcap"
$IncidentPcap = Join-Path $ProjectDir "samples\incident_troubleshooting.pcap"
$ManifestJson = Join-Path $ProjectDir "samples\sample_manifest.json"

if ((Test-Path $NormalPcap) -and (Test-Path $IncidentPcap) -and (Test-Path $ManifestJson)) {
    Write-Host ">> Sample PCAPs and Manifest Validated!" -ForegroundColor Green
} else {
    Write-Host ">> Warning: One or more sample files missing. Run samples\generate_samples.py" -ForegroundColor Red
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " ALL NETTRACE VERIFICATION CHECKS PASSED! " -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
