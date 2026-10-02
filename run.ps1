# RedFlag - Threat Defense Radar (PowerShell Startup)
param (
    [string]$Mode = "serve"
)

Set-Location $PSScriptRoot

if ($Mode -eq "seed") {
    Write-Host "==> Seeding demo database..." -ForegroundColor Cyan
    Set-Location backend
    python seed_demo.py
    Set-Location ..
    exit 0
}

if ($Mode -eq "build") {
    Write-Host "==> Building frontend..." -ForegroundColor Cyan
    Set-Location frontend
    npm run build
    Set-Location ..
    exit 0
}

Write-Host "==> Starting RedFlag Platform..." -ForegroundColor Green
Write-Host "  Backend:  http://localhost:8000" -ForegroundColor Yellow
Write-Host "  Frontend: http://localhost:5173" -ForegroundColor Yellow

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\backend'; python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\frontend'; npm run dev"
