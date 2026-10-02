@echo off
setlocal

echo =======================================================
echo          RedFlag - Threat Defense Radar
echo =======================================================

cd /d "%~dp0"

if "%1"=="seed" (
    echo [1/1] Seeding demo database...
    cd backend
    python seed_demo.py
    cd ..
    goto done
)

if "%1"=="build" (
    echo [1/1] Building frontend production bundle...
    cd frontend
    call npm run build
    cd ..
    goto done
)

echo Starting RedFlag Backend and Frontend Development Servers...
echo Backend:  http://localhost:8000
echo Frontend: http://localhost:5173
echo.

start "RedFlag Backend (:8000)" cmd /k "cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
start "RedFlag Frontend (:5173)" cmd /k "cd frontend && npm run dev"

:done
echo Done.
