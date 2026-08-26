@echo off
REM ============================================================
REM SentinelTrace AI - Full Stack Host Launcher (SIH 26106)
REM ============================================================

echo.
echo =====================================================
echo  SENTINELTRACE AI - CYBER FORENSIC PLATFORM
echo  Smart India Hackathon 2026 - SIH26106
echo =====================================================
echo.

REM 1. Start Backend in a background window
echo [*] Launching Python FastAPI Backend Server on port 8000...
start "SentinelTrace Backend (FastAPI :8000)" cmd /k "cd backend && python main.py"

REM 2. Start Frontend with Host Links
echo [*] Launching Vite Frontend Dev Server on port 5173...
echo.
echo =====================================================
echo  Frontend Links:
echo  - Local:   http://localhost:5173/
echo  - Network: Available on your LAN IP (see Vite output below)
echo  Backend API: http://localhost:8000/docs
echo =====================================================
echo.

cd web
npm run dev -- --host
