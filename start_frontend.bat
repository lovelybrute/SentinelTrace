@echo off
REM SentinelTrace AI - Modern Web Frontend Start Script (SIH 26106)

echo.
echo =====================================================
echo  SentinelTrace AI - Modern SOC Frontend Server
echo  Smart India Hackathon 2026 - SIH26106
echo =====================================================
echo.
echo Starting Vite Dev Server with Network Host Link enabled...
echo.
echo Press Ctrl+C to stop the server.
echo.

cd web
npm run dev -- --host
