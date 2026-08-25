@echo off
REM SentinelTrace AI - Quick Start Script for Windows

echo.
echo =====================================================
echo  SentinelTrace AI - Email Threat Detection Platform
echo  Smart India Hackathon 2026 - SIH26106
echo =====================================================
echo.

REM Check if virtual environment exists
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)

REM Activate virtual environment
echo Activating virtual environment...
call .venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt --quiet

REM Clear screen
cls

echo.
echo =====================================================
echo  Starting SentinelTrace AI Backend...
echo =====================================================
echo.
echo Backend URL: http://localhost:8000
echo API Docs: http://localhost:8000/docs
echo.
echo Press Ctrl+C to stop the server.
echo.

REM Start backend
cd backend
python main.py
