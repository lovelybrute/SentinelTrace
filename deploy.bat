@echo off
REM ============================================================
REM SentinelTrace AI - Deployment Script
REM Smart India Hackathon 2026 - SIH26106
REM ============================================================

echo.
echo ===============================================
echo  SentinelTrace AI - Email Threat Detection
echo  Deployment Script
echo ===============================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b 1
)

echo [*] Python detected
python --version

REM Create virtual environment if not exists
if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
)

REM Activate virtual environment
echo [*] Activating virtual environment...
call .\.venv\Scripts\activate.bat

REM Install dependencies
echo [*] Installing dependencies...
pip install -r requirements.txt --quiet

REM Initialize database
echo [*] Initializing database...
cd backend
python -c "from database import init_db; init_db(); print('[+] Database initialized successfully')"
cd ..

REM Display startup information
echo.
echo ===============================================
echo  SentinelTrace AI Ready!
echo ===============================================
echo.
echo [+] Backend Server:
echo     Command: cd backend ^&^& python main.py
echo     URL: http://localhost:8000
echo     Docs: http://localhost:8000/docs
echo.
echo [+] Frontend Dashboard:
echo     Open: frontend/index.html in your browser
echo     or serve with: python -m http.server 8080
echo.
echo [+] API Endpoints:
echo     POST   /analyze - Analyze email
echo     GET    /stats - Platform statistics
echo     GET    /recent-threats - Recent threats
echo     GET    /threat-by-country - Threat distribution
echo.
echo [+] Default Threat Levels:
echo     LOW (0-24)         - Safe email
echo     MEDIUM (25-49)     - Some indicators
echo     HIGH (50-74)       - Multiple threats
echo     CRITICAL (75-100)  - Highly suspicious
echo.
echo ===============================================
echo.

pause
