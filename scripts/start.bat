@echo off
REM ─────────────────────────────────────────────
REM  start.bat  —  Start the app (Windows)
REM  Double-click this file or run from cmd
REM ─────────────────────────────────────────────
cd /d "%~dp0.."

echo.
echo   AD/IAM Auditor v2.0
echo   http://localhost:5000
echo.

REM Activate venv if it exists
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
) else (
    echo   No venv found. Running with system Python.
    echo   Tip: run  python -m venv venv  to create one.
)

REM Install deps if needed
pip show flask >nul 2>&1 || pip install -r requirements.txt

REM Start Flask
start "" http://localhost:5000
python run.py
pause
