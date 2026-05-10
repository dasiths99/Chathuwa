@echo off
setlocal EnableExtensions

cd /d "%~dp0"
title API Behavior Analysis - Port 5005

if not exist ".venv\Scripts\activate.bat" (
    echo ERROR: .venv was not found.
    echo Run setup_full_project.bat first.
    pause
    exit /b 1
)

if not exist "System\app.py" (
    echo ERROR: System\app.py was not found.
    pause
    exit /b 1
)

call ".venv\Scripts\activate.bat"

set "PORT=5005"
set "DEBUG=false"

echo ========================================
echo Starting API Behavior Analysis
echo ========================================
echo URL: http://localhost:5005/api-analyzer
echo.

cd /d "%~dp0System"
python app.py

echo.
echo API service stopped with exit code %errorlevel%.
pause
