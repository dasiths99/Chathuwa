@echo off
setlocal EnableExtensions

cd /d "%~dp0"
title CyberWatch Full Project

if not exist ".venv\Scripts\activate.bat" (
    echo ERROR: .venv was not found.
    echo Run setup_full_project.bat first.
    pause
    exit /b 1
)

call ".venv\Scripts\activate.bat"

echo ========================================
echo Starting CyberWatch Full Project
echo ========================================
echo Main dashboard : http://localhost:5000
echo API Analyzer   : http://localhost:5005/api-analyzer
echo.

python app.py

echo.
echo Project stopped with exit code %errorlevel%.
pause
