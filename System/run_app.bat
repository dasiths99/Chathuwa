@echo off
cd /d "%~dp0"
set PORT=5005
set DEBUG=false
python app.py

if errorlevel 1 (
    echo.
    echo ERROR: API Behavior Analysis service failed to start
    pause
)
