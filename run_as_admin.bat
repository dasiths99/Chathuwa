@echo off
echo ========================================
echo Network Flow Monitor - Real Traffic Capture
echo ========================================
echo.
echo Requesting Administrator privileges...
echo.

:: Check if running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Not running as administrator. Restarting with admin rights...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ✓ Running with Administrator privileges
echo.

:: Navigate to project directory
cd /d "D:\Desktop\Ayesha Nangi SLIIT - Group\Group 1\Very New"

:: Install required packages if not installed
echo Installing required packages...
python -m pip install flask flask-socketio scapy psutil netifaces python-socketio --quiet

echo.
echo ========================================
echo Starting Network Flow Monitor
echo ========================================
echo Server URL: http://localhost:5000
echo Mode: REAL PACKET CAPTURE
echo ========================================
echo.

:: Run the application
python app.py

pause