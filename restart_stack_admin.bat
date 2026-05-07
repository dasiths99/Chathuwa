@echo off
setlocal EnableExtensions

echo ========================================
echo CyberWatch - FULL RESTART (Admin)
echo Kills old python.exe tree and starts app.py
echo ========================================
echo.

:: Re-launch elevated if needed
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

echo Running with Administrator privileges.
echo.

cd /d "%~dp0"
if not exist "app.py" (
    echo ERROR: app.py not found in:
    echo   %CD%
    pause
    exit /b 1
)

echo Stopping ALL python.exe processes (tree)...
taskkill /F /IM python.exe /T >nul 2>&1
timeout /t 2 /nobreak >nul

echo Starting app.py ^(auto-launches all components^)...
echo Main dashboard : http://localhost:5000
echo Network monitor: http://localhost:5001
echo Web Access     : http://localhost:5002
echo File ^& Mouse  : http://localhost:5003
echo.
py app.py

echo.
echo app.py exited with code %errorlevel%
pause
