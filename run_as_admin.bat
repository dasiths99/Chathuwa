@echo off
setlocal EnableExtensions

echo ========================================
echo CyberWatch - Run as Administrator
echo (real packet capture needs admin on Windows)
echo ========================================
echo.
echo PowerShell users: do NOT use "cd /d" ^(that is cmd.exe syntax^).
echo   cd /d "%~dp0"   ^<- wrong in PowerShell
echo   Use instead:
echo     Set-Location "%~dp0"
echo     python app.py
echo   Or:  powershell -ExecutionPolicy Bypass -File "%~dp0run_stack.ps1"
echo   Or elevated:  powershell -ExecutionPolicy Bypass -File "%~dp0run_as_admin.ps1"
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

:: MUST use the folder where this .bat lives — elevated shortcuts start in System32
cd /d "%~dp0"
if not exist "app.py" (
    echo ERROR: app.py not found in:
    echo   %CD%
    echo Place this batch file in your Research project folder ^(next to app.py^).
    pause
    exit /b 1
)

echo Project directory: %CD%
echo.

:: Hard reset: kill old python processes (prevents zombie :5001 listeners)
echo Stopping old Python services (if any)...
taskkill /F /IM python.exe /T >nul 2>&1

:: netifaces is optional and needs MSVC to build — not used by network.py
echo Installing / updating Python packages ^(skipping netifaces^)...
python -m pip install -q Flask Flask-SocketIO Flask-CORS python-socketio scapy psutil eventlet python-dotenv numpy pynput tensorflow joblib scikit-learn
if %errorlevel% neq 0 (
    echo pip reported an error; trying minimal set...
    python -m pip install -q Flask Flask-SocketIO python-socketio scapy psutil
)

echo.
echo ========================================
echo Starting unified dashboard ^(app.py^)
echo ========================================
echo Main dashboard : http://localhost:5000
echo Network monitor: http://localhost:5001
echo ========================================
echo.

python app.py
if %errorlevel% neq 0 (
    echo.
    echo Python exited with error %errorlevel%.
)

pause
