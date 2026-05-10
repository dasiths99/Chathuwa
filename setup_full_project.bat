@echo off
setlocal EnableExtensions

cd /d "%~dp0"

title CyberWatch Full Project Setup

echo ==================================================
echo CyberWatch - One Click Full Project Setup
echo ==================================================
echo.
echo This setup will:
echo   1. Rebuild a local Python virtual environment
echo   2. Install all project Python packages
echo   3. Create launch files that use the local environment
echo.

if not exist "app.py" (
    echo ERROR: app.py not found.
    echo Place this file in the project root folder, next to app.py.
    pause
    exit /b 1
)

where py >nul 2>nul
if not errorlevel 1 (
    py -3.12 --version >nul 2>nul
    if not errorlevel 1 (
        set "PYTHON_CMD=py -3.12"
    ) else (
        set "PYTHON_CMD=py"
    )
) else (
    set "PYTHON_CMD=python"
)

echo Checking Python...
%PYTHON_CMD% --version
if errorlevel 1 (
    echo.
    echo ERROR: Python was not found.
    echo Install Python 3.10, 3.11, or 3.12 from:
    echo   https://www.python.org/downloads/
    echo.
    echo IMPORTANT: Tick "Add python.exe to PATH" during install.
    pause
    exit /b 1
)

echo.
echo Rebuilding virtual environment in .venv...
if exist ".venv" (
    echo Removing old .venv because virtual environments are not portable between laptops...
    rmdir /s /q ".venv"
    if exist ".venv" (
        echo.
        echo ERROR: Could not remove old .venv.
        echo Close any terminal or editor using .venv, then run this setup again.
        pause
        exit /b 1
    )
)

%PYTHON_CMD% -m venv .venv
if errorlevel 1 (
    echo.
    echo ERROR: Failed to create .venv.
    pause
    exit /b 1
)

echo.
echo Activating .venv...
call ".venv\Scripts\activate.bat"
if errorlevel 1 (
    echo.
    echo ERROR: Failed to activate .venv.
    pause
    exit /b 1
)

echo.
echo Upgrading pip, setuptools, and wheel...
python -m pip install --upgrade pip setuptools wheel
if errorlevel 1 (
    echo.
    echo ERROR: Failed to upgrade pip tools.
    pause
    exit /b 1
)

echo.
echo Installing root requirements...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo ERROR: Failed to install root requirements.txt.
    pause
    exit /b 1
)

echo.
echo Installing System API Analyzer requirements...
python -m pip install -r System\requirements.txt
if errorlevel 1 (
    echo.
    echo ERROR: Failed to install System\requirements.txt.
    pause
    exit /b 1
)

echo.
echo Installing extra tools used by project scripts...
python -m pip install requests
if errorlevel 1 (
    echo.
    echo ERROR: Failed to install requests.
    pause
    exit /b 1
)

echo.
set /p INSTALL_TF="Install TensorFlow for optional deep-learning models? This is large. (y/N): "
if /i "%INSTALL_TF%"=="y" (
    python -m pip install tensorflow
    if errorlevel 1 (
        echo.
        echo WARNING: TensorFlow failed to install.
        echo The project can still run, but Keras/TensorFlow model features may use fallback behavior.
    )
)

echo.
echo Checking important files...
if not exist "System\app.py" echo WARNING: System\app.py not found.
if not exist "System\API_analyzer\Models\api_model.pkl" echo WARNING: API analyzer model file not found.
if not exist "System\API_analyzer\Models\api_scaler.pkl" echo WARNING: API analyzer scaler file not found.
if not exist "System\API_analyzer\Models\api_label_encoder.pkl" echo WARNING: API analyzer label encoder file not found.

echo.
echo ==================================================
echo Setup complete.
echo ==================================================
echo.
echo Run full project:
echo   start_full_project.bat
echo.
echo Run only API Behavior Analysis on port 5005:
echo   start_api_5005.bat
echo.
echo Manual install needed for live network packet capture:
echo   1. Install Npcap from https://npcap.com/
echo   2. Run capture features as Administrator
echo.
pause
