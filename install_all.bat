@echo off
setlocal EnableExtensions

cd /d "%~dp0"

echo This project now uses setup_full_project.bat for a clean one-click setup.
echo Starting full setup...
echo.

call "%~dp0setup_full_project.bat"
