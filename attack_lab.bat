@echo off
setlocal enabledelayedexpansion
title Network Attack Lab
cd /d "%~dp0"

if /i not "%~1"=="--keep-open" (
  echo %cmdcmdline% | find /i "/c" >nul 2>&1
  if not errorlevel 1 (
    cmd /k ""%~f0" --keep-open"
    exit /b
  )
)

:PY_SETUP
set "PY="
call py -3 -c "import sys" >nul 2>&1 && set "PY=py -3"
if not defined PY (
  call python -c "import sys" >nul 2>&1 && set "PY=python"
)
if not defined PY (
  cls
  echo ============================================================
  echo   ERROR: Python not found
  echo ============================================================
  echo.
  echo Install Python 3, or enable the "py" launcher.
  echo Then run this file again.
  echo.
  choice /c RX /n /m "Press R to retry or X to exit: "
  if errorlevel 2 goto EXIT
  goto PY_SETUP
)

:MAIN_MENU
cls
echo ============================================================
echo   NETWORK ATTACK LAB  -  Select and Run
echo   Monitor: http://localhost:5001
echo ============================================================
echo.
echo   [0]  System Check      (verify honeypots are running)
echo.
echo   [1]  SSH Brute Force    = detects SSH-Patator
echo   [2]  FTP Brute Force    = detects FTP-Patator
echo   [3]  RDP Brute Force    = detects Brute Force
echo   [4]  Telnet Brute Force = detects Brute Force
echo   [5]  VNC Brute Force    = detects Brute Force
echo.
echo   [6]  SSH DDoS Flood     = detects DDoS
echo   [7]  RDP DDoS Flood     = detects DDoS
echo.
echo   [8]  Port Scan          = detects PortScan
echo.
echo   [9]  Exit
echo.
echo ============================================================
choice /c 0123456789 /n /m "  Select [0-9]: "
set "CHOICE=%errorlevel%"

if "%CHOICE%"=="1" goto SYSTEM_CHECK
if "%CHOICE%"=="2" goto ATTACK_SSH
if "%CHOICE%"=="3" goto ATTACK_FTP
if "%CHOICE%"=="4" goto ATTACK_RDP
if "%CHOICE%"=="5" goto ATTACK_TELNET
if "%CHOICE%"=="6" goto ATTACK_VNC
if "%CHOICE%"=="7" goto DDOS_SSH
if "%CHOICE%"=="8" goto DDOS_RDP
if "%CHOICE%"=="9" goto SCAN
if "%CHOICE%"=="10" goto EXIT
goto MAIN_MENU

:SYSTEM_CHECK
cls
set "LAST_ACTION=SYSTEM_CHECK"
call %PY% attack_lab_runner.py system
goto AFTER_RUN

:ATTACK_SSH
cls
set "LAST_ACTION=ATTACK_SSH"
call %PY% attack_lab_runner.py brute ssh 2222 SSH-Patator
goto AFTER_RUN

:ATTACK_FTP
cls
set "LAST_ACTION=ATTACK_FTP"
call %PY% attack_lab_runner.py brute ftp 2121 FTP-Patator
goto AFTER_RUN

:ATTACK_RDP
cls
set "LAST_ACTION=ATTACK_RDP"
call %PY% attack_lab_runner.py brute rdp 13389 "Brute Force"
goto AFTER_RUN

:ATTACK_TELNET
cls
set "LAST_ACTION=ATTACK_TELNET"
call %PY% attack_lab_runner.py brute telnet 2323 "Brute Force"
goto AFTER_RUN

:ATTACK_VNC
cls
set "LAST_ACTION=ATTACK_VNC"
call %PY% attack_lab_runner.py brute vnc 5901 "Brute Force"
goto AFTER_RUN

:DDOS_SSH
cls
set "LAST_ACTION=DDOS_SSH"
call %PY% attack_lab_runner.py ddos ssh 2222
goto AFTER_RUN

:DDOS_RDP
cls
set "LAST_ACTION=DDOS_RDP"
call %PY% attack_lab_runner.py ddos rdp 13389
goto AFTER_RUN

:SCAN
cls
set "LAST_ACTION=SCAN"
call %PY% attack_lab_runner.py scan
goto AFTER_RUN

:AFTER_RUN
echo.
echo Attack/check finished. The window will stay open.
choice /c MR /n /m "Press M for menu or R to run the same option again: "
if errorlevel 2 goto RERUN_LAST
goto MAIN_MENU

:RERUN_LAST
if "%LAST_ACTION%"=="SYSTEM_CHECK" goto SYSTEM_CHECK
if "%LAST_ACTION%"=="ATTACK_SSH" goto ATTACK_SSH
if "%LAST_ACTION%"=="ATTACK_FTP" goto ATTACK_FTP
if "%LAST_ACTION%"=="ATTACK_RDP" goto ATTACK_RDP
if "%LAST_ACTION%"=="ATTACK_TELNET" goto ATTACK_TELNET
if "%LAST_ACTION%"=="ATTACK_VNC" goto ATTACK_VNC
if "%LAST_ACTION%"=="DDOS_SSH" goto DDOS_SSH
if "%LAST_ACTION%"=="DDOS_RDP" goto DDOS_RDP
if "%LAST_ACTION%"=="SCAN" goto SCAN
goto MAIN_MENU

:EXIT
echo.
echo Press any key to close this window...
pause >nul
endlocal
exit /b 0
