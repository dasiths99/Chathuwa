@echo off
setlocal EnableExtensions
title CyberTraffic AI — mitmproxy Traffic Interceptor

echo ========================================
echo  CyberTraffic AI — Live Traffic Capture
echo  mitmproxy interceptor on port 8080
echo ========================================
echo.

cd /d "%~dp0"

:: Set Windows system proxy
echo [1/3] Setting Windows system proxy to 127.0.0.1:8080 ...
powershell -NoProfile -Command "$r='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Set-ItemProperty $r ProxyEnable 1; Set-ItemProperty $r ProxyServer '127.0.0.1:8080'; Set-ItemProperty $r ProxyOverride 'localhost;127.0.0.1;<local>'; Write-Host '  Proxy set OK'"
echo.

echo [2/3] Starting traffic interceptor...
echo.
echo ========================================
echo  BROWSER SETUP (one-time):
echo ========================================
echo  1. Open Brave and visit: http://mitm.it
echo  2. Click the Windows icon and install the CA certificate
echo  3. In the dashboard: Live Traffic Monitor
echo     - Switch dropdown to "Live (Proxy)"
echo     - Click "Proxy is running - Start Monitoring"
echo ========================================
echo.
echo Press CTRL+C to stop and restore proxy settings.
echo.

:: Use mitmdump from Python Scripts folder (added to PATH or full path)
set MITMDUMP=mitmdump
where mitmdump >nul 2>&1
if %errorlevel% neq 0 (
    set MITMDUMP=C:\Users\Yasas Lakmina\AppData\Local\Programs\Python\Python314\Scripts\mitmdump.exe
)

echo Using mitmdump: %MITMDUMP%
"%MITMDUMP%" --listen-port 8080 -s proxy\traffic_interceptor.py --flow-detail 1

:: Restore proxy on exit
echo.
echo [3/3] Restoring system proxy (disabling)...
powershell -NoProfile -Command "$r='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Set-ItemProperty $r ProxyEnable 0; Write-Host '  System proxy disabled'"
echo Done.
pause
