# CyberWatch — same idea as run_as_admin.bat: re-launch elevated, then start app.py
# Usage: Right-click → Run with PowerShell, or: powershell -ExecutionPolicy Bypass -File .\run_as_admin.ps1

Set-StrictMode -Version 1
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host 'Requesting Administrator privileges...' -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$($MyInvocation.MyCommand.Path)`""
    )
    exit 0
}

Set-Location -LiteralPath $scriptDir
if (-not (Test-Path -LiteralPath '.\app.py')) {
    Write-Error "app.py not found in: $scriptDir"
    exit 1
}

Write-Host 'Running as Administrator.' -ForegroundColor Green
Write-Host "Directory: $PWD"

python -m pip install -q Flask Flask-SocketIO Flask-CORS python-socketio scapy psutil eventlet python-dotenv numpy pynput 2>$null
if ($LASTEXITCODE -ne 0) {
    python -m pip install -q Flask Flask-SocketIO python-socketio scapy psutil
}

Write-Host ''
Write-Host 'Main dashboard : http://localhost:5000' -ForegroundColor Cyan
Write-Host 'Network monitor: http://localhost:5001' -ForegroundColor Cyan
python app.py
