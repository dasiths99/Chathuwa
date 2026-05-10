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

$pythonCommand = $null
foreach ($candidate in @(
    @{ Exe = 'py'; Args = @('-3.12') },
    @{ Exe = 'py'; Args = @('-3.11') },
    @{ Exe = 'py'; Args = @('-3') },
    @{ Exe = 'python'; Args = @() }
)) {
    if (-not (Get-Command $candidate.Exe -ErrorAction SilentlyContinue)) {
        continue
    }
    & $candidate.Exe @($candidate.Args) -c 'import sys' 2>$null
    if ($LASTEXITCODE -eq 0) {
        $pythonCommand = $candidate
        break
    }
}

if (-not $pythonCommand) {
    Write-Error 'No working Python was found. Install Python 3.11 or 3.12, then run this file again.'
    exit 1
}

$pythonVersion = & $pythonCommand.Exe @($pythonCommand.Args) -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$canInstallTensorFlow = & $pythonCommand.Exe @($pythonCommand.Args) -c "import sys; print(1 if sys.version_info < (3,13) else 0)"

Write-Host "Python command : $($pythonCommand.Exe) $($pythonCommand.Args -join ' ')"
Write-Host "Python version : $pythonVersion"
if ($canInstallTensorFlow -ne '1') {
    Write-Host "NOTE: TensorFlow is skipped on Python $pythonVersion." -ForegroundColor Yellow
    Write-Host '      TensorFlow currently has no compatible package for this Python version.'
    Write-Host '      The app will run with heuristic/fallback detection.'
}

& $pythonCommand.Exe @($pythonCommand.Args) -m pip install -q Flask Flask-SocketIO Flask-CORS python-socketio scapy psutil eventlet python-dotenv numpy pynput joblib scikit-learn 2>$null
if ($LASTEXITCODE -ne 0) {
    & $pythonCommand.Exe @($pythonCommand.Args) -m pip install -q Flask Flask-SocketIO python-socketio scapy psutil
}

if ($canInstallTensorFlow -eq '1') {
    Write-Host 'Installing optional TensorFlow support...'
    & $pythonCommand.Exe @($pythonCommand.Args) -m pip install -q tensorflow
} else {
    Write-Host 'Skipping optional TensorFlow install.'
}

Write-Host ''
Write-Host 'Main dashboard : http://localhost:5000' -ForegroundColor Cyan
Write-Host 'Network monitor: http://localhost:5001' -ForegroundColor Cyan
& $pythonCommand.Exe @($pythonCommand.Args) app.py
