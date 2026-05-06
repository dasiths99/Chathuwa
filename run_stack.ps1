# CyberWatch — run from PowerShell (fixes "cd /d" / System32 issues)
# Usage (normal):    .\run_stack.ps1
# Usage (elevated):  Right-click PowerShell → Run as administrator, then:
#                     Set-Location 'C:\Users\Dassa\Documents\Research'
#                     .\run_stack.ps1

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

Set-Location -LiteralPath $PSScriptRoot

if (-not (Test-Path -LiteralPath '.\app.py')) {
    Write-Error "app.py not found next to this script. Path: $PSScriptRoot"
    exit 1
}

Write-Host "Project directory: $PWD" -ForegroundColor Cyan
& python app.py
