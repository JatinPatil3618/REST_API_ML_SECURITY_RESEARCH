# Controlled Traffic Stimulation & ZAP Experiment Runner
param(
    [string]$Target = "http://127.0.0.1:8080"
)

$baseDir = Split-Path -Parent $PSScriptRoot
$pyExe = "C:\Users\Admin\anaconda3\python.exe"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Executing Controlled Experiment Manifest via Gateway     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

& $pyExe "$baseDir\scripts\run_zap_experiment.py"
