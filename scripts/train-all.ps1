# Script to train and evaluate all models and reproduce all research outputs

$baseDir = Split-Path -Parent $PSScriptRoot
$pyExe = "C:\Users\Admin\anaconda3\python.exe"
if (-not (Test-Path $pyExe)) { $pyExe = "python" }

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Training & Evaluating All Research Models                " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

& $pyExe "$baseDir\scripts\train_and_evaluate_all.py"
