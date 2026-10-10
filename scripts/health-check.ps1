# System Environment & Runtime Health Verification
# Verifies Python, Node.js, Java 21, Maven, MongoDB, and benchmark datasets

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " REST API ML Security Research - Environment Health Check " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$allPass = $true

# 1. Python Environment
$pyExe = "C:\Users\Admin\anaconda3\python.exe"
if (-not (Test-Path $pyExe)) {
    $pyCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pyCmd) { $pyExe = $pyCmd.Source }
}

if ($pyExe -and (Test-Path $pyExe)) {
    $pyVer = & $pyExe --version 2>&1
    Write-Host "[PASS] Python: $pyVer ($pyExe)" -ForegroundColor Green
    
    # Check Python Packages
    $pkgCheck = & $pyExe -c "
import sys
pkgs = ['pandas', 'numpy', 'sklearn', 'joblib', 'fastapi', 'uvicorn', 'pymongo', 'matplotlib', 'seaborn']
missing = []
for p in pkgs:
    try:
        __import__(p)
    except ImportError:
        missing.append(p)
if missing:
    print('MISSING:' + ','.join(missing))
else:
    print('ALL_OK')
" 2>&1
    if ($pkgCheck -match "ALL_OK") {
        Write-Host "[PASS] Python ML Packages: pandas, numpy, scikit-learn, joblib, fastapi, uvicorn, pymongo, matplotlib, seaborn" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Python ML Packages: $pkgCheck" -ForegroundColor Yellow
    }
} else {
    Write-Host "[FAIL] Python: Not found" -ForegroundColor Red
    $allPass = $false
}

# 2. Java Runtime & Version
$javaCmd = Get-Command java -ErrorAction SilentlyContinue
if ($javaCmd) {
    $javaVer = & java -version 2>&1 | Select-Object -First 1
    Write-Host "[PASS] Java detected: $javaVer" -ForegroundColor Green
    if ($javaVer -match "21\.") {
        Write-Host "[PASS] Java 21 is active" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Java version is not 21 (Spring Boot 3.x recommends Java 21). Microsoft.OpenJDK.21 is available via winget." -ForegroundColor Yellow
    }
} else {
    Write-Host "[FAIL] Java: Not found" -ForegroundColor Red
    $allPass = $false
}

# 3. Maven
$mvnCmd = Get-Command mvn -ErrorAction SilentlyContinue
if ($mvnCmd) {
    $mvnVer = & mvn -version 2>&1 | Select-Object -First 1
    Write-Host "[PASS] Maven: $mvnVer" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Maven: Not found" -ForegroundColor Red
    $allPass = $false
}

# 4. Node.js & npm
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
$npmCmd = Get-Command npm -ErrorAction SilentlyContinue
if ($nodeCmd -and $npmCmd) {
    $nodeVer = & node --version 2>&1
    $npmVer = & npm --version 2>&1
    Write-Host "[PASS] Node.js: $nodeVer | npm: $npmVer" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Node.js or npm: Not found" -ForegroundColor Red
    $allPass = $false
}

# 5. Git
$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd) {
    $gitVer = & git --version 2>&1
    Write-Host "[PASS] Git: $gitVer" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Git: Not found" -ForegroundColor Red
    $allPass = $false
}

# 6. MongoDB
$mongoCmd = Get-Command mongod -ErrorAction SilentlyContinue
$mongoSvc = Get-Service -Name "*mongo*" -ErrorAction SilentlyContinue
if ($mongoCmd -or $mongoSvc) {
    Write-Host "[PASS] MongoDB: Service/Executable found" -ForegroundColor Green
} else {
    Write-Host "[WARN] MongoDB: Local service not running. Can be started or installed via winget (MongoDB.Server) or lightweight runner." -ForegroundColor Yellow
}

# 7. OWASP ZAP
$zapBat = Get-Command zap.bat -ErrorAction SilentlyContinue
if ($zapBat) {
    Write-Host "[PASS] OWASP ZAP: Available in PATH" -ForegroundColor Green
} else {
    Write-Host "[WARN] OWASP ZAP: Not found in current PATH. Available via winget (ZAP.ZAP)." -ForegroundColor Yellow
}

# 8. Datasets Verification
$baseDir = Split-Path -Parent $PSScriptRoot
$atrdfTrain = Join-Path $baseDir "data\raw\atrdf\REQUEST_ONLY_train.csv"
$atrdfTest = Join-Path $baseDir "data\raw\atrdf\REQUEST_ONLY_test.csv"
$vampiDataset = Join-Path $baseDir "data\raw\vampi\vampi_v6_2_50000_ML_READY.csv"

if ((Test-Path $atrdfTrain) -and (Test-Path $atrdfTest)) {
    Write-Host "[PASS] ATRDF Dataset: Verified present in data/raw/atrdf" -ForegroundColor Green
} else {
    Write-Host "[FAIL] ATRDF Dataset: Missing required csv files in data/raw/atrdf" -ForegroundColor Red
    $allPass = $false
}

if (Test-Path $vampiDataset) {
    Write-Host "[PASS] VAmPI BOLA Dataset: Verified present in data/raw/vampi" -ForegroundColor Green
} else {
    Write-Host "[FAIL] VAmPI BOLA Dataset: Missing vampi_v6_2_50000_ML_READY.csv in data/raw/vampi" -ForegroundColor Red
    $allPass = $false
}

Write-Host "----------------------------------------------------------"
if ($allPass) {
    Write-Host "[STATUS] Environment and benchmark dataset checks passed." -ForegroundColor Cyan
} else {
    Write-Host "[STATUS] Environment checks completed with warnings." -ForegroundColor Yellow
}
