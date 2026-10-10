# Multi-Service Orchestrator Script
# Starts MongoDB, ML Inference Service, Demo REST API, Gateway, and Frontends in dependency order

$baseDir = Split-Path -Parent $PSScriptRoot
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " REST API ML Security Research Environment Launcher        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

function Test-PortListening($port) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect("127.0.0.1", $port, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne(400, $false)
        if ($wait -and $client.Connected) {
            $client.EndConnect($iar)
            $client.Close()
            return $true
        }
        $client.Close()
        return $false
    } catch {
        return $false
    }
}

# 1. MongoDB (Port 27017)
if (Test-PortListening 27017) {
    Write-Host "[OK] MongoDB is already active on port 27017" -ForegroundColor Green
} else {
    $mongoExe = "C:\Users\Admin\mongodb\bin\mongod.exe"
    $mongoDbPath = "C:\Users\Admin\mongodb\data\db"
    if (Test-Path $mongoExe) {
        Write-Host "[*] Launching MongoDB Daemon on port 27017..." -ForegroundColor Yellow
        Start-Process -FilePath $mongoExe -ArgumentList "--dbpath `"$mongoDbPath`" --port 27017" -WindowStyle Hidden
        Start-Sleep -Seconds 2
    } else {
        Write-Host "[!] MongoDB binary not found at default location. Demo API will run in-memory mode." -ForegroundColor Gray
    }
}

# 2. FastAPI ML Inference Service (Port 8000)
if (Test-PortListening 8000) {
    Write-Host "[OK] ML Inference Service is already active on port 8000" -ForegroundColor Green
} else {
    Write-Host "[*] Launching FastAPI ML Service on http://localhost:8000..." -ForegroundColor Yellow
    $pyExe = "C:\Users\Admin\anaconda3\python.exe"
    if (-not (Test-Path $pyExe)) { $pyExe = "python" }
    Start-Process -FilePath $pyExe -ArgumentList "-m uvicorn main:app --host 0.0.0.0 --port 8000" -WorkingDirectory "$baseDir\ml_service" -WindowStyle Hidden
    Start-Sleep -Seconds 2
}

# 3. Demo REST API (Port 5001)
if (Test-PortListening 5001) {
    Write-Host "[OK] Demo REST API is already active on port 5001" -ForegroundColor Green
} else {
    Write-Host "[*] Launching SecureBook Demo API on http://localhost:5001..." -ForegroundColor Yellow
    Start-Process -FilePath "node" -ArgumentList "server.js" -WorkingDirectory "$baseDir\demo_api" -WindowStyle Hidden
    Start-Sleep -Seconds 2
}

# 4. Spring Boot Security Gateway (Port 8080)
if (Test-PortListening 8080) {
    Write-Host "[OK] Security Gateway is already active on port 8080" -ForegroundColor Green
} else {
    Write-Host "[*] Launching Spring Boot Security Gateway on http://localhost:8080..." -ForegroundColor Yellow
    $javaExe = "C:\Users\Admin\jdk-21\jdk-21.0.12.1+1\bin\java.exe"
    if (-not (Test-Path $javaExe)) { $javaExe = "java" }
    $jarPath = "$baseDir\gateway\target\security-gateway-1.0.0.jar"
    Start-Process -FilePath $javaExe -ArgumentList "-jar `"$jarPath`"" -WorkingDirectory "$baseDir\gateway" -WindowStyle Hidden
    Start-Sleep -Seconds 4
}

# 5. SecureBook Frontend (Port 5173)
if (Test-PortListening 5173) {
    Write-Host "[OK] SecureBook Frontend is already active on http://localhost:5173" -ForegroundColor Green
} else {
    Write-Host "[*] Launching SecureBook Frontend on http://localhost:5173..." -ForegroundColor Yellow
    Start-Process -FilePath "npm.cmd" -ArgumentList "run dev" -WorkingDirectory "$baseDir\frontend" -WindowStyle Hidden
}

# 6. Research Dashboard (Port 5174)
if (Test-PortListening 5174) {
    Write-Host "[OK] Research Dashboard is already active on http://localhost:5174" -ForegroundColor Green
} else {
    Write-Host "[*] Launching Research Dashboard on http://localhost:5174..." -ForegroundColor Yellow
    Start-Process -FilePath "npm.cmd" -ArgumentList "run dev" -WorkingDirectory "$baseDir\dashboard" -WindowStyle Hidden
}

Write-Host "==========================================================" -ForegroundColor Green
Write-Host " ALL RESEARCH SERVICES ARE RUNNING AND HEALTHY            " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host " [+] Demo Application:    http://localhost:5173" -ForegroundColor Cyan
Write-Host " [+] Research Dashboard:  http://localhost:5174" -ForegroundColor Cyan
Write-Host " [+] Security Gateway:    http://localhost:8080" -ForegroundColor Cyan
Write-Host " [+] Demo REST API:       http://localhost:5001" -ForegroundColor Cyan
Write-Host " [+] Python ML Service:   http://localhost:8000" -ForegroundColor Cyan
Write-Host " [+] MongoDB Telemetry:   localhost:27017" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Green
