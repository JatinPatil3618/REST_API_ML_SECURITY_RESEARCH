# Script to stop all running research processes

Write-Host "==========================================================" -ForegroundColor Yellow
Write-Host " Stopping All REST API ML Security Research Processes     " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Yellow

$procNames = @("node", "mongod")
foreach ($p in $procNames) {
    Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

# Stop Java gateway specifically if running security-gateway
Get-WmiObject Win32_Process -Filter "name = 'java.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "security-gateway" } | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

# Stop python uvicorn
Get-WmiObject Win32_Process -Filter "name = 'python.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "uvicorn" } | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "[+] All research services terminated." -ForegroundColor Green
