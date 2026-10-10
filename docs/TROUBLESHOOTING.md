# System Troubleshooting & Diagnostic Guide

## 1. Port Conflicts
If a service fails to bind:
- **Port 8080 (Gateway)**: Check if another proxy is running:
  ```powershell
  Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue
  ```
- **Port 8000 (ML Service)**: Check python uvicorn instances:
  ```powershell
  Get-Process python -ErrorAction SilentlyContinue
  ```
- **Port 5001 (Demo API)**: Check node instances:
  ```powershell
  Get-Process node -ErrorAction SilentlyContinue
  ```
- **Port 27017 (MongoDB)**: Check mongod daemon:
  ```powershell
  Get-Process mongod -ErrorAction SilentlyContinue
  ```

---

## 2. Java Runtime Version
Spring Boot 3.2.4 requires Java 17 or Java 21:
- Ensure `JAVA_HOME` points to `C:\Users\Admin\jdk-21\jdk-21.0.12.1+1`.
- Verify using:
  ```powershell
  & "C:\Users\Admin\jdk-21\jdk-21.0.12.1+1\bin\java.exe" -version
  ```

---

## 3. ML Service Connection Refusal
If the Security Gateway returns `{"error": "Security verification temporarily unavailable"}`:
- Ensure the FastAPI server is running on port 8000:
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:8000/health"
  ```
- Check that the model files exist in `models/atrdf/` and `models/bola/`. If missing, re-run `.\scripts\train-all.ps1`.

---

## 4. Resetting Entire Environment
To gracefully terminate and restart all services:
```powershell
.\scripts\stop-all.ps1
.\scripts\start-all.ps1
```
