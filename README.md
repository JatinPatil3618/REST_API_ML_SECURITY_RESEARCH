# Machine-Learning-Based Detection and Generalization of REST API Security Attacks Across Access-Control and Input-Manipulation Threats

**M.Tech Cybersecurity Final Year Research Project**

## 1. Project Overview
This research system investigates the detection and generalization of heterogeneous REST API security attacks by strictly separating the detection pathways for two fundamentally different vulnerability mechanisms:
1. **Access-Control / Business-Logic Abuse (BOLA - Broken Object Level Authorization)**: Handled via stateful rolling behavioral/session features ($W=10$) coupled with strict server-side authorization enforcement. Direct identity shortcuts are excluded from training to prevent memorization.
2. **Input / Payload Manipulation Attacks (ATRDF Dataset 4)**: Covers 7 distinct attack families (XSS, SQL Injection, Cookie Injection, Log Forging, RCE, Directory Traversal, Log4j) alongside Benign traffic. The live pre-response gateway employs a 13 request-only feature set, reserving 25-feature (full) and 18-feature (correlation-reduced) feature sets containing response attributes for offline ablation.

## 2. End-to-End Pipeline
```
[User Browser]           [OWASP ZAP Controller]
       \                         /
        v                       v
      [Spring Boot Security Gateway (Port 8080)]
        |-- Request ID & Timing
        |-- Mode Router (BOLA session vs. ATRDF payload)
        |-- Feature Extractor (13 request-only features / BOLA window)
        |-- Live ML Inference Service (FastAPI - Port 8000)
        |-- Decision Engine (ALLOW / BLOCK / ALERT)
        |-- Telemetry Logger (MongoDB)
        v
      [Demo REST API: Node.js/Express (Port 5001)]
        |-- Parameterized queries, virtual sandbox, JWT auth
        v
      [MongoDB Security Telemetry (Port 27017)]
        ^
        |
      [API Security Research Dashboard (Port 5174)]
```

## 3. Core Components
- **Demo Website (`frontend/`)**: *SecureBook API Lab* (React + Vite, Port 5173). Realistic book management application with login, book catalog, comments, search, and Security Lab.
- **Security Gateway (`gateway/`)**: Spring Boot 3.x / Java 21 (Port 8080). Intercepts all traffic, extracts features, performs live ML scoring, enforces mitigations, and forwards safe traffic to Demo API.
- **ML Inference Service (`ml_service/`)**: FastAPI / Python (Port 8000). Houses frozen Random Forest models for ATRDF (Binary & Multiclass) and BOLA, returning prediction probabilities, confidence, and top feature signals.
- **Demo API (`demo_api/`)**: Node.js / Express (Port 5001). Backend providing actual business logic, database operations, and object authorization validation.
- **Research Dashboard (`dashboard/`)**: React + Vite (Port 5174). Real-time telemetry monitoring, attack timeline, confusion matrices, ablation studies, and generalization analysis.
- **Traffic Stimulation (`zap/`)**: OWASP ZAP automated manifests and test cases for controlled empirical reproducibility.

## 4. System Deployment & Quick Start

All services are orchestrated and pre-configured. To start the complete system:

```powershell
# 1. Start all research services
.\scripts\start-all.ps1

# 2. Run end-to-end verification suite
python .\scripts\full_system_test.py

# 3. Stop all background processes
.\scripts\stop-all.ps1
```

### Active Service Endpoints
- **SecureBook Web Application**: [http://localhost:5173](http://localhost:5173)
- **API Security Research Dashboard**: [http://localhost:5174](http://localhost:5174)
- **Spring Boot Security Gateway**: [http://localhost:8080](http://localhost:8080)
- **FastAPI ML Inference Service**: [http://localhost:8000](http://localhost:8000)
- **Demo REST API**: [http://localhost:5001](http://localhost:5001)
- **MongoDB Telemetry Store**: `localhost:27017`

## 5. Experimental Results Summary

- **ATRDF Binary Detection (Payload Manipulation)**: Random Forest achieved **98.69% accuracy**, **100.0% precision**, and **0.9686 F1-score** on held-out test data.
- **ATRDF Multiclass Identification**: Achieved **1.0000 F1-score** across all 7 attack families (XSS, SQL Injection, Cookie Injection, Log Forging, RCE, Directory Traversal, Log4j).
- **BOLA Session Anomaly Detection**: Random Forest with rolling behavioral window ($W=10$) achieved **100.0% F1-score** with zero false alarms under session-disjoint evaluation.
- **Pre-Response Inference Latency**: Gateway feature extraction and scoring executes in **~2.2 microseconds** per request, ensuring zero perceptible user latency.

