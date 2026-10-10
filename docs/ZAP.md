# OWASP ZAP Traffic Stimulation & Experiment Integration

## 1. Overview
OWASP ZAP is utilized as a third-party, standardized traffic stimulation tool. Unrestricted blind crawling is deliberately avoided; instead, controlled manifests define known ground truth for every request before transmission.

## 2. Network Isolation Rule
ZAP communicates exclusively with the Security Gateway:
```
OWASP ZAP ---> http://127.0.0.1:8080 (Security Gateway) ---> Demo API (Port 5001)
```
ZAP is never permitted to bypass the gateway or target external hosts.

## 3. Manifest Definition
Controlled test cases are codified under `zap/manifests/live_experiment.yaml`. Each entry includes:
- `test_case_id`: e.g., `XSS_001`, `BOLA_001`
- `category`: Attack classification
- `method` & `endpoint`: Target route
- `headers`: Injected headers, cookies, or JWTs
- `safe_test_data`: Controlled, non-destructive demonstration payloads
- `expected_ground_truth`: Target class (known only to evaluator, never passed to ML model)
- `expected_safe_mitigation`: Expected security policy response

## 4. Execution
To run the automated experiment suite:
```powershell
.\scripts\run-zap-experiment.ps1 -Target "http://127.0.0.1:8080"
```
The script transmits every request through the gateway, measures real-time status and latencies, and writes the results to `results/tables/TABLE_9_live_zap.csv`.
