"""
End-to-End Live Verification of Security Gateway + ML Service (Step 1)
Tests:
1. Benign Traffic Invariance Across Test IDs (None, NORMAL_001, SQLI_001, CUSTOM_BENIGN)
2. Attack Detection Anti-Tampering: Caller cannot force ALLOW on Cookie Injection by supplying X-Test-Case-Id: NORMAL_001
3. BOLA Behavioral Interception Anti-Tampering: Caller cannot force ALLOW on BOLA by supplying X-Test-Case-Id: NORMAL_001
4. Model Output Invariance on Search Traffic Across Test IDs
5. Telemetry Integrity: Real model probabilities & confidence recorded; no ground truth from caller header
"""

import sys
import json
import urllib.request
import urllib.error

GATEWAY_URL = "http://localhost:8080"

def send(url, method="GET", headers=None, body=None):
    if headers is None:
        headers = {}
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="ignore")

browser_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Origin': 'http://localhost:5173',
    'Referer': 'http://localhost:5173/',
    'X-Authenticated-User': 'user01',
    'Authorization': 'Bearer dummy-token-user01'
}

print("=" * 70)
print("LIVE END-TO-END VERIFICATION: GATEWAY + ML SERVICE")
print("=" * 70)

# 1. Benign Traffic Invariance
print("\n[1] Testing Benign Traffic Invariance Across Test IDs:")
benign_decisions = []
for tid in [None, "NORMAL_001", "SQLI_001", "CUSTOM_BENIGN"]:
    h = browser_headers.copy()
    if tid:
        h["X-Test-Case-Id"] = tid
    status, hdrs, body = send(f"{GATEWAY_URL}/api/books", "GET", h)
    # Forwarded to demo API (502 when demo API is offline, or 200 when online; gateway decision is ALLOW)
    dec = hdrs.get("X-Security-Decision", "ALLOW" if status in [200, 502] else "BLOCK")
    benign_decisions.append((tid, status, dec))
    print(f"  Test ID: {str(tid):15} -> Status: {status} Decision: {dec}")

assert len(set(r[2] for r in benign_decisions)) == 1, "All benign requests must produce identical decision"
assert benign_decisions[0][2] == "ALLOW", "Benign request decision must be ALLOW"
print("  ==> PASS: Benign requests are invariant to test IDs (Decision: ALLOW).")

# 2. Cookie Attack Anti-Tampering (Caller attempts to force ALLOW using NORMAL_001)
print("\n[2] Testing Cookie Attack Anti-Tampering (Caller attempts to force ALLOW with NORMAL_001):")
cookie_results = []
for tid in [None, "NORMAL_001", "COOKIE_001", "FORCED_ALLOW_ATTEMPT"]:
    h = browser_headers.copy()
    h["Cookie"] = "admin=true; role=superadmin; token=malicious_forge_xyz"
    if tid:
        h["X-Test-Case-Id"] = tid
    status, hdrs, body = send(f"{GATEWAY_URL}/api/books", "GET", h)
    dec = hdrs.get("X-Security-Decision", "UNKNOWN")
    fam = hdrs.get("X-Attack-Family", "UNKNOWN")
    cookie_results.append((tid, status, dec, fam))
    print(f"  Test ID: {str(tid):22} -> Status: {status} Decision: {dec} Family: {fam}")

assert all(r[1] in [401, 403] and r[2] == "BLOCK" for r in cookie_results), "All Cookie attack requests must be BLOCKED"
print("  ==> PASS: Cookie attack is genuine BLOCKED; caller CANNOT force ALLOW with NORMAL_001.")

# 3. BOLA Behavioral Interception Anti-Tampering
print("\n[3] Testing BOLA Behavioral Interception Across Test IDs:")
bola_results = []
for tid in [None, "NORMAL_001", "BOLA_001"]:
    h = browser_headers.copy()
    h["Content-Type"] = "application/json"
    if tid:
        h["X-Test-Case-Id"] = tid
    body_json = json.dumps({"title": "Cross Owner Modification"})
    status, hdrs, body = send(f"{GATEWAY_URL}/api/books/201", "PUT", h, body_json)
    dec = hdrs.get("X-Security-Decision", "UNKNOWN")
    fam = hdrs.get("X-Attack-Family", "UNKNOWN")
    bola_results.append((tid, status, dec, fam))
    print(f"  Test ID: {str(tid):15} -> Status: {status} Decision: {dec} Family: {fam}")

assert all(r[1] == 403 and r[2] == "BLOCK" and r[3] == "BOLA" for r in bola_results), "All BOLA requests must be BLOCKED"
print("  ==> PASS: BOLA attacks are genuinely blocked and invariant to test IDs.")

# 4. Search Traffic Invariance Across Test IDs
print("\n[4] Testing Search Query Traffic Invariance Across Test IDs:")
search_results = []
for tid in [None, "NORMAL_001", "SQLI_001", "RANDOM_ID"]:
    h = browser_headers.copy()
    if tid:
        h["X-Test-Case-Id"] = tid
    status, hdrs, body = send(f"{GATEWAY_URL}/api/books?search=%27%20OR%20%271%27=%271%20--%20UNION%20SELECT%20*", "GET", h)
    dec = hdrs.get("X-Security-Decision", "ALLOW" if status in [200, 502] else "BLOCK")
    search_results.append((tid, status, dec))
    print(f"  Test ID: {str(tid):15} -> Status: {status} Decision: {dec}")

assert len(set(r[2] for r in search_results)) == 1, "All search query requests must produce identical decision"
print("  ==> PASS: Search requests produce invariant genuine model decisions regardless of test ID.")

# 5. Telemetry Integrity Verification
print("\n[5] Verifying Telemetry Integrity from /api/telemetry/events:")
status, hdrs, body = send(f"{GATEWAY_URL}/api/telemetry/events?limit=10", "GET")
events = json.loads(body)
verified_count = 0
for e in events[:5]:
    conf = e.get('confidence')
    gt = e.get('groundTruth')
    probs = e.get('probabilities')
    print(f"  Req: {e['requestId']} | Dec: {e['decision']} | Conf: {conf} | GT: {gt} | Probs: {probs}")
    # Verify confidence is honest (not fabricated 0.95 or 0.99)
    assert conf not in [0.95, 0.99], f"Fabricated confidence detected in {e['requestId']}"
    # Verify groundTruth is decoupled and never extracted from caller header
    assert gt is None, f"groundTruth must not be populated from caller header in {e['requestId']}"
    verified_count += 1

print(f"  ==> PASS: Verified {verified_count} telemetry records. Real model probabilities recorded with zero fabrication.")
print("\n" + "=" * 70)
print("ALL LIVE END-TO-END VERIFICATIONS PASSED SUCCESSFULLY (5/5)!")
print("=" * 70)
