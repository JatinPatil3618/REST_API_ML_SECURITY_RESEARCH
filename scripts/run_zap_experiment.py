"""
Controlled Traffic Stimulation & ZAP Experiment Runner
Executes YAML test manifest against Spring Boot Gateway on port 8080
Records empirical metrics to CSV tables
"""

import sys
import os
import time
import requests
import yaml
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(BASE_DIR, "zap", "manifests", "live_experiment.yaml")
TARGET_BASE = "http://127.0.0.1:8080"
TABLES_DIR = os.path.join(BASE_DIR, "results", "tables")

os.makedirs(TABLES_DIR, exist_ok=True)

with open(MANIFEST_PATH, "r") as f:
    manifest = yaml.safe_load(f)

test_cases = manifest.get("test_cases", [])
print(f"[*] Loaded {len(test_cases)} controlled test cases from {MANIFEST_PATH}")
print("="*80)
print(f"{'Case ID':<15} {'Category':<18} {'Method':<8} {'Status':<8} {'Decision':<10} {'Pass/Fail'}")
print("="*80)

results = []
passed_count = 0

for tc in test_cases:
    cid = tc["test_case_id"]
    cat = tc["category"]
    method = tc["method"]
    endpoint = tc["endpoint"]
    user = tc.get("user", "user01")
    exp_mit = tc.get("expected_safe_mitigation", "BLOCK")

    headers = {
        "X-Authenticated-User": user,
        "X-Test-Case-Id": cid,
        "X-Experiment-Id": "EXP-2026-LIVE",
        "Accept": "application/json"
    }
    headers.update(tc.get("headers", {}))

    url = f"{TARGET_BASE}{endpoint}"
    t0 = time.time()
    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=5)
        elif method == "POST":
            resp = requests.post(url, headers=headers, json=tc.get("safe_test_data", {}), timeout=5)
        elif method == "PUT":
            resp = requests.put(url, headers=headers, json=tc.get("safe_test_data", {}), timeout=5)
        elif method == "DELETE":
            resp = requests.delete(url, headers=headers, timeout=5)
        else:
            resp = requests.get(url, headers=headers, timeout=5)

        duration_ms = round((time.time() - t0) * 1000, 2)
        dec = resp.headers.get("X-Security-Decision", "BLOCK" if resp.status_code == 403 else "ALLOW")

        if cat == "BENIGN":
            is_pass = (resp.status_code == 200 and dec == "ALLOW")
        else:
            is_pass = (resp.status_code in [400, 401, 403] or dec == "BLOCK")

        if is_pass:
            passed_count += 1

        pass_txt = "PASS" if is_pass else "FAIL"
        print(f"{cid:<15} {cat:<18} {method:<8} {resp.status_code:<8} {dec:<10} {pass_txt}")

        results.append({
            "Test Case": cid,
            "Category": cat,
            "HTTP Method": method,
            "Expected": exp_mit,
            "Predicted": dec,
            "HTTP Status": resp.status_code,
            "Latency (ms)": duration_ms,
            "PASS/FAIL": pass_txt
        })
    except Exception as e:
        print(f"{cid:<15} {cat:<18} {method:<8} ERR      ERROR      FAIL ({e})")

print("="*80)
print(f"[+] Controlled Experiment Complete: {passed_count}/{len(test_cases)} Passed ({round(passed_count/len(test_cases)*100, 1)}%)")

df_results = pd.DataFrame(results)
out_csv = os.path.join(TABLES_DIR, "TABLE_9_live_zap.csv")
df_results.to_csv(out_csv, index=False)
df_results.to_csv(os.path.join(TABLES_DIR, "live_zap_results.csv"), index=False)
print(f"[+] Output recorded to {out_csv}")
