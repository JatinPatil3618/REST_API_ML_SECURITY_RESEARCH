"""Temporary 14-feature ATRDF candidate with jndi_lookup_marker.

Does not open REQUEST_ONLY_test.csv and does not write models/atrdf or gateway config.
"""

import csv
import json
import os
import re
from urllib.parse import unquote

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support, precision_score, recall_score
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
ABLATION = os.path.join(ROOT, "research", "atrdf_header_count_ablation")
TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
RECORD_IDS = os.path.join(ABLATION, "log4j_fn_diagnostic", "train_record_ids.npy")
RAW_JSON = (
    r"C:\Users\jatin\OneDrive\Documents\Desktop\TAG\New Start"
    r"\ATRDF_Research\01_Raw_Data\dataset_4_train\dataset_4_train.json"
)
SUITE_PATH = os.path.join(ABLATION, "controlled_suite_features.json")
BASELINE_BINARY = os.path.join(ABLATION, "candidate_a_binary_rf.joblib")
BASELINE_MULTI = os.path.join(ABLATION, "candidate_a_multiclass_rf.joblib")
ACTIVE_BINARY = os.path.join(ROOT, "models", "atrdf", "atrdf_binary_rf_request_only.joblib")
ACTIVE_MULTI = os.path.join(ROOT, "models", "atrdf", "atrdf_multiclass_rf_request_only.joblib")

FEATURES = [
    "url_entropy", "header_count", "path_length", "url_special_count", "url_length",
    "path_segment_count", "cookie_present", "query_length", "url_digit_count",
    "user_agent_entropy", "query_parameter_count", "request_body_entropy",
    "request_body_digit_count",
]
MARKER = "jndi_lookup_marker"
FEATURES_14 = FEATURES + [MARKER]
ATTACK_CLASSES = [
    "Cookie Injection", "Directory Traversal", "LOG4J", "Log Forging",
    "RCE", "SQL Injection", "XSS",
]
ATTACK_TO_INDEX = {name: index for index, name in enumerate(ATTACK_CLASSES)}
CLASS_ORDER = ["Benign"] + ATTACK_CLASSES
THRESHOLD = 0.50
INNER_SEED = 42
VAL_FRACTION = 0.1
PATTERN = re.compile(r"\$\{\s*jndi\s*:", re.IGNORECASE)
EXPECTED_BASELINE = {"tn": 11475, "fp": 0, "fn": 204, "tp": 2943}
SUITE_HEADER_VALUES = {
    "H2": [("Host", "127.0.0.1:8080"), ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")],
    "H3": [("Host", "127.0.0.1:8080"), ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), ("Accept", "application/json")],
    "H4": [("Host", "127.0.0.1:8080"), ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), ("Accept", "application/json"), ("Accept-Language", "en-US,en;q=0.9")],
    "H5": [("Host", "127.0.0.1:8080"), ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), ("Accept", "application/json"), ("Accept-Language", "en-US,en;q=0.9"), ("Accept-Encoding", "gzip, deflate")],
    "H6": [("Host", "127.0.0.1:8080"), ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), ("Accept", "application/json"), ("Accept-Language", "en-US,en;q=0.9"), ("Accept-Encoding", "gzip, deflate"), ("Connection", "keep-alive")],
}


def require_sklearn():
    if sklearn.__version__ != "1.2.2":
        raise SystemExit(f"Expected scikit-learn 1.2.2, found {sklearn.__version__}")


def value_texts(value):
    if isinstance(value, list):
        return ["" if item is None else str(item) for item in value]
    return ["" if value is None else str(value)]


def marker_from_headers(headers):
    """Boolean marker from header values only. Labels are not an input."""
    if not isinstance(headers, dict):
        return 0, False
    decoded_only = False
    for value in headers.values():
        for text in value_texts(value):
            if PATTERN.search(text):
                return 1, decoded_only
            decoded = unquote(text)
            if decoded != text and PATTERN.search(decoded):
                decoded_only = True
                return 1, True
    return 0, False


def load_train():
    with open(TRAIN_CSV, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames[:13] != FEATURES:
            raise SystemExit("Training CSV feature order does not match the 13-feature contract.")
        matrix, labels, binary = [], [], []
        for row in reader:
            matrix.append([float(row[name]) for name in FEATURES])
            labels.append(row["label"])
            binary.append(int(row["is_malicious"]))
    return np.asarray(matrix, dtype=np.float64), np.asarray(labels), np.asarray(binary, dtype=np.int64)


def load_marker_column(record_ids):
    needed = {int(record_id) for record_id in record_ids}
    found = {}
    decoded_only_rows = 0
    with open(RAW_JSON, encoding="utf-8") as handle:
        records = json.load(handle)
    for record_id, record in enumerate(records, start=1):
        if record_id not in needed:
            continue
        headers = (record.get("request") or {}).get("headers") or {}
        marker, decoded_only = marker_from_headers(headers)
        found[record_id] = marker
        if decoded_only:
            decoded_only_rows += 1
    del records
    missing = needed.difference(found)
    if missing:
        raise SystemExit(f"{len(missing)} training record ids were absent from the raw JSON")
    column = np.asarray([found[int(record_id)] for record_id in record_ids], dtype=np.float64)
    return column, decoded_only_rows


def copied_params(path):
    params = joblib.load(path).get_params()
    return {
        "n_estimators": params["n_estimators"],
        "max_depth": params["max_depth"],
        "min_samples_split": params["min_samples_split"],
        "min_samples_leaf": params["min_samples_leaf"],
        "class_weight": params["class_weight"],
        "max_features": params["max_features"],
        "random_state": INNER_SEED,
        "n_jobs": -1,
    }


def malicious_probability(model, rows):
    if list(model.classes_) != [0, 1]:
        raise SystemExit(f"Binary classes_ must be [0, 1], got {list(model.classes_)}")
    return model.predict_proba(rows)[:, 1]


def binary_metrics(y_true, proba):
    pred = (proba >= THRESHOLD).astype(np.int64)
    matrix = confusion_matrix(y_true, pred, labels=[0, 1])
    tn, fp, fn, tp = (int(matrix[0, 0]), int(matrix[0, 1]), int(matrix[1, 0]), int(matrix[1, 1]))
    return {
        "threshold": THRESHOLD,
        "precision": float(precision_score(y_true, pred, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_true, pred, pos_label=1, zero_division=0)),
        "f1": float(f1_score(y_true, pred, pos_label=1, zero_division=0)),
        "false_positive_rate": float(fp / (tn + fp)) if (tn + fp) else None,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "benign_blocked": fp,
    }


def attack_family(multi_model, rows):
    if list(multi_model.classes_) != list(range(7)):
        raise SystemExit(f"Multiclass classes_ must be 0-6, got {list(multi_model.classes_)}")
    indices = np.argmax(multi_model.predict_proba(rows), axis=1)
    return np.asarray([ATTACK_CLASSES[int(index)] for index in indices])


def pipeline_report(y_true, binary_model, multi_model, rows):
    proba = malicious_probability(binary_model, rows)
    binary_positive = proba >= THRESHOLD
    combined = np.where(binary_positive, attack_family(multi_model, rows), "Benign")
    matrix = confusion_matrix(y_true, combined, labels=CLASS_ORDER)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, combined, labels=CLASS_ORDER, zero_division=0
    )
    per_class = []
    for index, label in enumerate(CLASS_ORDER):
        per_class.append({
            "label": label,
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
            "support": int(support[index]),
            "missed": int(np.sum((y_true == label) & (combined != label))),
        })
    log4j_binary_misses = int(np.sum((y_true == "LOG4J") & ~binary_positive))
    return {
        "binary": binary_metrics(np.asarray([0 if label == "Benign" else 1 for label in y_true]), proba),
        "per_class": per_class,
        "confusion_matrix": matrix.astype(int).tolist(),
        "log4j_missed_at_binary_stage": log4j_binary_misses,
        "binary_malicious_then_labeled_benign": int(np.sum((y_true != "Benign") & binary_positive & (combined == "Benign"))),
    }


def suite_marker(profile):
    if profile not in SUITE_HEADER_VALUES:
        raise SystemExit(f"Unknown controlled-suite header profile {profile}")
    return marker_from_headers(dict(SUITE_HEADER_VALUES[profile]))[0]


def score_suite(binary_model, multi_model, cases, width):
    rows = []
    blocked = 0
    for case in cases:
        features = case["features"]
        vector = [float(features[name]) for name in FEATURES]
        marker = suite_marker(case["header_profile"])
        if width == 14:
            vector.append(marker)
        proba = malicious_probability(binary_model, np.asarray([vector], dtype=np.float64))
        positive = bool(proba[0] >= THRESHOLD)
        family = "Benign"
        if positive:
            family = str(attack_family(multi_model, np.asarray([vector], dtype=np.float64))[0])
            blocked += 1
        rows.append({
            "case_id": case["case_id"],
            "route": case["route"],
            "header_profile": case["header_profile"],
            "jndi_lookup_marker": marker,
            "binary_p_malicious": float(proba[0]),
            "combined_label": family,
        })
    return {"cases": len(rows), "blocked": blocked, "results": rows}


def marker_rates(labels, column):
    rates = {}
    for label in ["Benign"] + ATTACK_CLASSES:
        mask = labels == label
        count = int(np.sum(mask))
        positive = int(np.sum(column[mask] == 1))
        rates[label] = {"rows": count, "marker_positive": positive}
    return rates


def fmt(value):
    return f"{value:.6f}" if isinstance(value, float) else str(value)


def write_report(result):
    base = result["baseline_13"]
    cand = result["candidate_14"]
    base_log = next(row for row in base["per_class"] if row["label"] == "LOG4J")
    cand_log = next(row for row in cand["per_class"] if row["label"] == "LOG4J")
    lines = [
        "# JNDI header-value feature experiment",
        "",
        "Temporary candidates only. `REQUEST_ONLY_test.csv` was not opened. Files in `models/atrdf/` and the gateway were not modified. Threshold fixed at 0.50.",
        "",
        "## Command",
        "",
        "```",
        r".venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\jndi_feature_experiment\run_jndi_feature_experiment.py",
        "```",
        "",
        f"scikit-learn {result['sklearn']}. Fit rows {result['fit_rows']}. Validation rows {result['validation_rows']}.",
        "",
        "## Feature",
        "",
        "`jndi_lookup_marker` is 1 when any request header value matches `\\$\\{\\s*jndi\\s*:` without regard to case. The pattern is also applied after percent-decoding. Attack labels are not read while the feature is extracted. The column is aligned with `train_record_ids.npy` (`record_id` is the 1-based JSON position).",
        "",
        f"Training rows with the marker: {result['marker_positive_train_rows']} of {result['train_rows']}. Rows whose match appeared only after percent-decoding: {result['decoded_only_matches']}.",
        "",
        "| Label | Rows | Marker 1 |",
        "|---|---:|---:|",
    ]
    for label, row in result["marker_by_label_train_csv"].items():
        lines.append(f"| {label} | {row['rows']} | {row['marker_positive']} |")
    lines.extend([
        "",
        "The 13-feature baseline is the existing Candidate A binary model and the existing attack-only seven-class Candidate A multiclass model, scored again on this validation split. The 14-feature candidate was fit on the same fit indices. Random Forest settings were copied from the active artifacts and not otherwise changed.",
        "",
        f"Copied binary parameters: `{json.dumps(result['binary_params'])}`.",
        f"Copied multiclass parameters: `{json.dumps(result['multiclass_params'])}`.",
        "",
        "## Validation binary metrics",
        "",
        "| Model | Precision | Recall | F1 | FPR | TN | FP | FN | TP |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for name, block in (("13-feature baseline", base), ("14-feature candidate", cand)):
        binary = block["binary"]
        matrix = binary["confusion_matrix"]
        lines.append(
            f"| {name} | {fmt(binary['precision'])} | {fmt(binary['recall'])} | {fmt(binary['f1'])} | "
            f"{fmt(binary['false_positive_rate'])} | {matrix['tn']} | {matrix['fp']} | {matrix['fn']} | {matrix['tp']} |"
        )
    lines.extend([
        "",
        "## Validation attack-family pipeline",
        "",
        "A row is Benign when the binary score is below 0.50. Otherwise the attack-only multiclass label is used.",
        "",
        "| Family | Baseline P | Baseline R | Baseline F1 | Baseline missed | Candidate P | Candidate R | Candidate F1 | Candidate missed |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    cand_by_label = {row["label"]: row for row in cand["per_class"]}
    for row in base["per_class"]:
        other = cand_by_label[row["label"]]
        lines.append(
            f"| {row['label']} | {fmt(row['precision'])} | {fmt(row['recall'])} | {fmt(row['f1'])} | {row['missed']} | "
            f"{fmt(other['precision'])} | {fmt(other['recall'])} | {fmt(other['f1'])} | {other['missed']} |"
        )
    lines.extend([
        "",
        f"LOG4J missed at the binary stage: baseline {base['log4j_missed_at_binary_stage']}, candidate {cand['log4j_missed_at_binary_stage']}.",
        f"LOG4J pipeline recall: baseline {fmt(base_log['recall'])} ({base_log['support'] - base_log['missed']}/{base_log['support']}), candidate {fmt(cand_log['recall'])} ({cand_log['support'] - cand_log['missed']}/{cand_log['support']}).",
        f"Binary-malicious rows then labeled Benign by multiclass: baseline {base['binary_malicious_then_labeled_benign']}, candidate {cand['binary_malicious_then_labeled_benign']}.",
        "",
        "## Controlled legitimate suite",
        "",
        "The 35 saved Java feature vectors are scored unchanged on the first 13 features. `jndi_lookup_marker` for the candidate is computed from the harness header values that built those vectors (Host, User-Agent, and the Accept headers for profiles H3–H6). Specification labels are not model inputs.",
        "",
        f"Marker 1 on the suite: {result['suite_marker_positive']} of {result['suite']['cases']}.",
        f"Blocked requests: baseline {result['suite_baseline']['blocked']} of {result['suite_baseline']['cases']}, candidate {result['suite_candidate']['blocked']} of {result['suite_candidate']['cases']}.",
        "",
        "## Comparison",
        "",
        result["comparison"],
        "",
        "## Checks",
        "",
    ])
    for check in result["checks"]:
        lines.append(f"- {check}")
    lines.append("")
    with open(os.path.join(HERE, "JNDI_FEATURE_EXPERIMENT.md"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def main():
    require_sklearn()
    os.makedirs(HERE, exist_ok=True)
    record_ids = np.load(RECORD_IDS)
    matrix13, labels, binary = load_train()
    if len(record_ids) != len(matrix13):
        raise SystemExit("record-id alignment length does not match the training CSV")
    marker, decoded_only = load_marker_column(record_ids)
    matrix14 = np.column_stack([matrix13, marker])
    index = np.arange(len(binary))
    train_idx, val_idx = train_test_split(
        index, test_size=VAL_FRACTION, random_state=INNER_SEED, stratify=binary
    )

    baseline_binary = joblib.load(BASELINE_BINARY)
    baseline_multi = joblib.load(BASELINE_MULTI)
    if list(baseline_multi.classes_) != list(range(7)):
        raise SystemExit("Saved Candidate A multiclass classes_ are not 0-6.")
    baseline_check = binary_metrics(
        binary[val_idx], malicious_probability(baseline_binary, matrix13[val_idx])
    )
    checks = []
    if baseline_check["confusion_matrix"] != EXPECTED_BASELINE:
        checks.append(
            "FAILED: replayed 13-feature validation confusion matrix does not match the saved Candidate A result "
            + json.dumps(baseline_check["confusion_matrix"])
        )
        raise SystemExit(checks[-1])
    checks.append("Replayed 13-feature Candidate A validation confusion matrix matches TN 11475, FP 0, FN 204, TP 2943.")

    binary_params = copied_params(ACTIVE_BINARY)
    multi_params = copied_params(ACTIVE_MULTI)
    binary_model = RandomForestClassifier(**binary_params)
    binary_model.fit(matrix14[train_idx], binary[train_idx])
    attack_fit = train_idx[np.isin(labels[train_idx], ATTACK_CLASSES)]
    if np.any(labels[attack_fit] == "Benign") or len(attack_fit) != int(np.sum(binary[train_idx] == 1)):
        raise SystemExit("Attack-only fit rows do not match the malicious fit rows.")
    encoded = np.asarray([ATTACK_TO_INDEX[label] for label in labels[attack_fit]], dtype=np.int64)
    multi_model = RandomForestClassifier(**multi_params)
    multi_model.fit(matrix14[attack_fit], encoded)
    if list(binary_model.classes_) != [0, 1] or list(multi_model.classes_) != list(range(7)):
        raise SystemExit("Fitted candidate classes_ do not match the production encoding.")
    checks.append(
        f"Candidate binary classes_ [0, 1]; candidate multiclass classes_ 0-6; attack-only fit rows {len(attack_fit)}."
    )

    baseline_report = pipeline_report(labels[val_idx], baseline_binary, baseline_multi, matrix13[val_idx])
    candidate_report = pipeline_report(labels[val_idx], binary_model, multi_model, matrix14[val_idx])

    with open(SUITE_PATH, encoding="utf-8") as handle:
        suite_cases = json.load(handle)["cases"]
    suite_baseline = score_suite(baseline_binary, baseline_multi, suite_cases, 13)
    suite_candidate = score_suite(binary_model, multi_model, suite_cases, 14)
    suite_marker_positive = int(sum(row["jndi_lookup_marker"] for row in suite_candidate["results"]))

    base_log_miss = baseline_report["log4j_missed_at_binary_stage"]
    cand_log_miss = candidate_report["log4j_missed_at_binary_stage"]
    base_fp = baseline_report["binary"]["confusion_matrix"]["fp"]
    cand_fp = candidate_report["binary"]["confusion_matrix"]["fp"]
    log4j_improved = cand_log_miss < base_log_miss
    benign_not_worse = cand_fp <= base_fp
    suite_not_worse = suite_candidate["blocked"] <= suite_baseline["blocked"]
    if log4j_improved and benign_not_worse and suite_not_worse:
        comparison = (
            f"On this validation split the candidate misses {cand_log_miss} LOG4J rows against the baseline's {base_log_miss}. "
            f"Validation benign blocks stay at {cand_fp} (baseline {base_fp}). "
            f"The 35-case suite blocks {suite_candidate['blocked']} requests against the baseline's {suite_baseline['blocked']}. "
            "LOG4J detection improved without an increase in validation benign blocks or controlled-suite blocks. "
            "The suite can remain largely blocked when `jndi_lookup_marker` is 0, because the other 13 features are unchanged."
        )
    else:
        comparison = (
            f"The measurements do not support an unqualified improvement. "
            f"LOG4J binary misses: baseline {base_log_miss}, candidate {cand_log_miss}. "
            f"Validation benign blocks: baseline {base_fp}, candidate {cand_fp}. "
            f"Controlled-suite blocks: baseline {suite_baseline['blocked']}, candidate {suite_candidate['blocked']}."
        )
    checks.append("Held-out test CSV was not opened. Active model files were loaded and not written.")

    joblib.dump(binary_model, os.path.join(HERE, "candidate_binary_rf_jndi_marker.joblib"))
    joblib.dump(multi_model, os.path.join(HERE, "candidate_multiclass_rf_jndi_marker.joblib"))
    np.save(os.path.join(HERE, "jndi_lookup_marker_train.npy"), marker.astype(np.int8))

    result = {
        "sklearn": sklearn.__version__,
        "threshold": THRESHOLD,
        "train_rows": int(len(labels)),
        "fit_rows": int(len(train_idx)),
        "validation_rows": int(len(val_idx)),
        "marker_positive_train_rows": int(np.sum(marker == 1)),
        "decoded_only_matches": int(decoded_only),
        "marker_by_label_train_csv": marker_rates(labels, marker),
        "binary_params": {key: binary_params[key] for key in binary_params if key != "n_jobs"},
        "multiclass_params": {key: multi_params[key] for key in multi_params if key != "n_jobs"},
        "baseline_13": baseline_report,
        "candidate_14": candidate_report,
        "suite": {"cases": len(suite_cases)},
        "suite_marker_positive": suite_marker_positive,
        "suite_baseline": suite_baseline,
        "suite_candidate": suite_candidate,
        "comparison": comparison,
        "checks": checks,
        "files_not_opened": ["data/raw/atrdf/REQUEST_ONLY_test.csv"],
    }
    with open(os.path.join(HERE, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    write_report(result)
    print(comparison)
    print(
        f"baseline_log4j_miss={base_log_miss} candidate_log4j_miss={cand_log_miss} "
        f"baseline_fp={base_fp} candidate_fp={cand_fp} "
        f"suite_baseline={suite_baseline['blocked']} suite_candidate={suite_candidate['blocked']}"
    )


if __name__ == "__main__":
    main()
