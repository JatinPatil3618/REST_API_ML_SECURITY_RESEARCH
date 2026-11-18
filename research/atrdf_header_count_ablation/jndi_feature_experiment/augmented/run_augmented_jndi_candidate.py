"""Augment the 14-feature JNDI candidate with the 23 leave-overlap-out benign rows.

Does not open REQUEST_ONLY_test.csv and does not write production artifacts.
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
EXPERIMENT = os.path.dirname(HERE)
ABLATION = os.path.dirname(EXPERIMENT)
ROOT = os.path.abspath(os.path.join(ABLATION, "..", ".."))
TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
MARKER_NPY = os.path.join(EXPERIMENT, "jndi_lookup_marker_train.npy")
LEAVE_DIR = os.path.join(ABLATION, "benign_augmentation", "leave_overlap_out")
AUG_FEATURES = os.path.join(ABLATION, "benign_augmentation", "augmentation_features.json")
SUITE_PATH = os.path.join(ABLATION, "controlled_suite_features.json")
CURRENT_BINARY = os.path.join(EXPERIMENT, "candidate_binary_rf_jndi_marker.joblib")
CURRENT_MULTI = os.path.join(EXPERIMENT, "candidate_multiclass_rf_jndi_marker.joblib")
BASELINE_13 = os.path.join(ABLATION, "candidate_a_binary_rf.joblib")
ACTIVE_BINARY = os.path.join(ROOT, "models", "atrdf", "atrdf_binary_rf_request_only.joblib")
ACTIVE_MULTI = os.path.join(ROOT, "models", "atrdf", "atrdf_multiclass_rf_request_only.joblib")
FEATURES = [
    "url_entropy", "header_count", "path_length", "url_special_count", "url_length",
    "path_segment_count", "cookie_present", "query_length", "url_digit_count",
    "user_agent_entropy", "query_parameter_count", "request_body_entropy",
    "request_body_digit_count",
]
MARKER = "jndi_lookup_marker"
ATTACK_CLASSES = [
    "Cookie Injection", "Directory Traversal", "LOG4J", "Log Forging",
    "RCE", "SQL Injection", "XSS",
]
ATTACK_TO_INDEX = {name: index for index, name in enumerate(ATTACK_CLASSES)}
CLASS_ORDER = ["Benign"] + ATTACK_CLASSES
THRESHOLD = 0.50
PATTERN = re.compile(r"\$\{\s*jndi\s*:", re.IGNORECASE)
HEADER_VALUES = {
    "H2": [("Host", "127.0.0.1:8080"), ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")],
    "H3": [("Host", "127.0.0.1:8080"), ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), ("Accept", "application/json")],
    "H4": [("Host", "127.0.0.1:8080"), ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), ("Accept", "application/json"), ("Accept-Language", "en-US,en;q=0.9")],
    "H5": [("Host", "127.0.0.1:8080"), ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), ("Accept", "application/json"), ("Accept-Language", "en-US,en;q=0.9"), ("Accept-Encoding", "gzip, deflate")],
    "H6": [("Host", "127.0.0.1:8080"), ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), ("Accept", "application/json"), ("Accept-Language", "en-US,en;q=0.9"), ("Accept-Encoding", "gzip, deflate"), ("Connection", "keep-alive")],
}


def require_sklearn():
    if sklearn.__version__ != "1.2.2":
        raise SystemExit(f"Expected scikit-learn 1.2.2, found {sklearn.__version__}")


def marker_from_headers(headers):
    for value in headers.values():
        text = "" if value is None else str(value)
        if PATTERN.search(text) or PATTERN.search(unquote(text)):
            return 1
    return 0


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


def copied_params(path):
    params = joblib.load(path).get_params()
    return {
        "n_estimators": params["n_estimators"],
        "max_depth": params["max_depth"],
        "min_samples_split": params["min_samples_split"],
        "min_samples_leaf": params["min_samples_leaf"],
        "class_weight": params["class_weight"],
        "max_features": params["max_features"],
        "random_state": 42,
        "n_jobs": -1,
    }


def malicious_probability(model, rows):
    if list(model.classes_) != [0, 1]:
        raise SystemExit(f"Binary classes_ must be [0, 1], got {list(model.classes_)}")
    return model.predict_proba(rows)[:, 1]


def attack_family(model, rows):
    if list(model.classes_) != list(range(7)):
        raise SystemExit(f"Multiclass classes_ must be 0-6, got {list(model.classes_)}")
    indices = np.argmax(model.predict_proba(rows), axis=1)
    return np.asarray([ATTACK_CLASSES[int(index)] for index in indices])


def binary_metrics(y_true, proba):
    pred = (proba >= THRESHOLD).astype(np.int64)
    tn, fp, fn, tp = [int(value) for value in confusion_matrix(y_true, pred, labels=[0, 1]).ravel()]
    return {
        "precision": float(precision_score(y_true, pred, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_true, pred, pos_label=1, zero_division=0)),
        "f1": float(f1_score(y_true, pred, pos_label=1, zero_division=0)),
        "false_positive_rate": float(fp / (tn + fp)) if tn + fp else None,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def pipeline_report(labels, binary_model, multi_model, rows):
    proba = malicious_probability(binary_model, rows)
    positive = proba >= THRESHOLD
    combined = np.where(positive, attack_family(multi_model, rows), "Benign")
    y_binary = (labels != "Benign").astype(np.int64)
    precision, recall, f1, support = precision_recall_fscore_support(
        labels, combined, labels=CLASS_ORDER, zero_division=0
    )
    per_class = []
    for index, label in enumerate(CLASS_ORDER):
        per_class.append({
            "label": label,
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
            "support": int(support[index]),
            "missed": int(np.sum((labels == label) & (combined != label))),
        })
    return {
        "binary": binary_metrics(y_binary, proba),
        "per_class": per_class,
        "log4j_missed_at_binary_stage": int(np.sum((labels == "LOG4J") & ~positive)),
        "proba": proba,
        "combined": combined,
    }


def load_augmentation():
    with open(AUG_FEATURES, encoding="utf-8") as handle:
        by_id = {row["case_id"]: row for row in json.load(handle)}
    with open(os.path.join(LEAVE_DIR, "retained_manifest.json"), encoding="utf-8") as handle:
        retained = json.load(handle)
    if len(retained) != 23:
        raise SystemExit(f"Expected 23 retained augmentation rows, found {len(retained)}")
    rows = []
    marker_hits = []
    for meta in retained:
        profile = meta["header_profile"]
        if profile not in HEADER_VALUES:
            raise SystemExit(f"{meta['case_id']} uses an unknown header profile {profile}")
        names = [name for name, _value in HEADER_VALUES[profile]]
        if list(meta["header_names"]) != names:
            raise SystemExit(f"{meta['case_id']} header names do not match profile {profile}")
        marker = marker_from_headers(dict(HEADER_VALUES[profile]))
        if marker != 0:
            marker_hits.append(meta["case_id"])
        features = by_id[meta["case_id"]]["features"]
        vector = [float(features[name]) for name in FEATURES] + [0.0]
        rows.append({"case_id": meta["case_id"], "route": meta["route"], "query": meta["query"], "header_profile": profile, "vector": vector, "marker": marker})
    if marker_hits:
        raise SystemExit("Augmentation header values matched the JNDI pattern: " + ", ".join(marker_hits))
    keys = [tuple(row["vector"][:13]) for row in rows]
    if len(set(keys)) != 23:
        raise SystemExit("Retained augmentation vectors are not 23 distinct 13-feature rows.")
    return rows


def score_suite(binary_model, multi_model, cases):
    scored = []
    for case in cases:
        features = case["features"]
        marker = marker_from_headers(dict(HEADER_VALUES[case["header_profile"]]))
        vector = np.asarray([[float(features[name]) for name in FEATURES] + [marker]], dtype=np.float64)
        proba = float(malicious_probability(binary_model, vector)[0])
        label = "Benign"
        if proba >= THRESHOLD:
            label = str(attack_family(multi_model, vector)[0])
        scored.append({
            "case_id": case["case_id"],
            "route": case["route"],
            "query": case["query"],
            "header_profile": case["header_profile"],
            "jndi_lookup_marker": marker,
            "features": {name: float(features[name]) for name in FEATURES},
            "binary_p_malicious": proba,
            "combined_label": label,
        })
    return scored


def fmt(value):
    return f"{value:.6f}" if isinstance(value, float) else str(value)


def write_report(result):
    current = result["current_14"]
    augmented = result["augmented_14"]
    lines = [
        "# Augmented 14-feature JNDI candidate",
        "",
        "Temporary candidates only. `REQUEST_ONLY_test.csv` was not opened. Production models and gateway code were not changed. Threshold fixed at 0.50. Results are limited to this validation split and the 35-case suite.",
        "",
        "## Command",
        "",
        "```",
        r".venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\jndi_feature_experiment\augmented\run_augmented_jndi_candidate.py",
        "```",
        "",
        f"scikit-learn {result['sklearn']}. Original fit rows {result['fit_rows']}. Added benign rows {result['added_benign_rows']}. Validation rows {result['validation_rows']}.",
        "",
        "The 23 leave-overlap-out vectors keep their saved 13 features. `jndi_lookup_marker` was set to 0 only after the harness header values for each row's profile were checked with `\\$\\{\\s*jndi\\s*:`. None matched. Labels were not used to set the feature.",
        "",
        "## Validation binary metrics",
        "",
        "| Model | Precision | Recall | F1 | FPR | TN | FP | FN | TP |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, block in (("Current 14-feature", current), ("Augmented 14-feature", augmented)):
        binary = block["binary"]
        matrix = binary["confusion_matrix"]
        lines.append(
            f"| {name} | {fmt(binary['precision'])} | {fmt(binary['recall'])} | {fmt(binary['f1'])} | "
            f"{fmt(binary['false_positive_rate'])} | {matrix['tn']} | {matrix['fp']} | {matrix['fn']} | {matrix['tp']} |"
        )
    lines.extend([
        "",
        "## Validation attack families",
        "",
        "| Family | Current P | Current R | Current F1 | Current missed | Augmented P | Augmented R | Augmented F1 | Augmented missed |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    augmented_by_label = {row["label"]: row for row in augmented["per_class"]}
    for row in current["per_class"]:
        other = augmented_by_label[row["label"]]
        lines.append(
            f"| {row['label']} | {fmt(row['precision'])} | {fmt(row['recall'])} | {fmt(row['f1'])} | {row['missed']} | "
            f"{fmt(other['precision'])} | {fmt(other['recall'])} | {fmt(other['f1'])} | {other['missed']} |"
        )
    recovered = result["previously_missed_log4j"]
    lines.extend([
        "",
        f"The 13-feature baseline still identifies {recovered['count']} validation LOG4J misses. The augmented candidate detects {recovered['detected_by_augmented_binary']} of them at the binary stage and labels {recovered['labeled_log4j_by_augmented_pipeline']} as LOG4J.",
        "",
        "## Legitimate suite, case by case",
        "",
        f"Blocked: current {result['suite_current_blocked']} of 35, augmented {result['suite_augmented_blocked']} of 35. Marker 1 on the suite: {result['suite_marker_positive']}.",
        "",
        "| Case | Route | Profile | Current score | Current label | Augmented score | Augmented label |",
        "|---|---|---|---:|---|---:|---|",
    ])
    for row in result["suite_comparison"]:
        lines.append(
            f"| {row['case_id']} | `{row['route']}` | {row['header_profile']} | {fmt(row['current_score'])} | {row['current_label']} | {fmt(row['augmented_score'])} | {row['augmented_label']} |"
        )
    lines.extend(["", "## Remaining false positives", ""])
    if not result["remaining_false_positives"]:
        lines.append("The augmented candidate blocks no validation benign row and none of the 35 legitimate cases.")
    else:
        lines.append("Validation benign blocks: " + str(augmented["binary"]["confusion_matrix"]["fp"]) + ". Remaining suite blocks:")
        lines.append("")
        lines.append("| Case | Route | Profile | Score | Label | header_count | jndi_lookup_marker | url_length | url_entropy | url_special_count | path_length | user_agent_entropy |")
        lines.append("|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|")
        for row in result["remaining_false_positives"]:
            features = row["features"]
            lines.append(
                f"| {row['case_id']} | `{row['route']}` | {row['header_profile']} | {fmt(row['binary_p_malicious'])} | {row['combined_label']} | "
                f"{fmt(features['header_count'])} | {row['jndi_lookup_marker']} | {fmt(features['url_length'])} | {fmt(features['url_entropy'])} | "
                f"{fmt(features['url_special_count'])} | {fmt(features['path_length'])} | {fmt(features['user_agent_entropy'])} |"
            )
    lines.extend(["", "## Checks", ""])
    for check in result["checks"]:
        lines.append(f"- {check}")
    lines.append("")
    with open(os.path.join(HERE, "AUGMENTED_EXPERIMENT.md"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def main():
    require_sklearn()
    augmentation = load_augmentation()
    matrix13, labels, binary = load_train()
    marker = np.load(MARKER_NPY)
    if len(marker) != len(matrix13):
        raise SystemExit("Saved marker column does not match the training CSV")
    matrix14 = np.column_stack([matrix13, marker.astype(np.float64)])
    index = np.arange(len(binary))
    train_idx, val_idx = train_test_split(index, test_size=0.1, random_state=42, stratify=binary)
    if len(train_idx) != 131591 or len(val_idx) != 14622:
        raise SystemExit("Fit/validation sizes do not match the saved split.")

    added = np.asarray([row["vector"] for row in augmentation], dtype=np.float64)
    with open(SUITE_PATH, encoding="utf-8") as handle:
        suite = json.load(handle)["cases"]
    suite_keys = {tuple(float(case["features"][name]) for name in FEATURES) for case in suite}
    overlap = [row["case_id"] for row in augmentation if tuple(row["vector"][:13]) in suite_keys]
    if overlap:
        raise SystemExit("Retained augmentation vectors overlap the 35-case suite: " + ", ".join(overlap))

    binary_params = copied_params(ACTIVE_BINARY)
    multi_params = copied_params(ACTIVE_MULTI)
    binary_model = RandomForestClassifier(**binary_params)
    binary_model.fit(
        np.vstack([matrix14[train_idx], added]),
        np.concatenate([binary[train_idx], np.zeros(len(added), dtype=np.int64)]),
    )
    attack_fit = train_idx[np.isin(labels[train_idx], ATTACK_CLASSES)]
    if len(attack_fit) != int(np.sum(binary[train_idx] == 1)):
        raise SystemExit("Attack-only fit rows do not match the malicious fit rows.")
    encoded = np.asarray([ATTACK_TO_INDEX[label] for label in labels[attack_fit]], dtype=np.int64)
    multi_model = RandomForestClassifier(**multi_params)
    multi_model.fit(matrix14[attack_fit], encoded)
    if list(binary_model.classes_) != [0, 1] or list(multi_model.classes_) != list(range(7)):
        raise SystemExit("Fitted classes_ do not match the production encoding.")

    current_binary = joblib.load(CURRENT_BINARY)
    current_multi = joblib.load(CURRENT_MULTI)
    current = pipeline_report(labels[val_idx], current_binary, current_multi, matrix14[val_idx])
    augmented = pipeline_report(labels[val_idx], binary_model, multi_model, matrix14[val_idx])

    baseline13 = joblib.load(BASELINE_13)
    baseline_proba = malicious_probability(baseline13, matrix13[val_idx])
    missed_mask = (labels[val_idx] == "LOG4J") & (baseline_proba < THRESHOLD)
    missed_count = int(np.sum(missed_mask))
    if missed_count != 203:
        raise SystemExit(f"Expected 203 prior LOG4J validation misses, found {missed_count}")
    detected = int(np.sum(augmented["proba"][missed_mask] >= THRESHOLD))
    labeled = int(np.sum(augmented["combined"][missed_mask] == "LOG4J"))

    current_suite = score_suite(current_binary, current_multi, suite)
    augmented_suite = score_suite(binary_model, multi_model, suite)
    comparison = []
    remaining = []
    for current_row, augmented_row in zip(current_suite, augmented_suite):
        comparison.append({
            "case_id": current_row["case_id"],
            "route": current_row["route"],
            "header_profile": current_row["header_profile"],
            "current_score": current_row["binary_p_malicious"],
            "current_label": current_row["combined_label"],
            "augmented_score": augmented_row["binary_p_malicious"],
            "augmented_label": augmented_row["combined_label"],
        })
        if augmented_row["combined_label"] != "Benign":
            remaining.append(augmented_row)

    checks = [
        "23 retained augmentation rows use profiles H2-H6 and none of those header values match the JNDI pattern.",
        "jndi_lookup_marker was set to 0 on those 23 rows after that check.",
        "None of the 23 vectors matches a 35-case suite vector on the original 13 features.",
        f"Previously missed LOG4J validation rows: {missed_count}. Augmented binary detections among them: {detected}. Augmented pipeline LOG4J labels among them: {labeled}.",
        "Held-out test CSV was not opened. Active model files were loaded and not written.",
    ]
    if detected != 203 or labeled != 203:
        checks.append("FAILED: the augmented candidate does not still detect every previously missed LOG4J validation row.")

    joblib.dump(binary_model, os.path.join(HERE, "candidate_binary_rf_jndi_augmented.joblib"))
    joblib.dump(multi_model, os.path.join(HERE, "candidate_multiclass_rf_jndi_augmented.joblib"))
    result = {
        "sklearn": sklearn.__version__,
        "fit_rows": int(len(train_idx)),
        "added_benign_rows": len(augmentation),
        "validation_rows": int(len(val_idx)),
        "current_14": {key: value for key, value in current.items() if key not in ("proba", "combined")},
        "augmented_14": {key: value for key, value in augmented.items() if key not in ("proba", "combined")},
        "previously_missed_log4j": {
            "count": missed_count,
            "detected_by_augmented_binary": detected,
            "labeled_log4j_by_augmented_pipeline": labeled,
        },
        "suite_current_blocked": int(sum(row["combined_label"] != "Benign" for row in current_suite)),
        "suite_augmented_blocked": len(remaining),
        "suite_marker_positive": int(sum(row["jndi_lookup_marker"] for row in augmented_suite)),
        "suite_comparison": comparison,
        "remaining_false_positives": remaining,
        "checks": checks,
    }
    with open(os.path.join(HERE, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    write_report(result)
    print(
        f"log4j_still_detected={detected}/{missed_count} labeled_log4j={labeled} "
        f"val_fp={augmented['binary']['confusion_matrix']['fp']} "
        f"suite_current={result['suite_current_blocked']} suite_augmented={result['suite_augmented_blocked']}"
    )


if __name__ == "__main__":
    main()
