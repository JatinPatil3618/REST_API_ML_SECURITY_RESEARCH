"""Refit the benign-augmentation forest after dropping suite-identical vectors.

Reads the saved augmentation files. Does not overwrite them or read the test CSV.
"""

import csv
import json
import os

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
AUG_DIR = os.path.dirname(HERE)
ABLATION = os.path.dirname(AUG_DIR)
ROOT = os.path.abspath(os.path.join(ABLATION, "..", ".."))
TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
FEATURES = [
    "url_entropy",
    "header_count",
    "path_length",
    "url_special_count",
    "url_length",
    "path_segment_count",
    "cookie_present",
    "query_length",
    "url_digit_count",
    "user_agent_entropy",
    "query_parameter_count",
    "request_body_entropy",
    "request_body_digit_count",
]
ATTACK_CLASSES = [
    "Cookie Injection",
    "Directory Traversal",
    "LOG4J",
    "Log Forging",
    "RCE",
    "SQL Injection",
    "XSS",
]
THRESHOLD = 0.50
INNER_SEED = 42
FOCUS_ROUTES = {"/api/books", "/api/comments/book/101"}


def load_train():
    with open(TRAIN_CSV, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames[:13] != FEATURES:
            raise SystemExit("Training CSV feature order does not match the 13-feature contract.")
        matrix = []
        labels = []
        binary = []
        for row in reader:
            matrix.append([float(row[name]) for name in FEATURES])
            labels.append(row["label"])
            binary.append(int(row["is_malicious"]))
    return (
        np.asarray(matrix, dtype=np.float64),
        np.asarray(labels),
        np.asarray(binary, dtype=np.int64),
    )


def vector_key(features):
    return tuple(float(features[name]) for name in FEATURES)


def binary_metrics(y_true, proba):
    pred = (proba >= THRESHOLD).astype(np.int64)
    matrix = confusion_matrix(y_true, pred, labels=[0, 1])
    tn, fp, fn, tp = [int(value) for value in matrix.ravel()]
    return {
        "threshold": THRESHOLD,
        "precision": float(precision_score(y_true, pred, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_true, pred, pos_label=1, zero_division=0)),
        "f1": float(f1_score(y_true, pred, pos_label=1, zero_division=0)),
        "false_positive_rate": float(fp / (tn + fp)) if (tn + fp) else None,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def main():
    with open(os.path.join(AUG_DIR, "augmentation_features.json"), encoding="utf-8") as handle:
        feature_rows = json.load(handle)
    with open(os.path.join(AUG_DIR, "augmentation_manifest.json"), encoding="utf-8") as handle:
        manifest = {row["case_id"]: row for row in json.load(handle)}
    with open(os.path.join(ABLATION, "controlled_suite_features.json"), encoding="utf-8") as handle:
        suite = json.load(handle)["cases"]

    suite_by_key = {}
    for case in suite:
        suite_by_key.setdefault(vector_key(case["features"]), []).append(case["case_id"])

    overlaps = []
    retained_features = []
    retained_manifest = []
    for row in feature_rows:
        matches = suite_by_key.get(vector_key(row["features"]), [])
        meta = manifest[row["case_id"]]
        if matches:
            compared = []
            for case in suite:
                if case["case_id"] in matches:
                    compared.append({
                        "suite_case_id": case["case_id"],
                        "route": case["route"],
                        "query": case["query"],
                        "header_profile": case["header_profile"],
                        "equal_on_all_13": vector_key(case["features"]) == vector_key(row["features"]),
                    })
            overlaps.append({
                "augmentation_case_id": row["case_id"],
                "route": meta["route"],
                "query": meta["query"],
                "header_profile": meta["header_profile"],
                "suite_matches": compared,
            })
        else:
            retained_features.append(row)
            retained_manifest.append(meta)

    if not overlaps:
        raise SystemExit("No exact feature-vector overlaps were found.")

    x, labels, binary = load_train()
    index = np.arange(len(binary))
    train_idx, val_idx = train_test_split(
        index, test_size=0.1, random_state=INNER_SEED, stratify=binary
    )
    if len(train_idx) != 131591 or len(val_idx) != 14622:
        raise SystemExit("Fit/validation sizes do not match the saved split.")

    augmentation = np.asarray(
        [[float(row["features"][name]) for name in FEATURES] for row in retained_features],
        dtype=np.float64,
    )
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=5,
        min_samples_leaf=1,
        class_weight=None,
        max_features="sqrt",
        random_state=INNER_SEED,
        n_jobs=-1,
    )
    model.fit(
        np.vstack([x[train_idx], augmentation]),
        np.concatenate([binary[train_idx], np.zeros(len(augmentation), dtype=np.int64)]),
    )
    column = list(model.classes_).index(1)
    val_proba = model.predict_proba(x[val_idx])[:, column]
    validation = binary_metrics(binary[val_idx], val_proba)
    val_positive = val_proba >= THRESHOLD
    per_attack = []
    for name in ATTACK_CLASSES:
        mask = labels[val_idx] == name
        per_attack.append({
            "label": name,
            "support": int(np.sum(mask)),
            "recall": float(np.sum(mask & val_positive) / np.sum(mask)),
            "missed_at_binary_stage": int(np.sum(mask & ~val_positive)),
        })

    suite_matrix = np.asarray(
        [[float(case["features"][name]) for name in FEATURES] for case in suite],
        dtype=np.float64,
    )
    suite_proba = model.predict_proba(suite_matrix)[:, column]
    suite_results = []
    focus = []
    false_positives = 0
    for case, proba in zip(suite, suite_proba):
        decision = "MALICIOUS" if proba >= THRESHOLD else "BENIGN"
        if decision == "MALICIOUS":
            false_positives += 1
        row = {
            "case_id": case["case_id"],
            "route": case["route"],
            "query": case["query"],
            "header_profile": case["header_profile"],
            "binary_p_malicious": float(proba),
            "binary_decision": decision,
        }
        suite_results.append(row)
        if case["route"] in FOCUS_ROUTES and not case["query"]:
            focus.append(row)

    result = {
        "test_csv": "not read",
        "threshold": THRESHOLD,
        "random_state": INNER_SEED,
        "original_fit_rows": int(len(train_idx)),
        "removed_overlap_rows": [row["augmentation_case_id"] for row in overlaps],
        "retained_augmentation_rows": int(len(retained_features)),
        "validation_rows": int(len(val_idx)),
        "exact_feature_vector_overlaps": overlaps,
        "validation_binary": validation,
        "validation_per_attack_recall": per_attack,
        "controlled_suite_false_positives": false_positives,
        "controlled_suite_cases": len(suite_results),
        "focus_routes": focus,
        "controlled_suite_results": suite_results,
    }
    os.makedirs(HERE, exist_ok=True)
    joblib.dump(model, os.path.join(HERE, "candidate_binary_rf_leave_overlap_out.joblib"))
    with open(os.path.join(HERE, "retained_manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(retained_manifest, handle, indent=2)
    with open(os.path.join(HERE, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    printable = {key: result[key] for key in result if key != "controlled_suite_results"}
    print(json.dumps(printable, indent=2))


if __name__ == "__main__":
    main()
