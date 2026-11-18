"""Train one temporary binary forest on the original fit rows plus benign augmentation.

Does not read the held-out test CSV and does not write parent candidate files or models/atrdf.
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
PARENT = os.path.dirname(HERE)
ROOT = os.path.abspath(os.path.join(PARENT, "..", ".."))
TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
FEATURES_PATH = os.path.join(HERE, "augmentation_features.json")
MANIFEST_PATH = os.path.join(HERE, "augmentation_manifest.json")
SUITE_PATH = os.path.join(PARENT, "controlled_suite_features.json")
MULTICLASS_PATH = os.path.join(PARENT, "candidate_a_multiclass_rf.joblib")
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
    with open(FEATURES_PATH, encoding="utf-8") as handle:
        feature_rows = json.load(handle)
    with open(MANIFEST_PATH, encoding="utf-8") as handle:
        manifest = json.load(handle)
    by_id = {row["case_id"]: row for row in manifest}
    if [row["case_id"] for row in feature_rows] != [row["case_id"] for row in manifest]:
        raise SystemExit("Feature rows and manifest case ids differ.")
    augmentation = np.asarray(
        [[float(row["features"][name]) for name in FEATURES] for row in feature_rows],
        dtype=np.float64,
    )

    with open(SUITE_PATH, encoding="utf-8") as handle:
        suite = json.load(handle)["cases"]
    suite_keys = {vector_key(case["features"]): case["case_id"] for case in suite}
    suite_identity = {
        (case["route"], case["query"], case["header_profile"])
        for case in suite
    }
    overlaps = []
    for row in feature_rows:
        meta = by_id[row["case_id"]]
        identity = (meta["route"], meta["query"], meta["header_profile"])
        feature_match = suite_keys.get(vector_key(row["features"]))
        if identity in suite_identity or feature_match:
            overlaps.append({
                "augmentation_case_id": row["case_id"],
                "same_request_identity": identity in suite_identity,
                "same_feature_vector_as": feature_match,
            })

    x, labels, binary = load_train()
    index = np.arange(len(binary))
    train_idx, val_idx = train_test_split(
        index, test_size=0.1, random_state=INNER_SEED, stratify=binary
    )
    if len(train_idx) != 131591 or len(val_idx) != 14622:
        raise SystemExit("Fit/validation sizes do not match the saved split.")

    x_fit = np.vstack([x[train_idx], augmentation])
    y_fit = np.concatenate([binary[train_idx], np.zeros(len(augmentation), dtype=np.int64)])
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
    model.fit(x_fit, y_fit)
    malicious_column = list(model.classes_).index(1)
    val_proba = model.predict_proba(x[val_idx])[:, malicious_column]
    validation = binary_metrics(binary[val_idx], val_proba)
    val_positive = val_proba >= THRESHOLD
    missed = {}
    for name in ATTACK_CLASSES:
        mask = labels[val_idx] == name
        missed[name] = {
            "support": int(np.sum(mask)),
            "missed_at_binary_stage": int(np.sum(mask & ~val_positive)),
            "recall": float(np.sum(mask & val_positive) / np.sum(mask)) if np.any(mask) else None,
        }

    multiclass = joblib.load(MULTICLASS_PATH)
    if list(multiclass.classes_) != list(range(7)):
        raise SystemExit("Candidate A multiclass classes_ are not 0-6.")

    def family(rows):
        indices = np.argmax(multiclass.predict_proba(rows), axis=1)
        return [ATTACK_CLASSES[int(index)] for index in indices]

    suite_matrix = np.asarray(
        [[float(case["features"][name]) for name in FEATURES] for case in suite],
        dtype=np.float64,
    )
    suite_proba = model.predict_proba(suite_matrix)[:, malicious_column]
    suite_positive = suite_proba >= THRESHOLD
    suite_family = family(suite_matrix)
    suite_results = []
    suite_fp = 0
    for case, proba, positive, predicted in zip(suite, suite_proba, suite_positive, suite_family):
        combined = predicted if positive else "Benign"
        if combined != "Benign":
            suite_fp += 1
        suite_results.append({
            "case_id": case["case_id"],
            "route": case["route"],
            "query": case["query"],
            "header_profile": case["header_profile"],
            "binary_p_malicious": float(proba),
            "combined_label": combined,
        })

    val_family = family(x[val_idx])
    combined = np.where(val_positive, val_family, "Benign")
    per_attack = []
    for name in ATTACK_CLASSES:
        mask = labels[val_idx] == name
        per_attack.append({
            "label": name,
            "support": int(np.sum(mask)),
            "recall": float(np.sum(mask & (combined == name)) / np.sum(mask)),
        })

    result = {
        "test_csv": "not read",
        "threshold": THRESHOLD,
        "original_fit_rows": int(len(train_idx)),
        "augmentation_rows": int(len(augmentation)),
        "augmented_fit_rows": int(len(y_fit)),
        "validation_rows": int(len(val_idx)),
        "health_route": "excluded from augmentation because H2-H6 on /api/health are already the 35-case suite",
        "feature_vector_overlaps_with_suite": overlaps,
        "overlap_count": len(overlaps),
        "validation_binary": validation,
        "validation_attacks_missed_at_binary_stage": missed,
        "validation_pipeline_attack_recall": per_attack,
        "validation_benign_blocked": validation["confusion_matrix"]["fp"],
        "controlled_suite_false_positives": suite_fp,
        "controlled_suite_false_positive_rate": suite_fp / len(suite_results),
        "controlled_suite_results": suite_results,
    }
    joblib.dump(model, os.path.join(HERE, "candidate_binary_rf_augmented.joblib"))
    with open(os.path.join(HERE, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps({key: result[key] for key in result if key != "controlled_suite_results"}, indent=2))


if __name__ == "__main__":
    main()
