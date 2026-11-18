"""Fit temporary multiclass forests on the saved binary candidates' fit rows.

Does not read REQUEST_ONLY_test.csv and does not write models/atrdf.
"""

import json
import os

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support, precision_score, recall_score
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
ACTIVE_MULTICLASS = os.path.join(ROOT, "models", "atrdf", "atrdf_multiclass_rf_request_only.joblib")
SUITE_PATH = os.path.join(HERE, "controlled_suite_features.json")
THRESHOLD = 0.50
INNER_SEED = 42
VAL_FRACTION = 0.1
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
FEATURES_B = [name for name in FEATURES if name != "header_count"]
ATTACK_CLASSES = [
    "Cookie Injection",
    "Directory Traversal",
    "LOG4J",
    "Log Forging",
    "RCE",
    "SQL Injection",
    "XSS",
]
ATTACK_TO_INDEX = {name: index for index, name in enumerate(ATTACK_CLASSES)}
CLASS_ORDER = ["Benign"] + ATTACK_CLASSES
EXPECTED_BINARY = {
    "A": {"tn": 11475, "fp": 0, "fn": 204, "tp": 2943},
    "B": {"tn": 11475, "fp": 0, "fn": 300, "tp": 2847},
}


def load_train():
    import csv
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
    }


def malicious_probability(model, rows):
    proba = model.predict_proba(rows)
    return proba[:, list(model.classes_).index(1)]


def attack_family(multi_model, rows):
    """Map argmax to the production metadata list, as ml_service does."""
    if list(multi_model.classes_) != list(range(7)):
        raise SystemExit(f"Multiclass classes_ must be 0-6, got {list(multi_model.classes_)}")
    probabilities = multi_model.predict_proba(rows)
    indices = np.argmax(probabilities, axis=1)
    return np.asarray([ATTACK_CLASSES[int(index)] for index in indices])


def pipeline_predictions(binary_model, multi_model, rows, columns):
    proba = malicious_probability(binary_model, rows[:, columns])
    binary_positive = proba >= THRESHOLD
    family = attack_family(multi_model, rows[:, columns])
    combined = np.where(binary_positive, family, "Benign")
    return proba, binary_positive, combined


def combined_report(y_true, combined, binary_positive):
    matrix = confusion_matrix(y_true, combined, labels=CLASS_ORDER)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, combined, labels=CLASS_ORDER, zero_division=0
    )
    attack = y_true != "Benign"
    missed = attack & ~binary_positive
    missed_by_label = {
        label: int(np.sum(missed & (y_true == label)))
        for label in CLASS_ORDER
        if label != "Benign"
    }
    blocked_then_benign = int(np.sum(attack & binary_positive & (combined == "Benign")))
    per_class = []
    for index, label in enumerate(CLASS_ORDER):
        per_class.append({
            "label": label,
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
            "support": int(support[index]),
        })
    return {
        "class_order": CLASS_ORDER,
        "confusion_matrix": matrix.astype(int).tolist(),
        "per_class": per_class,
        "attacks_missed_at_binary_stage": int(np.sum(missed)),
        "attacks_missed_at_binary_stage_by_label": missed_by_label,
        "attacks_blocked_then_labeled_benign_by_multiclass": blocked_then_benign,
    }


def score_suite(binary_model, multi_model, cases, columns):
    rows = []
    false_positives = 0
    for case in cases:
        features = case["features"]
        vector = np.asarray([[float(features[name]) for name in FEATURES]], dtype=np.float64)
        proba, binary_positive, combined = pipeline_predictions(
            binary_model, multi_model, vector, columns
        )
        decision = "MALICIOUS" if bool(binary_positive[0]) else "BENIGN"
        family = str(combined[0])
        if family != "Benign":
            false_positives += 1
        rows.append({
            "case_id": case["case_id"],
            "route": case["route"],
            "query": case["query"],
            "header_profile": case["header_profile"],
            "extracted_header_count": features["header_count"],
            "specification_label": case["specification_label"],
            "binary_p_malicious": float(proba[0]),
            "binary_decision": decision,
            "combined_label": family,
            "extraction_error": case.get("extraction_error"),
        })
    scored = len(rows)
    return {
        "cases": scored,
        "false_positives": false_positives,
        "false_positive_rate": false_positives / scored if scored else None,
        "results": rows,
    }


def main():
    active = joblib.load(ACTIVE_MULTICLASS)
    active_params = active.get_params()
    copied = {
        "n_estimators": active_params["n_estimators"],
        "max_depth": active_params["max_depth"],
        "min_samples_split": active_params["min_samples_split"],
        "min_samples_leaf": active_params["min_samples_leaf"],
        "class_weight": active_params["class_weight"],
        "max_features": active_params["max_features"],
        "random_state": INNER_SEED,
        "n_jobs": -1,
    }
    active_classes = [int(value) if isinstance(value, np.integer) else value for value in active.classes_]

    x, labels, binary = load_train()
    index = np.arange(len(binary))
    train_idx, val_idx = train_test_split(
        index, test_size=VAL_FRACTION, random_state=INNER_SEED, stratify=binary
    )
    columns_a = list(range(len(FEATURES)))
    columns_b = [FEATURES.index(name) for name in FEATURES_B]
    binary_a = joblib.load(os.path.join(HERE, "candidate_a_binary_rf.joblib"))
    binary_b = joblib.load(os.path.join(HERE, "candidate_b_binary_rf_no_header_count.joblib"))

    check_a = binary_metrics(binary[val_idx], malicious_probability(binary_a, x[val_idx][:, columns_a]))
    check_b = binary_metrics(binary[val_idx], malicious_probability(binary_b, x[val_idx][:, columns_b]))
    if check_a["confusion_matrix"] != EXPECTED_BINARY["A"] or check_b["confusion_matrix"] != EXPECTED_BINARY["B"]:
        raise SystemExit("Replayed validation split does not match the saved binary confusion matrices.")

    attack_fit = train_idx[np.isin(labels[train_idx], ATTACK_CLASSES)]
    if np.any(labels[attack_fit] == "Benign") or len(attack_fit) != int(np.sum(binary[train_idx] == 1)):
        raise SystemExit("Attack-only fit rows do not match the malicious fit rows.")
    encoded = np.asarray([ATTACK_TO_INDEX[label] for label in labels[attack_fit]], dtype=np.int64)
    multi_a = RandomForestClassifier(**copied)
    multi_b = RandomForestClassifier(**copied)
    multi_a.fit(x[attack_fit][:, columns_a], encoded)
    multi_b.fit(x[attack_fit][:, columns_b], encoded)
    if list(multi_a.classes_) != list(range(7)) or list(multi_b.classes_) != list(range(7)):
        raise SystemExit("Fitted multiclass classes_ are not exactly 0-6.")

    proba_a, positive_a, combined_a = pipeline_predictions(binary_a, multi_a, x[val_idx], columns_a)
    proba_b, positive_b, combined_b = pipeline_predictions(binary_b, multi_b, x[val_idx], columns_b)
    validation = {
        "A": {
            "binary": binary_metrics(binary[val_idx], proba_a),
            "combined": combined_report(labels[val_idx], combined_a, positive_a),
        },
        "B": {
            "binary": binary_metrics(binary[val_idx], proba_b),
            "combined": combined_report(labels[val_idx], combined_b, positive_b),
        },
    }

    with open(SUITE_PATH, encoding="utf-8") as handle:
        suite = json.load(handle)
    suite_scores = {
        "A": score_suite(binary_a, multi_a, suite["cases"], columns_a),
        "B": score_suite(binary_b, multi_b, suite["cases"], columns_b),
    }

    joblib.dump(multi_a, os.path.join(HERE, "candidate_a_multiclass_rf.joblib"))
    joblib.dump(multi_b, os.path.join(HERE, "candidate_b_multiclass_rf.joblib"))
    result = {
        "sklearn": sklearn.__version__,
        "test_csv": "not read",
        "threshold": THRESHOLD,
        "fit_rows": int(len(train_idx)),
        "attack_only_fit_rows": int(len(attack_fit)),
        "validation_rows": int(len(val_idx)),
        "multiclass_label_encoding": ATTACK_TO_INDEX,
        "benign_included_in_multiclass_fit": False,
        "random_state": INNER_SEED,
        "stratify": "is_malicious",
        "active_multiclass_classes": active_classes,
        "temporary_multiclass_classes": [str(value) for value in multi_a.classes_],
        "candidate_params": {key: copied[key] for key in copied if key != "n_jobs"},
        "pipeline_rule": "Benign when binary probability < 0.50; otherwise ATTACK_CLASSES[argmax], indices 0-6",
        "validation": validation,
        "controlled_suite": {
            "note": "35 specification-benign reads; not population metrics",
            "A_false_positives": suite_scores["A"]["false_positives"],
            "A_false_positive_rate": suite_scores["A"]["false_positive_rate"],
            "B_false_positives": suite_scores["B"]["false_positives"],
            "B_false_positive_rate": suite_scores["B"]["false_positive_rate"],
        },
    }
    with open(os.path.join(HERE, "pipeline_validation_metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    with open(os.path.join(HERE, "controlled_suite_pipeline_results.json"), "w", encoding="utf-8") as handle:
        json.dump(suite_scores, handle, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
