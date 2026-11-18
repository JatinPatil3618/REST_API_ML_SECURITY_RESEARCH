"""One locked scoring pass of the untouched ATRDF test split.

Does not fit models and does not write models/atrdf.
"""

import csv
import json
import os

import joblib
import numpy as np
import sklearn
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support, precision_score, recall_score

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
ABLATION = os.path.join(ROOT, "research", "atrdf_header_count_ablation")
TEST_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_test.csv")
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
CLASS_ORDER = ["Benign"] + ATTACK_CLASSES
THRESHOLD = 0.50
REMOVED_OVERLAPS = {"A06", "A19", "A24"}


def load_test():
    with open(TEST_CSV, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames[:13] != FEATURES:
            raise SystemExit("Test CSV feature order does not match the 13-feature contract.")
        if reader.fieldnames[13:] != ["label", "is_malicious"]:
            raise SystemExit(f"Unexpected test columns after features: {reader.fieldnames[13:]}")
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


def vector_key(values):
    return tuple(float(value) for value in values)


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
    matrix = confusion_matrix(y_true, pred, labels=[0, 1])
    tn, fp, fn, tp = [int(value) for value in matrix.ravel()]
    return {
        "threshold": THRESHOLD,
        "precision": float(precision_score(y_true, pred, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_true, pred, pos_label=1, zero_division=0)),
        "f1": float(f1_score(y_true, pred, pos_label=1, zero_division=0)),
        "false_positive_rate": float(fp / (tn + fp)) if (tn + fp) else None,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "benign_incorrectly_blocked": fp,
        "attacks_missed_at_binary_stage": fn,
    }


def pipeline_report(y_labels, y_binary, proba, families):
    positive = proba >= THRESHOLD
    combined = np.where(positive, families, "Benign")
    matrix = confusion_matrix(y_labels, combined, labels=CLASS_ORDER)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_labels, combined, labels=CLASS_ORDER, zero_division=0
    )
    missed = (y_labels != "Benign") & ~positive
    missed_by_label = {
        label: int(np.sum(missed & (y_labels == label)))
        for label in ATTACK_CLASSES
    }
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
        "binary": binary_metrics(y_binary, proba),
        "class_order": CLASS_ORDER,
        "confusion_matrix": matrix.astype(int).tolist(),
        "per_class": per_class,
        "attacks_missed_at_binary_stage_by_label": missed_by_label,
        "binary_malicious_then_labeled_benign": int(np.sum((y_labels != "Benign") & positive & (combined == "Benign"))),
    }


def augmentation_overlap(test_matrix):
    with open(os.path.join(ABLATION, "benign_augmentation", "augmentation_features.json"), encoding="utf-8") as handle:
        rows = json.load(handle)
    retained = [row for row in rows if row["case_id"] not in REMOVED_OVERLAPS]
    if len(retained) != 23 or len(rows) - len(retained) != 3:
        raise SystemExit("Retained augmentation count is not 23.")
    lookup = {}
    for index, values in enumerate(test_matrix):
        lookup.setdefault(vector_key(values), []).append(int(index))
    overlaps = []
    for row in retained:
        hits = lookup.get(vector_key([row["features"][name] for name in FEATURES]), [])
        if hits:
            overlaps.append({
                "augmentation_case_id": row["case_id"],
                "equal_on_all_13": True,
                "test_row_indexes": hits,
                "test_row_count": len(hits),
            })
    return overlaps


def main():
    production_binary = joblib.load(os.path.join(ROOT, "models", "atrdf", "atrdf_binary_rf_request_only.joblib"))
    production_multi = joblib.load(os.path.join(ROOT, "models", "atrdf", "atrdf_multiclass_rf_request_only.joblib"))
    candidate_binary = joblib.load(os.path.join(ABLATION, "candidate_a_binary_rf.joblib"))
    candidate_multi = joblib.load(os.path.join(ABLATION, "candidate_a_multiclass_rf.joblib"))
    augmented_binary = joblib.load(os.path.join(
        ABLATION, "benign_augmentation", "leave_overlap_out", "candidate_binary_rf_leave_overlap_out.joblib"
    ))
    for model in (production_binary, candidate_binary, augmented_binary):
        if list(model.classes_) != [0, 1] or int(model.n_features_in_) != 13:
            raise SystemExit("A binary candidate does not have classes [0, 1] and 13 features.")
    for model in (production_multi, candidate_multi):
        if list(model.classes_) != list(range(7)) or int(model.n_features_in_) != 13:
            raise SystemExit("A multiclass model does not have classes 0-6 and 13 features.")

    x, labels, binary = load_test()
    inconsistent = int(np.sum((labels == "Benign") != (binary == 0)))
    if inconsistent:
        raise SystemExit(f"label and is_malicious disagree on {inconsistent} test rows.")
    unknown = sorted(set(labels) - set(CLASS_ORDER))
    if unknown:
        raise SystemExit(f"Unexpected test labels: {unknown}")

    distribution = {label: int(np.sum(labels == label)) for label in CLASS_ORDER}
    systems = {
        "production": pipeline_report(
            labels, binary,
            malicious_probability(production_binary, x),
            attack_family(production_multi, x),
        ),
        "candidate_a": pipeline_report(
            labels, binary,
            malicious_probability(candidate_binary, x),
            attack_family(candidate_multi, x),
        ),
        "leave_overlap_out": pipeline_report(
            labels, binary,
            malicious_probability(augmented_binary, x),
            attack_family(candidate_multi, x),
        ),
    }
    result = {
        "sklearn": sklearn.__version__,
        "threshold": THRESHOLD,
        "test_rows": int(len(labels)),
        "class_distribution": distribution,
        "malicious_rows": int(np.sum(binary == 1)),
        "benign_rows": int(np.sum(binary == 0)),
        "augmentation_test_feature_overlaps": augmentation_overlap(x),
        "controlled_suite_included": False,
        "models_fitted_in_this_script": False,
        "systems": systems,
    }
    with open(os.path.join(HERE, "final_test_metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
