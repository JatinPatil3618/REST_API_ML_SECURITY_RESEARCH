"""Validation-only threshold sweep. Does not read REQUEST_ONLY_test.csv or fit models."""

import csv
import json
import os

import joblib
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
ABLATION = os.path.join(ROOT, "research", "atrdf_header_count_ablation")
TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
FEATURES = [
    "url_entropy", "header_count", "path_length", "url_special_count", "url_length",
    "path_segment_count", "cookie_present", "query_length", "url_digit_count",
    "user_agent_entropy", "query_parameter_count", "request_body_entropy",
    "request_body_digit_count",
]
ATTACKS = [
    "Cookie Injection", "Directory Traversal", "LOG4J", "Log Forging",
    "RCE", "SQL Injection", "XSS",
]
GRID = [round(0.05 * step, 2) for step in range(1, 20)]


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
    return np.asarray(matrix), np.asarray(labels), np.asarray(binary, dtype=np.int64)


def metrics_at(labels, binary, proba, threshold):
    pred = proba >= threshold
    pred_int = pred.astype(np.int64)
    tn, fp, fn, tp = [int(value) for value in confusion_matrix(binary, pred_int, labels=[0, 1]).ravel()]
    attack_recall = {}
    for name in ATTACKS:
        mask = labels == name
        attack_recall[name] = {
            "support": int(np.sum(mask)),
            "recall": float(np.sum(mask & pred) / np.sum(mask)),
            "missed": int(np.sum(mask & ~pred)),
        }
    return {
        "threshold": threshold,
        "precision": float(precision_score(binary, pred_int, pos_label=1, zero_division=0)),
        "recall": float(recall_score(binary, pred_int, pos_label=1, zero_division=0)),
        "f1": float(f1_score(binary, pred_int, pos_label=1, zero_division=0)),
        "false_positive_rate": float(fp / (tn + fp)) if tn + fp else None,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "benign_blocked": fp,
        "per_attack_recall": attack_recall,
    }


def recommend(labels, binary, proba):
    """Max validation attack recall among thresholds with FPR 0.

    The largest such threshold is used when several give the same decisions.
    """
    benign = proba[binary == 0]
    attacks = proba[binary == 1]
    max_benign = float(np.max(benign))
    recoverable = attacks[attacks > max_benign]
    if len(recoverable) == 0:
        return {"threshold": None, "reason": "No attack score exceeds the maximum benign score."}
    threshold = float(np.min(recoverable))
    return {
        "criterion": "maximum validation attack recall subject to validation FPR 0; largest threshold with those decisions",
        "max_benign_p_malicious": max_benign,
        "threshold": threshold,
        "attacks_recoverable_at_fpr_0": int(len(recoverable)),
        "attacks_not_separable_from_benign": int(np.sum(attacks <= max_benign)),
    }


def suite_at(proba, thresholds):
    rows = []
    for threshold in thresholds:
        blocked = int(np.sum(proba >= threshold))
        rows.append({
            "threshold": threshold,
            "benign_cases_blocked": blocked,
            "cases": int(len(proba)),
            "false_positive_rate_on_this_suite_only": blocked / len(proba),
        })
    return rows


def main():
    x, labels, binary = load_train()
    index = np.arange(len(binary))
    train_idx, val_idx = train_test_split(
        index, test_size=0.1, random_state=42, stratify=binary
    )
    if len(train_idx) != 131591 or len(val_idx) != 14622:
        raise SystemExit("Validation split size does not match the saved experiment split.")
    y = binary[val_idx]
    y_labels = labels[val_idx]
    x_val = x[val_idx]

    models = {
        "production": joblib.load(os.path.join(ROOT, "models", "atrdf", "atrdf_binary_rf_request_only.joblib")),
        "leave_overlap_out": joblib.load(os.path.join(
            ABLATION, "benign_augmentation", "leave_overlap_out",
            "candidate_binary_rf_leave_overlap_out.joblib",
        )),
    }
    with open(os.path.join(ABLATION, "controlled_suite_features.json"), encoding="utf-8") as handle:
        suite = json.load(handle)["cases"]
    suite_x = np.asarray([[float(case["features"][name]) for name in FEATURES] for case in suite])

    systems = {}
    for name, model in models.items():
        if list(model.classes_) != [0, 1]:
            raise SystemExit(f"{name} binary classes_ are not [0, 1].")
        proba = model.predict_proba(x_val)[:, 1]
        suite_proba = model.predict_proba(suite_x)[:, 1]
        choice = recommend(y_labels, y, proba)
        thresholds = list(GRID)
        if choice["threshold"] is not None and choice["threshold"] not in thresholds:
            thresholds.append(choice["threshold"])
        thresholds = sorted(set(thresholds))
        systems[name] = {
            "validation_rows": int(len(y)),
            "score_min": float(np.min(proba)),
            "score_max": float(np.max(proba)),
            "max_benign_p_malicious": float(np.max(proba[y == 0])),
            "recommendation_from_validation_only": choice,
            "validation_sweep": [metrics_at(y_labels, y, proba, threshold) for threshold in thresholds],
            "controlled_suite_diagnostic_not_used_for_selection": suite_at(suite_proba, thresholds),
        }

    result = {
        "test_csv": "not read",
        "split": "REQUEST_ONLY_train.csv train_test_split test_size=0.1 random_state=42 stratify=is_malicious",
        "fit_rows_excluded_from_scoring": 131591,
        "validation_rows": 14622,
        "saved_probability_files": "none; probabilities recomputed from frozen models",
        "production_split_note": "Production metadata records 124241 training and 21972 validation rows, so this 14622-row split is not that model's original holdout.",
        "systems": systems,
    }
    with open(os.path.join(HERE, "threshold_sweep.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    summary = {}
    for name, system in systems.items():
        summary[name] = {
            "max_benign_p_malicious": system["max_benign_p_malicious"],
            "recommendation": system["recommendation_from_validation_only"],
            "at_0.50": next(row for row in system["validation_sweep"] if row["threshold"] == 0.5),
            "at_recommended": next(
                row for row in system["validation_sweep"]
                if row["threshold"] == system["recommendation_from_validation_only"]["threshold"]
            ),
        }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
