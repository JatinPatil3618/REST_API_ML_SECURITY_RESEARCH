"""Temporary binary Random Forest ablation: with and without header_count.

Fits candidates only. Does not read the held-out test CSV and does not
write into models/atrdf.
"""

import csv
import json
import os
from collections import Counter

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
ACTIVE_MODEL = os.path.join(ROOT, "models", "atrdf", "atrdf_binary_rf_request_only.joblib")
OUT_DIR = os.path.dirname(os.path.abspath(__file__))

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
INNER_SEED = 42
VAL_FRACTION = 0.1
THRESHOLD = 0.50

# Twelve features recovered from the gateway rescore. header_count was not stored.
# Counts 2-6 are the live range that produced the same frozen-model scores.
BOOKS_KNOWN = {
    "url_entropy": 3.897587,
    "path_length": 10,
    "url_special_count": 9,
    "url_length": 31,
    "path_segment_count": 2,
    "cookie_present": 0,
    "query_length": 0,
    "url_digit_count": 10,
    "user_agent_entropy": 4.4522,
    "query_parameter_count": 0,
    "request_body_entropy": 0.0,
    "request_body_digit_count": 0,
}
COMMENTS_KNOWN = {
    "url_entropy": 4.091751,
    "path_length": 22,
    "url_special_count": 11,
    "url_length": 43,
    "path_segment_count": 4,
    "cookie_present": 0,
    "query_length": 0,
    "url_digit_count": 13,
    "user_agent_entropy": 4.4522,
    "query_parameter_count": 0,
    "request_body_entropy": 0.0,
    "request_body_digit_count": 0,
}
HEADER_COUNT_RANGE = [2, 3, 4, 5, 6]


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
    return np.asarray(matrix, dtype=np.float64), np.asarray(labels), np.asarray(binary, dtype=np.int64)


def counts(labels, binary):
    return {
        "rows": int(len(labels)),
        "benign": int((binary == 0).sum()),
        "malicious": int((binary == 1).sum()),
        "by_label": dict(Counter(labels)),
    }


def metrics_at_threshold(y_true, proba):
    pred = (proba >= THRESHOLD).astype(np.int64)
    matrix = confusion_matrix(y_true, pred, labels=[0, 1])
    tn, fp, fn, tp = (int(matrix[0, 0]), int(matrix[0, 1]), int(matrix[1, 0]), int(matrix[1, 1]))
    negatives = tn + fp
    return {
        "threshold": THRESHOLD,
        "precision": float(precision_score(y_true, pred, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_true, pred, pos_label=1, zero_division=0)),
        "f1": float(f1_score(y_true, pred, pos_label=1, zero_division=0)),
        "false_positive_rate": float(fp / negatives) if negatives else None,
        "roc_auc": float(roc_auc_score(y_true, proba)),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def vector(known, header_count, names):
    values = dict(known)
    values["header_count"] = header_count
    return np.asarray([[values[name] for name in names]], dtype=np.float64)


def score_cases(model, names):
    rows = []
    for case_name, known in (("books", BOOKS_KNOWN), ("comments", COMMENTS_KNOWN)):
        if "header_count" in names:
            for header_count in HEADER_COUNT_RANGE:
                proba = model.predict_proba(vector(known, header_count, names))[0]
                malicious = float(proba[list(model.classes_).index(1)])
                rows.append({
                    "case": case_name,
                    "header_count": header_count,
                    "header_count_status": "unresolved_live_range",
                    "p_malicious": malicious,
                    "decision_at_0.50": "MALICIOUS" if malicious >= THRESHOLD else "BENIGN",
                })
        else:
            proba = model.predict_proba(vector(known, 0, names))[0]
            malicious = float(proba[list(model.classes_).index(1)])
            rows.append({
                "case": case_name,
                "header_count": None,
                "header_count_status": "feature_excluded",
                "p_malicious": malicious,
                "decision_at_0.50": "MALICIOUS" if malicious >= THRESHOLD else "BENIGN",
            })
    return rows


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    active = joblib.load(ACTIVE_MODEL)
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

    x, labels, binary = load_train()
    index = np.arange(len(binary))
    train_idx, val_idx = train_test_split(
        index,
        test_size=VAL_FRACTION,
        random_state=INNER_SEED,
        stratify=binary,
    )

    def fit(feature_names):
        columns = [FEATURES.index(name) for name in feature_names]
        model = RandomForestClassifier(**copied)
        model.fit(x[train_idx][:, columns], binary[train_idx])
        proba = model.predict_proba(x[val_idx][:, columns])[:, list(model.classes_).index(1)]
        return model, metrics_at_threshold(binary[val_idx], proba)

    model_a, metrics_a = fit(FEATURES)
    model_b, metrics_b = fit(FEATURES_B)

    importance = {
        name: float(value)
        for name, value in zip(FEATURES, model_a.feature_importances_)
    }

    result = {
        "sklearn": sklearn.__version__,
        "numpy": np.__version__,
        "active_model_params": {key: active_params[key] for key in copied if key != "n_jobs"},
        "candidate_params": copied,
        "inner_split": {
            "source": "REQUEST_ONLY_train.csv only",
            "test_csv": "not read",
            "test_size": VAL_FRACTION,
            "random_state": INNER_SEED,
            "stratify": "is_malicious",
            "train": counts(labels[train_idx], binary[train_idx]),
            "validation": counts(labels[val_idx], binary[val_idx]),
        },
        "candidate_a_validation": metrics_a,
        "candidate_b_validation": metrics_b,
        "candidate_a_feature_importance": importance,
        "known_requests": {
            "books": BOOKS_KNOWN,
            "comments": COMMENTS_KNOWN,
            "missing": "exact header_count; live evidence is consistent with 2-6 and frozen scores were identical for 0-9",
        },
        "candidate_a_cases": score_cases(model_a, FEATURES),
        "candidate_b_cases": score_cases(model_b, FEATURES_B),
    }

    joblib.dump(model_a, os.path.join(OUT_DIR, "candidate_a_binary_rf.joblib"))
    joblib.dump(model_b, os.path.join(OUT_DIR, "candidate_b_binary_rf_no_header_count.joblib"))
    with open(os.path.join(OUT_DIR, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
