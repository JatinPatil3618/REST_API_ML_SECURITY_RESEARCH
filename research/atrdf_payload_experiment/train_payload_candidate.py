"""Train the payload-feature ATRDF candidate on the training partition only.

Does not open REQUEST_ONLY_test.csv and does not add the live lab requests.
"""

import csv
import json
import os
import sys

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "ml_service"))

from payload_features import PAYLOAD_FEATURES, PAYLOAD_MODEL_FEATURES, PAYLOAD_THRESHOLD, payload_feature_map

FEATURES_CSV = (
    r"C:\Users\jatin\OneDrive\Documents\Desktop\TAG\New Start"
    r"\ATRDF_Research\03_Features\atrdf4_features.csv"
)
CLEAN_CSV = (
    r"C:\Users\jatin\OneDrive\Documents\Desktop\TAG\New Start"
    r"\ATRDF_Research\02_Preprocessing\atrdf4_clean.csv"
)
TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
ATTACKS = [
    "Cookie Injection",
    "Directory Traversal",
    "LOG4J",
    "Log Forging",
    "RCE",
    "SQL Injection",
    "XSS",
]
BASE_13 = PAYLOAD_MODEL_FEATURES[:13]


def train_ids_in_saved_order():
    ids, labels = [], []
    with open(FEATURES_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            ids.append(int(row["record_id"]))
            labels.append(row["label"])
    id_train, id_test, y_train, y_test = train_test_split(
        np.array(ids), np.array(labels), test_size=0.20, random_state=42, stratify=np.array(labels)
    )
    del id_test, y_test
    return [int(value) for value in id_train], [str(value) for value in y_train]


def load_saved_train():
    rows = []
    with open(TRAIN_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            rows.append(row)
    return rows


def main():
    if sklearn.__version__ != "1.2.2":
        raise SystemExit("scikit-learn is " + sklearn.__version__ + ", expected 1.2.2")
    ordered_ids, ordered_labels = train_ids_in_saved_order()
    saved = load_saved_train()
    if len(saved) != len(ordered_ids):
        raise SystemExit("train row count mismatch")
    if [row["label"] for row in saved] != ordered_labels:
        raise SystemExit("train label order does not match the saved partition")

    wanted = set(ordered_ids)
    content = {}
    with open(CLEAN_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            record_id = int(row["record_id"])
            if record_id not in wanted:
                continue
            content[record_id] = payload_feature_map(
                path=row.get("path") or "",
                query=row.get("query") or "",
                body=row.get("request_body") or "",
                user_agent=row.get("user_agent") or "",
            )
    if len(content) != len(ordered_ids):
        raise SystemExit("missing training content rows")

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
    x = np.array(x_rows, dtype=np.float64)
    y_bin = np.array(y_bin)
    y_label = np.array(y_label)

    np.random.seed(42)
    val_mask = np.random.rand(len(x)) < 0.15
    if int(val_mask.sum()) != 21972:
        raise SystemExit("validation row count is " + str(int(val_mask.sum())) + ", expected 21972")

    coverage = {}
    for label in ["Benign"] + ATTACKS:
        chosen = y_label == label
        coverage[label] = {
            name: int(x[chosen, 13 + index].sum()) for index, name in enumerate(PAYLOAD_FEATURES)
        }
        coverage[label]["rows"] = int(chosen.sum())

    x_train, x_val = x[~val_mask], x[val_mask]
    y_train, y_val = y_bin[~val_mask], y_bin[val_mask]
    label_val = y_label[val_mask]
    binary = RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42)
    binary.fit(x_train, y_train)
    proba = binary.predict_proba(x_val)[:, 1]
    pred = (proba >= PAYLOAD_THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_val, pred, labels=[0, 1]).ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(y_val, pred, average="binary", pos_label=1)
    family_recall = {}
    for label in ATTACKS:
        chosen = label_val == label
        family_recall[label] = {
            "rows": int(chosen.sum()),
            "binary_recall": float(pred[chosen].mean()) if chosen.any() else None,
        }

    mal_train = y_train == 1
    train_labels = y_label[~val_mask][mal_train]
    class_index = {name: index for index, name in enumerate(ATTACKS)}
    y_multi = np.array([class_index[label] for label in train_labels])
    multi = RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42)
    multi.fit(x_train[mal_train], y_multi)
    val_mal = y_val == 1
    multi_pred = multi.predict(x_val[val_mal])
    multi_true = np.array([class_index[label] for label in label_val[val_mal]])
    for label in ATTACKS:
        chosen = label_val == label
        detected = pred[chosen] == 1
        if detected.any():
            family_codes = multi.predict(x_val[chosen][detected])
            family_recall[label]["multiclass_recall_when_detected"] = float((family_codes == class_index[label]).mean())
        else:
            family_recall[label]["multiclass_recall_when_detected"] = None
    multiclass_accuracy = float((multi_pred == multi_true).mean())

    os.makedirs(HERE, exist_ok=True)
    joblib.dump(binary, os.path.join(HERE, "candidate_binary_rf_payload.joblib"))
    joblib.dump(multi, os.path.join(HERE, "candidate_multiclass_rf_payload.joblib"))
    metrics = {
        "sklearn": sklearn.__version__,
        "threshold": PAYLOAD_THRESHOLD,
        "features": PAYLOAD_MODEL_FEATURES,
        "train_rows": int((~val_mask).sum()),
        "validation_rows": int(val_mask.sum()),
        "held_out_test_csv": "not_opened",
        "accuracy": float((pred == y_val).mean()),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "false_positive_rate": float(fp / (fp + tn)),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "family_recall": family_recall,
        "multiclass_accuracy_on_validation_attacks": multiclass_accuracy,
        "coverage_on_training_partition": coverage,
        "binary_importances": {
            name: float(value) for name, value in zip(PAYLOAD_MODEL_FEATURES, binary.feature_importances_)
        },
    }
    with open(os.path.join(HERE, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)
    print(json.dumps({
        "accuracy": metrics["accuracy"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "false_positive_rate": metrics["false_positive_rate"],
        "confusion": metrics["confusion"],
        "family_recall": family_recall,
        "benign_flags": coverage["Benign"],
    }, indent=2))


if __name__ == "__main__":
    main()
