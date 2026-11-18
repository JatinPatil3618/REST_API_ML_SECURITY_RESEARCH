"""Score the frozen six-family candidate on REQUEST_ONLY_test.csv.

Does not fit a model and does not write files under models/.
XSS rows are dropped, not relabeled. Threshold stays 0.50.
Flags come from the clean request text for the official test ids.
Raw JSON header scanning is not used in this pass, so header-only LOG4J
markers are not injected into the score.
"""

import csv
import json
import os
import sys

import joblib
import numpy as np
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "ml_service"))

from payload_features import (
    PAYLOAD_FEATURES,
    PAYLOAD_THRESHOLD,
    REQUEST_ONLY_13,
    SCOPED_ATTACKS,
    payload_feature_map,
)

FEATURES_CSV = (
    r"C:\Users\jatin\OneDrive\Documents\Desktop\TAG\New Start"
    r"\ATRDF_Research\03_Features\atrdf4_features.csv"
)
CLEAN_CSV = (
    r"C:\Users\jatin\OneDrive\Documents\Desktop\TAG\New Start"
    r"\ATRDF_Research\02_Preprocessing\atrdf4_clean.csv"
)
TEST_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_test.csv")
TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
BINARY = os.path.join(HERE, "context_six", "candidate_binary_rf_payload_six.joblib")
MULTI = os.path.join(HERE, "context_six", "candidate_multiclass_rf_payload_six.joblib")
OUT = os.path.join(HERE, "context_six", "official_test_metrics.json")


def vector_key(values):
    return "|".join("%.6f" % float(v) for v in values)


def main():
    ids, labels = [], []
    with open(FEATURES_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            ids.append(int(row["record_id"]))
            labels.append(row["label"])
    _, id_test, _, y_test = train_test_split(
        np.array(ids), np.array(labels), test_size=0.20, random_state=42, stratify=np.array(labels)
    )
    content = {}
    wanted = set(int(v) for v in id_test)
    with open(CLEAN_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            record_id = int(row["record_id"])
            if record_id in wanted:
                content[record_id] = row
    test_rows = []
    with open(TEST_CSV, newline="", encoding="utf-8") as handle:
        test_rows = list(csv.DictReader(handle))
    if [row["label"] for row in test_rows] != [str(v) for v in y_test]:
        raise SystemExit("REQUEST_ONLY_test.csv is not aligned with the seed-42 split")

    train_keys = set()
    with open(TRAIN_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            train_keys.add(vector_key([row[name] for name in REQUEST_ONLY_13]))

    x_rows, y_bin, y_label, unseen = [], [], [], []
    for record_id, saved, label in zip(id_test, test_rows, y_test):
        label = str(label)
        if label == "XSS":
            continue
        clean = content[int(record_id)]
        flags = payload_feature_map(
            path=clean.get("path") or "",
            query=clean.get("query") or "",
            body=clean.get("request_body") or "",
            user_agent=clean.get("user_agent") or "",
        )
        values = [float(saved[name]) for name in REQUEST_ONLY_13]
        values.extend(float(flags[name]) for name in PAYLOAD_FEATURES)
        x_rows.append(values)
        y_bin.append(int(float(saved["is_malicious"])))
        y_label.append(label)
        unseen.append(vector_key([saved[name] for name in REQUEST_ONLY_13]) not in train_keys)

    x = np.array(x_rows, dtype=np.float64)
    y_bin = np.array(y_bin)
    y_label = np.array(y_label)
    unseen = np.array(unseen)
    binary = joblib.load(BINARY)
    multi = joblib.load(MULTI)

    def score(mask, split_name):
        xx, yy, ll = x[mask], y_bin[mask], y_label[mask]
        proba = binary.predict_proba(xx)[:, 1]
        pred = (proba >= PAYLOAD_THRESHOLD).astype(int)
        tn, fp, fn, tp = confusion_matrix(yy, pred, labels=[0, 1]).ravel()
        precision, recall, f1, _ = precision_recall_fscore_support(
            yy, pred, average="binary", pos_label=1, zero_division=0
        )
        predicted = np.array(["Benign"] * len(ll), dtype=object)
        if pred.any():
            predicted[pred == 1] = [SCOPED_ATTACKS[int(code)] for code in multi.predict(xx[pred == 1])]
        family_precision, family_recall, family_f1, family_support = precision_recall_fscore_support(
            ll, predicted, labels=SCOPED_ATTACKS, zero_division=0
        )
        families = {}
        for index, name in enumerate(SCOPED_ATTACKS):
            families[name] = {
                "precision": float(family_precision[index]),
                "recall": float(family_recall[index]),
                "f1": float(family_f1[index]),
                "support": int(family_support[index]),
            }
        return {
            "split": split_name,
            "rows": int(mask.sum()),
            "accuracy": float((pred == yy).mean()),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
            "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "per_family": families,
        }

    all_mask = np.ones(len(x), dtype=bool)
    report = {
        "threshold": PAYLOAD_THRESHOLD,
        "xss_dropped_not_relabeled": True,
        "raw_json_headers_scanned": False,
        "development_mask_1_0_withdrawn": True,
        "official_test_six_family": score(all_mask, "official_test_xss_dropped"),
        "unseen_13_vector_six_family": score(unseen, "official_test_unseen_13_vector"),
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
