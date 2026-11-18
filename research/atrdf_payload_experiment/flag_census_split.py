"""Flag coverage on the seed-42 80/20 split. Does not fit a model."""

import csv
import os
import sys
from collections import Counter

import numpy as np
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "ml_service"))

from payload_features import PAYLOAD_FEATURES, payload_feature_map

FEATURES_CSV = (
    r"C:\Users\jatin\OneDrive\Documents\Desktop\TAG\New Start"
    r"\ATRDF_Research\03_Features\atrdf4_features.csv"
)
CLEAN_CSV = (
    r"C:\Users\jatin\OneDrive\Documents\Desktop\TAG\New Start"
    r"\ATRDF_Research\02_Preprocessing\atrdf4_clean.csv"
)
SCOPED = {
    "Cookie Injection",
    "Directory Traversal",
    "LOG4J",
    "Log Forging",
    "RCE",
    "SQL Injection",
}


def main():
    ids, labels = [], []
    with open(FEATURES_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            ids.append(int(row["record_id"]))
            labels.append(row["label"])
    id_train, id_test, y_train, y_test = train_test_split(
        np.array(ids), np.array(labels), test_size=0.20, random_state=42, stratify=np.array(labels)
    )
    test_ids = set(int(v) for v in id_test)
    content = {}
    with open(CLEAN_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            record_id = int(row["record_id"])
            if record_id not in test_ids:
                continue
            content[record_id] = row
    print("test rows", len(id_test), "clean hits", len(content))
    scoped_attack = 0
    flagged = 0
    unflagged_by = Counter()
    benign = 0
    benign_flagged = 0
    xss = 0
    for record_id, label in zip(id_test, y_test):
        label = str(label)
        if label == "XSS":
            xss += 1
            continue
        row = content[int(record_id)]
        flags = payload_feature_map(
            path=row.get("path") or "",
            query=row.get("query") or "",
            body=row.get("request_body") or "",
            user_agent=row.get("user_agent") or "",
        )
        any_flag = any(flags[name] for name in PAYLOAD_FEATURES)
        if label == "Benign":
            benign += 1
            benign_flagged += int(any_flag)
            continue
        if label not in SCOPED:
            continue
        scoped_attack += 1
        flagged += int(any_flag)
        if not any_flag:
            unflagged_by[label] += 1
    print("xss dropped", xss)
    print("benign", benign, "benign flagged from path/query/body/ua", benign_flagged)
    print("scoped attacks", scoped_attack, "flagged without headers", flagged)
    print("unflagged without headers", dict(unflagged_by))


if __name__ == "__main__":
    main()
