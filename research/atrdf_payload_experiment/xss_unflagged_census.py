"""Count XSS request templates on the saved train/validation partition.

Does not open REQUEST_ONLY_test.csv. Prints aggregate counts only.
The validation mask is the same seed-42 split already used to train the
payload candidates, so these counts are not a fresh holdout.
"""
import csv
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "ml_service"))
sys.path.insert(0, HERE)

from payload_features import payload_feature_map
from train_payload_candidate import train_ids_in_saved_order

CLEAN = (
    r"C:\Users\jatin\OneDrive\Documents\Desktop\TAG\New Start"
    r"\ATRDF_Research\02_Preprocessing\atrdf4_clean.csv"
)


def main():
    ids, labels = train_ids_in_saved_order()
    np.random.seed(42)
    validation = np.random.rand(len(ids)) < 0.15
    role = {}
    for index, record_id in enumerate(ids):
        label = labels[index]
        if label not in ("XSS", "Benign"):
            continue
        split = "val" if validation[index] else "train"
        role[int(record_id)] = (label, split)

    counts = {
        "xss_val_markup": 0,
        "xss_val_plain": 0,
        "xss_train_markup": 0,
        "xss_train_plain": 0,
        "benign_forum": 0,
        "xss_other_path": 0,
    }
    with open(CLEAN, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            record_id = int(row["record_id"])
            item = role.get(record_id)
            if item is None:
                continue
            label, split = item
            path = row.get("path") or ""
            if label == "Benign" and path == "/forum":
                counts["benign_forum"] += 1
                continue
            if label != "XSS":
                continue
            if path != "/forum":
                counts["xss_other_path"] += 1
                continue
            flags = payload_feature_map(
                path=path,
                query=row.get("query") or "",
                body=row.get("request_body") or "",
                user_agent=row.get("user_agent") or "",
            )
            key = "xss_" + split + ("_markup" if flags["markup_script"] else "_plain")
            counts[key] += 1
    xss_val = counts["xss_val_markup"] + counts["xss_val_plain"]
    print("validation_xss", xss_val)
    print("validation_xss_with_markup", counts["xss_val_markup"])
    print("validation_xss_without_markup", counts["xss_val_plain"])
    print("train_xss_with_markup", counts["xss_train_markup"])
    print("train_xss_without_markup", counts["xss_train_plain"])
    print("benign_path_forum", counts["benign_forum"])
    print("xss_path_other_than_forum", counts["xss_other_path"])
    if xss_val:
        print("markup_rate_on_validation_xss", round(counts["xss_val_markup"] / xss_val, 4))


if __name__ == "__main__":
    main()
