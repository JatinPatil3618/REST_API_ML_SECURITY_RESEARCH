"""Name the headers that carry the marker. Does not store header values."""

import json
import os
from urllib.parse import unquote

import numpy as np
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
RAW_JSON = (
    r"C:\Users\jatin\OneDrive\Documents\Desktop\TAG\New Start"
    r"\ATRDF_Research\01_Raw_Data\dataset_4_train\dataset_4_train.json"
)
FEATURES = [
    "url_entropy", "header_count", "path_length", "url_special_count", "url_length",
    "path_segment_count", "cookie_present", "query_length", "url_digit_count",
    "user_agent_entropy", "query_parameter_count", "request_body_entropy",
    "request_body_digit_count",
]


def hits(text):
    folded = unquote(text).lower()
    return "${" in folded, "jndi" in folded


def main():
    import csv
    root = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
    train_csv = os.path.join(root, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
    with open(train_csv, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    matrix = np.asarray([[float(row[name]) for name in FEATURES] for row in rows])
    labels = np.asarray([row["label"] for row in rows])
    binary = np.asarray([int(row["is_malicious"]) for row in rows])
    record_ids = np.load(os.path.join(HERE, "train_record_ids.npy"))
    index = np.arange(len(binary))
    _, val_idx = train_test_split(index, test_size=0.1, random_state=42, stratify=binary)
    import joblib
    model = joblib.load(os.path.join(root, "research", "atrdf_header_count_ablation", "candidate_a_binary_rf.joblib"))
    proba = model.predict_proba(matrix[val_idx])[:, 1]
    val_labels = labels[val_idx]
    log4j = val_labels == "LOG4J"
    positive = proba >= 0.50
    groups = {
        "tp": record_ids[val_idx[log4j & positive]],
        "fn": record_ids[val_idx[log4j & ~positive]],
        "benign_marker": record_ids[val_idx[(val_labels == "Benign")]],
    }
    wanted = {}
    for name, ids in groups.items():
        for record_id in ids:
            wanted.setdefault(int(record_id), name)

    name_counts = {name: {} for name in ("tp", "fn", "benign_jndi", "benign_dollar")}
    conjunction = {name: 0 for name in ("tp", "fn")}
    with open(RAW_JSON, encoding="utf-8") as handle:
        records = json.load(handle)
    for record_id, group in wanted.items():
        headers = (records[record_id - 1].get("request") or {}).get("headers") or {}
        marker_names = []
        jndi_names = []
        dollar_names = []
        for name, value in headers.items():
            dollar, jndi = hits("" if value is None else str(value))
            if dollar and jndi:
                marker_names.append(str(name).lower())
            elif jndi:
                jndi_names.append(str(name).lower())
            elif dollar:
                dollar_names.append(str(name).lower())
        if group in ("tp", "fn"):
            if marker_names:
                conjunction[group] += 1
            for name in marker_names:
                name_counts[group][name] = name_counts[group].get(name, 0) + 1
        else:
            for name in jndi_names:
                name_counts["benign_jndi"][name] = name_counts["benign_jndi"].get(name, 0) + 1
            for name in dollar_names:
                name_counts["benign_dollar"][name] = name_counts["benign_dollar"].get(name, 0) + 1

    hc = matrix[val_idx, FEATURES.index("header_count")]
    slices = {
        "tp_header_14": log4j & positive & (hc == 14),
        "tp_header_15": log4j & positive & (hc == 15),
        "tp_header_16": log4j & positive & (hc == 16),
        "fn_header_15": log4j & ~positive & (hc == 15),
        "benign_header_15": (val_labels == "Benign") & (hc == 15),
    }
    compared = ["url_entropy", "url_special_count", "url_length", "path_length", "user_agent_entropy", "query_length", "url_digit_count"]
    medians = {}
    for name, mask in slices.items():
        medians[name] = {"count": int(np.sum(mask))}
        for feature in compared:
            medians[name][feature] = float(np.median(matrix[val_idx[mask], FEATURES.index(feature)]))

    print(json.dumps({
        "conjunction_header_counts": conjunction,
        "marker_header_names": name_counts,
        "medians": medians,
    }, indent=2))


if __name__ == "__main__":
    main()
