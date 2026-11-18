"""Redacted structural skeletons for missed LOG4J header values.

Stores no raw header values.
"""

import csv
import json
import os

import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from urllib.parse import unquote

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
ABLATION = os.path.join(ROOT, "research", "atrdf_header_count_ablation")
TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
RECORD_IDS = os.path.join(ABLATION, "log4j_fn_diagnostic", "train_record_ids.npy")
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
KEEP = {"jndi", "ldap", "ldaps", "http", "https", "dns", "rmi", "lower", "upper", "base64", "env"}


def load_train():
    matrix, labels, binary = [], [], []
    with open(TRAIN_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            matrix.append([float(row[name]) for name in FEATURES])
            labels.append(row["label"])
            binary.append(int(row["is_malicious"]))
    return np.asarray(matrix, dtype=np.float64), np.asarray(labels), np.asarray(binary)


def skeleton(text, start, end):
    chunk = text[start:end]
    out = []
    i = 0
    while i < len(chunk):
        char = chunk[i]
        if char.isalpha():
            j = i + 1
            while j < len(chunk) and chunk[j].isalpha():
                j += 1
            word = chunk[i:j].lower()
            out.append(word if word in KEEP else "[word]")
            i = j
        elif char.isdigit():
            while i < len(chunk) and chunk[i].isdigit():
                i += 1
            out.append("[n]")
        else:
            out.append(char)
            i += 1
    rendered = "".join(out)
    if "://" in rendered:
        rendered = rendered.split("://", 1)[0] + "://[redacted]"
    return rendered


def placement(text, marker_at):
    prefix = text[:marker_at]
    semicolons = prefix.count(";")
    if marker_at == 0:
        return "value_starts_with_marker"
    if prefix.rstrip().endswith("="):
        return "after_equals" if semicolons == 0 else "later_cookie_field"
    if semicolons:
        return "after_cookie_separator"
    return "embedded_after_other_text"


def main():
    matrix, labels, binary = load_train()
    record_ids = np.load(RECORD_IDS)
    _, val_idx = train_test_split(
        np.arange(len(binary)), test_size=0.1, random_state=42, stratify=binary
    )
    model = joblib.load(os.path.join(ABLATION, "candidate_a_binary_rf.joblib"))
    proba = model.predict_proba(matrix[val_idx])[:, 1]
    missed = val_idx[(labels[val_idx] == "LOG4J") & (proba < 0.50)]
    if len(missed) != 203:
        raise SystemExit(f"expected 203 misses, found {len(missed)}")
    wanted = {int(record_ids[position]): int(position) for position in missed}

    skeletons = {}
    placements = {}
    gaps = {}
    examples = []
    with open(RAW_JSON, encoding="utf-8") as handle:
        records = json.load(handle)
    for record_id in wanted:
        headers = (records[record_id - 1].get("request") or {}).get("headers") or {}
        for name, value in headers.items():
            text = unquote("" if value is None else str(value))
            lower = text.lower()
            if "${" not in lower or "jndi" not in lower:
                continue
            marker_at = lower.find("${")
            jndi_at = lower.find("jndi")
            gap = jndi_at - (marker_at + 2)
            key_gap = "jndi_immediately_after_prefix" if gap == 0 else f"gap_{gap}"
            place = placement(text, marker_at)
            window = skeleton(text, marker_at, marker_at + 80)
            header = str(name).lower()
            label = f"{header} | {place} | {key_gap} | {window}"
            skeletons[label] = skeletons.get(label, 0) + 1
            placements[f"{header}|{place}"] = placements.get(f"{header}|{place}", 0) + 1
            gaps[f"{header}|{key_gap}"] = gaps.get(f"{header}|{key_gap}", 0) + 1
            if len(examples) < 8 and label not in {item["skeleton"] for item in examples}:
                examples.append({
                    "header": header,
                    "placement": place,
                    "jndi_gap_after_interpolation_prefix": gap,
                    "value_length": len(text),
                    "prefix_length": marker_at,
                    "skeleton": f"{header}: [redacted prefix length {marker_at}] {window}",
                })
    del records
    result = {
        "missed_rows": 203,
        "skeleton_counts": dict(sorted(skeletons.items(), key=lambda item: -item[1])),
        "placement_counts": dict(sorted(placements.items(), key=lambda item: -item[1])),
        "gap_counts": dict(sorted(gaps.items(), key=lambda item: -item[1])),
        "examples": examples,
    }
    with open(os.path.join(HERE, "redacted_skeletons.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
