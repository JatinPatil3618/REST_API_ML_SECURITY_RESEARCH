"""Validation-only LOG4J false-negative diagnostic.

Does not open REQUEST_ONLY_test.csv, fit models, or write active artifacts.
"""

import csv
import json
import os
from urllib.parse import unquote

import joblib
import numpy as np
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
ABLATION = os.path.join(ROOT, "research", "atrdf_header_count_ablation")
TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
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
NEEDLES = ("jndi", "${", "%24%7b", "ldap:", "rmi:", "dns:")
THRESHOLD = 0.50


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
    return np.asarray(matrix, dtype=np.float64), np.asarray(labels), np.asarray(binary, dtype=np.int64)


def malicious_proba(model, matrix):
    classes = list(model.classes_)
    if classes != [0, 1] or model.n_features_in_ != 13:
        raise SystemExit(f"Unexpected binary model: classes={classes} features={model.n_features_in_}")
    return model.predict_proba(matrix)[:, 1]


def percentiles(matrix):
    if len(matrix) == 0:
        return None
    points = [0, 5, 25, 50, 75, 95, 100]
    values = np.percentile(matrix, points, axis=0)
    return {
        FEATURES[index]: {
            "min": float(values[0, index]),
            "p05": float(values[1, index]),
            "p25": float(values[2, index]),
            "median": float(values[3, index]),
            "p75": float(values[4, index]),
            "p95": float(values[5, index]),
            "max": float(values[6, index]),
            "mean": float(np.mean(matrix[:, index])),
        }
        for index in range(matrix.shape[1])
    }


def value_counts(column):
    values, counts = np.unique(column, return_counts=True)
    output = {}
    for value, count in zip(values, counts):
        key = str(int(value)) if float(value).is_integer() else str(float(value))
        output[key] = int(count)
    return output


def inside_interval(rows, low, high):
    if len(rows) == 0:
        return [None] * len(FEATURES)
    return [float(np.mean((rows[:, index] >= low[index]) & (rows[:, index] <= high[index]))) for index in range(len(FEATURES))]


def contains_marker(text):
    folded = text.lower()
    hits = [needle for needle in NEEDLES if needle in folded]
    decoded = unquote(text).lower()
    if decoded != folded:
        hits.extend(needle for needle in NEEDLES if needle in decoded and needle not in hits)
    return hits


def new_content():
    return {
        "records": 0,
        "method": {},
        "empty_body": 0,
        "marker_any": 0,
        "marker_by_needle": {needle: 0 for needle in NEEDLES},
        "marker_in_url": 0,
        "marker_in_user_agent": 0,
        "marker_in_other_header_value": 0,
        "marker_in_header_name": 0,
        "marker_in_body": 0,
        "marker_only_outside_url_ua_body": 0,
        "no_marker": 0,
        "header_names": {},
    }


def add_count(bucket, key):
    bucket[key] = bucket.get(key, 0) + 1


def inspect(record, stats, header_names):
    request = record.get("request") or {}
    headers = request.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    url = "" if request.get("url") is None else str(request.get("url"))
    body = "" if request.get("body") is None else str(request.get("body"))
    method = "" if request.get("method") is None else str(request.get("method")).strip().upper()
    user_agent = ""
    other_values = []
    names = []
    for name, value in headers.items():
        name_text = "" if name is None else str(name)
        names.append(name_text)
        if name_text.lower() == "user-agent":
            user_agent = "" if value is None else str(value)
        else:
            other_values.append("" if value is None else str(value))

    url_hits = contains_marker(url)
    ua_hits = contains_marker(user_agent)
    other_hits = []
    for value in other_values:
        other_hits.extend(contains_marker(value))
    name_hits = []
    for name in names:
        name_hits.extend(contains_marker(name))
    body_hits = contains_marker(body)
    all_hits = set(url_hits + ua_hits + other_hits + name_hits + body_hits)

    stats["records"] += 1
    add_count(stats["method"], method or "<missing>")
    if body == "":
        stats["empty_body"] += 1
    if all_hits:
        stats["marker_any"] += 1
    else:
        stats["no_marker"] += 1
    for needle in all_hits:
        stats["marker_by_needle"][needle] += 1
    if url_hits:
        stats["marker_in_url"] += 1
    if ua_hits:
        stats["marker_in_user_agent"] += 1
    if other_hits:
        stats["marker_in_other_header_value"] += 1
    if name_hits:
        stats["marker_in_header_name"] += 1
    if body_hits:
        stats["marker_in_body"] += 1
    if all_hits and not url_hits and not ua_hits and not body_hits:
        stats["marker_only_outside_url_ua_body"] += 1
    for name in names:
        if contains_marker(name):
            continue
        add_count(header_names, name.lower())


def top_names(counts, limit=12):
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [{ "name": name, "count": count } for name, count in ranked[:limit]]


def main():
    record_ids = np.load(os.path.join(HERE, "train_record_ids.npy"))
    extra = np.load(os.path.join(HERE, "train_extra_request_features.npz"))
    matrix, labels, binary = load_train()
    if len(record_ids) != len(matrix):
        raise SystemExit("record-id alignment length does not match the training CSV")

    index = np.arange(len(binary))
    train_idx, val_idx = train_test_split(
        index, test_size=0.1, random_state=42, stratify=binary
    )
    candidate = joblib.load(os.path.join(ABLATION, "candidate_a_binary_rf.joblib"))
    production = joblib.load(os.path.join(ROOT, "models", "atrdf", "atrdf_binary_rf_request_only.joblib"))
    candidate_p = malicious_proba(candidate, matrix[val_idx])
    production_p = malicious_proba(production, matrix[val_idx])

    val_labels = labels[val_idx]
    val_binary = binary[val_idx]
    val_x = matrix[val_idx]
    log4j = val_labels == "LOG4J"
    benign = val_binary == 0
    candidate_positive = candidate_p >= THRESHOLD
    tp = log4j & candidate_positive
    fn = log4j & ~candidate_positive
    if int(np.sum(log4j)) != 319 or int(np.sum(fn)) != 203 or int(np.sum(tp)) != 116:
        raise SystemExit(
            f"Unexpected Candidate A validation LOG4J split: support={int(np.sum(log4j))} "
            f"tp={int(np.sum(tp))} fn={int(np.sum(fn))}"
        )

    production_fn = log4j & ~(production_p >= THRESHOLD)
    benign_low, benign_high = np.percentile(val_x[benign], [5, 95], axis=0)
    benign_min = np.min(val_x[benign], axis=0)
    benign_max = np.max(val_x[benign], axis=0)

    def group_feature_report(mask):
        rows = val_x[mask]
        return {
            "count": int(np.sum(mask)),
            "distributions": percentiles(rows),
            "header_count": value_counts(rows[:, FEATURES.index("header_count")]),
            "cookie_present": value_counts(rows[:, FEATURES.index("cookie_present")]),
            "query_length_zero": int(np.sum(rows[:, FEATURES.index("query_length")] == 0)),
            "body_entropy_zero": int(np.sum(rows[:, FEATURES.index("request_body_entropy")] == 0)),
            "body_digits_zero": int(np.sum(rows[:, FEATURES.index("request_body_digit_count")] == 0)),
            "fraction_inside_benign_p05_p95": dict(zip(FEATURES, inside_interval(rows, benign_low, benign_high))),
            "fraction_inside_full_benign_minmax_box": float(np.mean(np.all((rows >= benign_min) & (rows <= benign_max), axis=1))),
        }

    extra_names = list(extra.keys())
    extra_val = np.column_stack([extra[name][val_idx] for name in extra_names])

    def extra_report(mask):
        rows = extra_val[mask]
        points = np.percentile(rows, [0, 50, 100], axis=0)
        return {
            extra_names[index]: {
                "min": float(points[0, index]),
                "median": float(points[1, index]),
                "max": float(points[2, index]),
                "mean": float(np.mean(rows[:, index])),
            }
            for index in range(len(extra_names))
        }

    groups = {
        "candidate_a_log4j_true_positive": np.where(tp)[0],
        "candidate_a_log4j_false_negative": np.where(fn)[0],
        "validation_benign": np.where(benign)[0],
        "train_csv_log4j": np.where(labels == "LOG4J")[0],
        "train_csv_benign": np.where(labels == "Benign")[0],
    }
    # Validation positions index val_idx; train-csv groups index the full training CSV.
    content = {name: new_content() for name in groups}
    header_names = {name: {} for name in groups}
    wanted = {}
    for name, positions in groups.items():
        if name.startswith("train_csv"):
            ids = record_ids[positions]
        else:
            ids = record_ids[val_idx[positions]]
        for record_id in ids:
            wanted.setdefault(int(record_id), []).append(name)

    with open(RAW_JSON, encoding="utf-8") as handle:
        raw_records = json.load(handle)
    missing_ids = 0
    for record_id, group_names in wanted.items():
        raw_index = record_id - 1
        if raw_index < 0 or raw_index >= len(raw_records):
            missing_ids += 1
            continue
        for group_name in group_names:
            inspect(raw_records[raw_index], content[group_name], header_names[group_name])
    del raw_records

    for name in content:
        content[name]["common_header_names"] = top_names(header_names[name])
        del content[name]["header_names"]

    result = {
        "files_opened": [
            "data/raw/atrdf/REQUEST_ONLY_train.csv",
            "research/atrdf_header_count_ablation/candidate_a_binary_rf.joblib",
            "models/atrdf/atrdf_binary_rf_request_only.joblib",
            "dataset_4_train.json",
        ],
        "files_not_opened": ["data/raw/atrdf/REQUEST_ONLY_test.csv"],
        "threshold": THRESHOLD,
        "validation_rows": int(len(val_idx)),
        "fit_rows_not_scored": int(len(train_idx)),
        "candidate_a_validation_log4j": {
            "support": int(np.sum(log4j)),
            "true_positives": int(np.sum(tp)),
            "false_negatives": int(np.sum(fn)),
            "score_min_tp": float(np.min(candidate_p[tp])),
            "score_max_fn": float(np.max(candidate_p[fn])),
            "score_median_tp": float(np.median(candidate_p[tp])),
            "score_median_fn": float(np.median(candidate_p[fn])),
        },
        "production_on_same_validation_rows": {
            "log4j_false_negatives": int(np.sum(production_fn)),
            "false_negative_ids_equal_to_candidate_a": bool(np.array_equal(fn, production_fn)),
        },
        "class_counts_train_csv": {
            "rows": int(len(labels)),
            "benign": int(np.sum(labels == "Benign")),
            "LOG4J": int(np.sum(labels == "LOG4J")),
        },
        "feature_comparison": {
            "candidate_a_log4j_true_positive": group_feature_report(tp),
            "candidate_a_log4j_false_negative": group_feature_report(fn),
            "validation_benign": group_feature_report(benign),
        },
        "engineered_request_features_excluded_from_the_13": {
            "candidate_a_log4j_true_positive": extra_report(tp),
            "candidate_a_log4j_false_negative": extra_report(fn),
            "validation_benign": extra_report(benign),
        },
        "raw_record_markers": content,
        "raw_records_missing": missing_ids,
        "note": "Marker counts are presence checks. No request body, URL, or header value is stored.",
    }
    with open(os.path.join(HERE, "log4j_fn_diagnostics.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    summary = result["candidate_a_validation_log4j"]
    print(
        f"log4j_tp={summary['true_positives']} log4j_fn={summary['false_negatives']} "
        f"same_fn_as_production={result['production_on_same_validation_rows']['false_negative_ids_equal_to_candidate_a']}"
    )
    fn_markers = content["candidate_a_log4j_false_negative"]
    print(
        "fn_marker_any={marker_any} fn_no_marker={no_marker} fn_url={marker_in_url} "
        "fn_ua={marker_in_user_agent} fn_other_header={marker_in_other_header_value} "
        "fn_body={marker_in_body} fn_only_other={marker_only_outside_url_ua_body}".format(**fn_markers)
    )


if __name__ == "__main__":
    main()
