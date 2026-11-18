"""Validation-only header-pattern counts for the 203 missed LOG4J rows.

Does not open REQUEST_ONLY_test.csv, fit models, or store raw header values.
"""

import csv
import json
import os
import re
from urllib.parse import unquote

import joblib
import numpy as np
from sklearn.model_selection import train_test_split

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
FOCUS_HEADERS = ("set-cookie", "sec-fetch-dest", "sec-fetch-site", "accept-encoding", "cookie", "user-agent")
SCHEME_RE = re.compile(r"\$\{jndi:([a-z0-9]+)://", re.IGNORECASE)
BOTH_OTHER_RE = re.compile(r"\$\{", re.IGNORECASE)
JNDI_WORD_RE = re.compile(r"(?<![a-z0-9])jndi(?![a-z0-9])", re.IGNORECASE)


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


def classify_value(value):
    text = unquote("" if value is None else str(value))
    lower = text.lower()
    has_interp = "${" in lower
    has_jndi = "jndi" in lower
    scheme = None
    match = SCHEME_RE.search(text)
    if match:
        shape = "interpolation_jndi_scheme"
        scheme = match.group(1).lower()
    elif has_interp and has_jndi:
        shape = "both_tokens_other_shape"
    elif has_jndi:
        shape = "jndi_without_interpolation"
    elif has_interp:
        shape = "interpolation_without_jndi"
    else:
        shape = "neither"
    return {
        "length": len(text),
        "shape": shape,
        "scheme": scheme,
        "jndi_is_whole_token": bool(JNDI_WORD_RE.search(text)) if has_jndi else False,
        "has_equals": "=" in text,
        "starts_with_interpolation": text.startswith("${"),
    }


def empty_counts():
    return {
        "rows": 0,
        "both_tokens_in_any_header": 0,
        "jndi_without_interpolation": 0,
        "interpolation_without_jndi": 0,
        "header_present": {name: 0 for name in FOCUS_HEADERS},
        "both_tokens_by_header": {},
        "jndi_only_by_header": {},
        "shapes": {},
        "schemes": {},
        "lengths_both": [],
    }


def add(bucket, key):
    bucket[key] = bucket.get(key, 0) + 1


def consume(record, stats, example_sink, example_key):
    request = record.get("request") or {}
    headers = request.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    stats["rows"] += 1
    names = {str(name).lower(): value for name, value in headers.items()}
    for name in FOCUS_HEADERS:
        if name in names:
            stats["header_present"][name] += 1
    both_headers = []
    for name, value in names.items():
        info = classify_value(value)
        if info["shape"] == "interpolation_jndi_scheme" or info["shape"] == "both_tokens_other_shape":
            both_headers.append(name)
            add(stats["both_tokens_by_header"], name)
            add(stats["shapes"], info["shape"])
            if info["scheme"]:
                add(stats["schemes"], info["scheme"])
            stats["lengths_both"].append(info["length"])
            if example_key and len(example_sink) < 6 and info["shape"] == "interpolation_jndi_scheme":
                redacted = f"{name}: ${{jndi:{info['scheme']}://[redacted]}}"
                if redacted not in example_sink and "://" in redacted and "[redacted]" in redacted:
                    example_sink.append({
                        "group": example_key,
                        "header": name,
                        "redacted_value": redacted,
                        "value_length": info["length"],
                        "starts_with_interpolation": info["starts_with_interpolation"],
                    })
        elif info["shape"] == "jndi_without_interpolation":
            add(stats["jndi_only_by_header"], name)
            add(stats["shapes"], info["shape"] + (":whole_token" if info["jndi_is_whole_token"] else ":inside_larger_token"))
        elif info["shape"] == "interpolation_without_jndi":
            add(stats["shapes"], info["shape"])
    if both_headers:
        stats["both_tokens_in_any_header"] += 1
    if any(classify_value(value)["shape"] == "jndi_without_interpolation" for value in names.values()):
        stats["jndi_without_interpolation"] += 1
    if any(classify_value(value)["shape"] == "interpolation_without_jndi" for value in names.values()):
        stats["interpolation_without_jndi"] += 1
    return both_headers


def summarize(stats):
    lengths = stats.pop("lengths_both")
    rows = stats["rows"]
    def rate(count):
        return {"count": count, "percent_of_group": (100.0 * count / rows) if rows else None}
    stats["both_tokens_in_any_header"] = rate(stats["both_tokens_in_any_header"])
    stats["jndi_without_interpolation"] = rate(stats["jndi_without_interpolation"])
    stats["interpolation_without_jndi"] = rate(stats["interpolation_without_jndi"])
    stats["header_present"] = {name: rate(count) for name, count in stats["header_present"].items()}
    stats["both_tokens_by_header"] = {name: rate(count) for name, count in sorted(stats["both_tokens_by_header"].items())}
    stats["jndi_only_by_header"] = {name: rate(count) for name, count in sorted(stats["jndi_only_by_header"].items())}
    if lengths:
        stats["both_token_value_length"] = {
            "min": int(min(lengths)),
            "median": float(np.median(lengths)),
            "max": int(max(lengths)),
            "unique_lengths": int(len(set(lengths))),
        }
    else:
        stats["both_token_value_length"] = None
    return stats


def main():
    matrix, labels, binary = load_train()
    record_ids = np.load(RECORD_IDS)
    if len(record_ids) != len(matrix):
        raise SystemExit("record-id alignment length does not match the training CSV")
    index = np.arange(len(binary))
    _, val_idx = train_test_split(index, test_size=0.1, random_state=42, stratify=binary)
    model = joblib.load(os.path.join(ABLATION, "candidate_a_binary_rf.joblib"))
    if list(model.classes_) != [0, 1]:
        raise SystemExit("Candidate A classes are not [0, 1]")
    proba = model.predict_proba(matrix[val_idx])[:, 1]
    val_labels = labels[val_idx]
    log4j = val_labels == "LOG4J"
    missed = log4j & (proba < 0.50)
    detected = log4j & (proba >= 0.50)
    if int(np.sum(missed)) != 203 or int(np.sum(detected)) != 116:
        raise SystemExit(f"Unexpected LOG4J split tp={int(np.sum(detected))} fn={int(np.sum(missed))}")

    groups = {
        "log4j_missed": val_idx[missed],
        "log4j_detected": val_idx[detected],
        "benign": val_idx[val_labels == "Benign"],
    }
    for name in sorted(set(val_labels.tolist())):
        if name in ("LOG4J", "Benign"):
            continue
        groups[name] = val_idx[val_labels == name]

    wanted = {}
    for name, positions in groups.items():
        for record_id in record_ids[positions]:
            wanted.setdefault(int(record_id), []).append(name)

    stats = {name: empty_counts() for name in groups}
    examples = []
    fn_header_sets = []
    with open(RAW_JSON, encoding="utf-8") as handle:
        records = json.load(handle)
    for record_id, group_names in wanted.items():
        record = records[record_id - 1]
        for group_name in group_names:
            both_headers = consume(
                record,
                stats[group_name],
                examples if group_name == "log4j_missed" else [],
                group_name if group_name == "log4j_missed" else None,
            )
            if group_name == "log4j_missed":
                fn_header_sets.append(tuple(sorted(both_headers)))
    del records

    cookie_idx = FEATURES.index("cookie_present")
    header_idx = FEATURES.index("header_count")
    missed_features = {
        "cookie_present_values": {
            str(int(value)): int(count)
            for value, count in zip(*np.unique(matrix[val_idx[missed], cookie_idx], return_counts=True))
        },
        "header_count_values": {
            str(int(value)): int(count)
            for value, count in zip(*np.unique(matrix[val_idx[missed], header_idx], return_counts=True))
        },
    }
    pair_counts = {}
    for pair in fn_header_sets:
        add(pair_counts, "+".join(pair) if pair else "<none>")

    result = {
        "validation_rows": int(len(val_idx)),
        "log4j_missed": int(np.sum(missed)),
        "missed_feature_flags": missed_features,
        "missed_marker_header_combinations": pair_counts,
        "groups": {name: summarize(stats[name]) for name in stats},
        "sanitized_examples": examples,
        "files_not_opened": ["data/raw/atrdf/REQUEST_ONLY_test.csv"],
    }
    with open(os.path.join(HERE, "header_pattern_counts.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps({
        "missed": result["log4j_missed"],
        "combinations": pair_counts,
        "examples": examples,
        "group_rows": {name: result["groups"][name]["rows"] for name in result["groups"]},
        "both": {name: result["groups"][name]["both_tokens_in_any_header"] for name in result["groups"]},
    }, indent=2))


if __name__ == "__main__":
    main()
