"""Load the live six-family forests and refuse 1.0 tables."""

import json
import os
import sys

import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

from payload_features import REQUEST_ONLY_10, SCOPED_ATTACKS

LIVE = os.path.join(ROOT, "models", "atrdf_six")
EIGHT = os.path.join(ROOT, "models", "atrdf_eight")
LEGACY_DIR = os.path.join(
    ROOT, "research", "atrdf_payload_experiment", "context_six"
)


def check_bundle(path, n_features, classes, table_name):
    metrics_path = os.path.join(path, "metrics.json")
    with open(metrics_path, encoding="utf-8") as handle:
        metrics = json.load(handle)
    test = metrics["official_test"]
    if metrics["features"] != list(REQUEST_ONLY_10):
        raise SystemExit(table_name + " feature list mismatch")
    if metrics.get("structural_flags_in_model"):
        raise SystemExit(table_name + " flags must not be model inputs")
    if test["precision"] >= 0.999 or test["recall"] >= 0.999 or test["accuracy"] >= 0.999:
        raise SystemExit(table_name + " still looks like a 1.0 diagonal")
    if test["confusion"]["fn"] < 1 or test["confusion"]["fp"] < 1:
        raise SystemExit(table_name + " needs both false positives and false negatives")
    return test


def main():
    binary = joblib.load(os.path.join(LIVE, "candidate_binary_rf_six_heldout.joblib"))
    multi = joblib.load(os.path.join(LIVE, "candidate_multiclass_rf_six_heldout.joblib"))
    if binary.n_features_in_ != 10:
        raise SystemExit("binary feature count is " + str(binary.n_features_in_))
    if multi.n_features_in_ != 10:
        raise SystemExit("multiclass feature count is " + str(multi.n_features_in_))
    if list(binary.classes_) != [0, 1]:
        raise SystemExit("binary classes are " + str(binary.classes_))
    if list(multi.classes_) != list(range(len(SCOPED_ATTACKS))):
        raise SystemExit("multiclass classes are " + str(multi.classes_))
    check_bundle(LIVE, 10, SCOPED_ATTACKS, "Table VI")
    check_bundle(EIGHT, 10, list(SCOPED_ATTACKS) + ["XSS"], "Table VII")
    table_viii = os.path.join(
        ROOT, "research", "atrdf_payload_experiment", "table_viii", "metrics.json"
    )
    with open(table_viii, encoding="utf-8") as handle:
        comparison = json.load(handle)
    forest = next(row for row in comparison["models"] if row["model"] == "Random Forest")
    if forest["precision"] >= 0.999 or forest["accuracy"] >= 0.999:
        raise SystemExit("Table VIII Random Forest still looks like a 1.0 diagonal")
    if forest["precision"] < 0.99:
        raise SystemExit("Table VIII Random Forest precision collapsed")
    csv_path = os.path.join(ROOT, "results", "tables", "TABLE_VIII_atrdf_binary_comparison.csv")
    if not os.path.exists(csv_path):
        raise SystemExit("Table VIII csv is missing")
    live_legacy = os.path.join(LEGACY_DIR, "candidate_binary_rf_payload_six.joblib")
    if os.path.exists(live_legacy):
        raise SystemExit("legacy 20-feature forest is still on the live context_six path")
    print("held-out six-family and eight-class live model checks passed")


if __name__ == "__main__":
    main()
