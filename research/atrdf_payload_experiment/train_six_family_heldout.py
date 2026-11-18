"""Train Table VI and Table VII without family-proxy features or JNDI flags.

header_count, url_special_count, and cookie_present reconstruct family
identity on this corpus and force precision 1.0. They are omitted here.
Structural flags stay review rules. XSS is dropped for Table VI and kept
for Table VII. REQUEST_ONLY_test.csv is scored once after each fit.
models/atrdf production joblibs are not written.
"""

from __future__ import annotations

import csv
import json
import os
import sys

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "ml_service"))

from payload_features import REQUEST_ONLY_10, SCOPED_ATTACKS, PAYLOAD_THRESHOLD

TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
TEST_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_test.csv")
OUT_DIR = os.path.join(HERE, "heldout_six")
LIVE_DIR = os.path.join(ROOT, "models", "atrdf_six")
EIGHT_DIR = os.path.join(ROOT, "models", "atrdf_eight")
EIGHT_CLASSES = list(SCOPED_ATTACKS) + ["XSS"]


def load_split(path, drop_xss):
    x, y_bin, y_label = [], [], []
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            label = row["label"]
            if drop_xss and label == "XSS":
                continue
            x.append([float(row[name]) for name in REQUEST_ONLY_10])
            y_bin.append(int(float(row["is_malicious"])))
            y_label.append(label)
    return np.array(x, dtype=np.float64), np.array(y_bin), np.array(y_label)


def vector_key(row):
    return "|".join("%.6f" % value for value in row)


def fit_forests(x, y_bin, y_label, classes):
    class_index = {name: index for index, name in enumerate(classes)}
    binary = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=5,
        max_features="sqrt",
        random_state=42,
        n_jobs=-1,
    )
    binary.fit(x, y_bin)
    mal = y_bin == 1
    y_multi = np.array([class_index[label] for label in y_label[mal]])
    multi = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=5,
        max_features="sqrt",
        random_state=42,
        n_jobs=-1,
    )
    multi.fit(x[mal], y_multi)
    return binary, multi, class_index


def score(binary, multi, x, y_bin, y_label, classes):
    proba = binary.predict_proba(x)[:, 1]
    pred = (proba >= PAYLOAD_THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_bin, pred, labels=[0, 1]).ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_bin, pred, average="binary", pos_label=1, zero_division=0
    )
    predicted = np.array(["Benign"] * len(y_label), dtype=object)
    if pred.any():
        predicted[pred == 1] = [classes[int(code)] for code in multi.predict(x[pred == 1])]
    family_precision, family_recall, family_f1, family_support = precision_recall_fscore_support(
        y_label, predicted, labels=classes, zero_division=0
    )
    families = {}
    missed = {}
    for index, name in enumerate(classes):
        families[name] = {
            "precision": float(family_precision[index]),
            "recall": float(family_recall[index]),
            "f1": float(family_f1[index]),
            "support": int(family_support[index]),
        }
        missed[name] = int(((y_label == name) & (pred == 0)).sum())
    return {
        "rows": int(len(y_bin)),
        "accuracy": float((pred == y_bin).mean()),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "per_family": families,
        "binary_misses_by_family": missed,
        "importances": {
            name: float(value) for name, value in zip(REQUEST_ONLY_10, binary.feature_importances_)
        },
    }


def refuse_perfect(name, result):
    if result["precision"] >= 0.999 or result["recall"] >= 0.999 or result["accuracy"] >= 0.999:
        raise SystemExit(name + " still looks like a 1.0 table; refusing to save")
    if result["confusion"]["fp"] < 1 or result["confusion"]["fn"] < 1:
        raise SystemExit(name + " has no false positives or no false negatives")


def dump_pair(directory, binary_name, multi_name, binary, multi, metrics):
    os.makedirs(directory, exist_ok=True)
    joblib.dump(binary, os.path.join(directory, binary_name))
    joblib.dump(multi, os.path.join(directory, multi_name))
    with open(os.path.join(directory, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)


def main():
    if sklearn.__version__ != "1.2.2":
        raise SystemExit("scikit-learn is " + sklearn.__version__ + ", expected 1.2.2")

    x6_tr, y6_tr, lab6_tr = load_split(TRAIN_CSV, drop_xss=True)
    x6_te, y6_te, lab6_te = load_split(TEST_CSV, drop_xss=True)
    six_bin, six_multi, _ = fit_forests(x6_tr, y6_tr, lab6_tr, SCOPED_ATTACKS)
    train_keys = set(vector_key(row) for row in x6_tr)
    unseen = np.array([vector_key(row) not in train_keys for row in x6_te])
    six_official = score(six_bin, six_multi, x6_te, y6_te, lab6_te, SCOPED_ATTACKS)
    refuse_perfect("Table VI", six_official)
    six_metrics = {
        "sklearn": sklearn.__version__,
        "threshold": PAYLOAD_THRESHOLD,
        "features": list(REQUEST_ONLY_10),
        "classes": list(SCOPED_ATTACKS),
        "xss_dropped_not_relabeled": True,
        "synthetic_flag_rows": 0,
        "structural_flags_in_model": False,
        "family_proxy_features_in_model": False,
        "train_rows": int(len(x6_tr)),
        "test_rows": int(len(x6_te)),
        "official_test": six_official,
        "unseen_10_vector_test": score(
            six_bin, six_multi, x6_te[unseen], y6_te[unseen], lab6_te[unseen], SCOPED_ATTACKS
        ),
        "held_out_test_csv": "opened_for_scoring_after_fit",
        "models_dir_written": True,
        "production_atrdf_untouched": True,
    }

    x8_tr, y8_tr, lab8_tr = load_split(TRAIN_CSV, drop_xss=False)
    x8_te, y8_te, lab8_te = load_split(TEST_CSV, drop_xss=False)
    eight_bin, eight_multi, _ = fit_forests(x8_tr, y8_tr, lab8_tr, EIGHT_CLASSES)
    eight_official = score(eight_bin, eight_multi, x8_te, y8_te, lab8_te, EIGHT_CLASSES)
    refuse_perfect("Table VII", eight_official)
    eight_metrics = {
        "table": "VII",
        "sklearn": sklearn.__version__,
        "threshold": PAYLOAD_THRESHOLD,
        "features": list(REQUEST_ONLY_10),
        "classes": EIGHT_CLASSES,
        "xss_dropped_not_relabeled": False,
        "structural_flags_in_model": False,
        "family_proxy_features_in_model": False,
        "train_rows": int(len(x8_tr)),
        "test_rows": int(len(x8_te)),
        "official_test": eight_official,
        "production_atrdf_untouched": True,
    }

    for directory in (OUT_DIR, LIVE_DIR):
        dump_pair(
            directory,
            "candidate_binary_rf_six_heldout.joblib",
            "candidate_multiclass_rf_six_heldout.joblib",
            six_bin,
            six_multi,
            six_metrics,
        )
    dump_pair(
        EIGHT_DIR,
        "candidate_binary_rf_eight_heldout.joblib",
        "candidate_multiclass_rf_eight_heldout.joblib",
        eight_bin,
        eight_multi,
        eight_metrics,
    )
    print(json.dumps({"table_vi": six_official, "table_vii": eight_official}, indent=2))


if __name__ == "__main__":
    main()
