"""Train Table VIII in the project: official-test binary comparison.

Ten request statistics, XSS dropped, tau=0.50. This replaces the 1.000
grouped-development comparison. Leave-one-family-out is a different file.
models/atrdf production joblibs are not written.
"""

from __future__ import annotations

import csv
import json
import os
import sys
import time

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "ml_service"))

from payload_features import PAYLOAD_THRESHOLD, REQUEST_ONLY_10

TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
TEST_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_test.csv")
OUT_DIR = os.path.join(HERE, "table_viii")
TABLE_DIR = os.path.join(ROOT, "results", "tables")
LIVE_SIX = os.path.join(ROOT, "models", "atrdf_six", "metrics.json")


def load_split(path):
    x, y = [], []
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["label"] == "XSS":
                continue
            x.append([float(row[name]) for name in REQUEST_ONLY_10])
            y.append(int(float(row["is_malicious"])))
    return np.array(x, dtype=np.float64), np.array(y)


def score_row(name, y, scores, pred, latency_ms):
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, pred, average="binary", pos_label=1, zero_division=0
    )
    return {
        "model": name,
        "accuracy": float((pred == y).mean()),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "latency_ms_per_row": float(latency_ms),
        "roc_auc": float(roc_auc_score(y, scores)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "rows": int(len(y)),
    }


def makers():
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_split=5,
            max_features="sqrt",
            random_state=42,
            n_jobs=-1,
        ),
        "Gradient boosting": HistGradientBoostingClassifier(max_depth=16, random_state=42),
        "Extra Trees": ExtraTreesClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_split=5,
            max_features="sqrt",
            random_state=42,
            n_jobs=-1,
        ),
        "Logistic regression": Pipeline(
            [
                ("scaler", StandardScaler()),
                ("clf", LogisticRegression(max_iter=2000, random_state=42)),
            ]
        ),
    }


def write_csv(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fields = [
        "model",
        "accuracy",
        "precision",
        "recall",
        "f1",
        "fpr",
        "latency_ms_per_row",
        "roc_auc",
        "tn",
        "fp",
        "fn",
        "tp",
        "rows",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main():
    if sklearn.__version__ != "1.2.2":
        raise SystemExit("scikit-learn is " + sklearn.__version__ + ", expected 1.2.2")

    x_train, y_train = load_split(TRAIN_CSV)
    x_test, y_test = load_split(TEST_CSV)
    os.makedirs(OUT_DIR, exist_ok=True)
    rows = []

    for name, model in makers().items():
        model.fit(x_train, y_train)
        t0 = time.perf_counter()
        scores = model.predict_proba(x_test)[:, 1]
        latency = (time.perf_counter() - t0) / len(x_test) * 1000.0
        pred = (scores >= PAYLOAD_THRESHOLD).astype(int)
        row = score_row(name, y_test, scores, pred, latency)
        rows.append(row)
        slug = name.lower().replace(" ", "_")
        joblib.dump(model, os.path.join(OUT_DIR, slug + ".joblib"))

    iso = IsolationForest(n_estimators=100, random_state=42, n_jobs=-1)
    iso.fit(x_train[y_train == 0])
    t0 = time.perf_counter()
    scores = -iso.score_samples(x_test)
    latency = (time.perf_counter() - t0) / len(x_test) * 1000.0
    pred = (iso.predict(x_test) == -1).astype(int)
    rows.append(score_row("Isolation Forest", y_test, scores, pred, latency))
    joblib.dump(iso, os.path.join(OUT_DIR, "isolation_forest.joblib"))

    forest = next(row for row in rows if row["model"] == "Random Forest")
    if forest["precision"] >= 0.999 or forest["recall"] >= 0.999 or forest["accuracy"] >= 0.999:
        raise SystemExit("Table VIII Random Forest still looks like a 1.0 diagonal")
    if forest["fp"] < 1 or forest["fn"] < 1:
        raise SystemExit("Table VIII Random Forest needs both false positives and false negatives")
    if os.path.exists(LIVE_SIX):
        with open(LIVE_SIX, encoding="utf-8") as handle:
            live = json.load(handle)["official_test"]
        if abs(forest["precision"] - live["precision"]) > 1e-9:
            raise SystemExit("Table VIII Random Forest does not match models/atrdf_six")

    metrics = {
        "table": "VIII",
        "sklearn": sklearn.__version__,
        "threshold": PAYLOAD_THRESHOLD,
        "features": list(REQUEST_ONLY_10),
        "xss_dropped_not_relabeled": True,
        "protocol": "official_test_10_request_features",
        "train_rows": int(len(x_train)),
        "test_rows": int(len(x_test)),
        "models": rows,
        "production_atrdf_untouched": True,
    }
    with open(os.path.join(OUT_DIR, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)
    write_csv(os.path.join(TABLE_DIR, "TABLE_VIII_atrdf_binary_comparison.csv"), rows)
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
