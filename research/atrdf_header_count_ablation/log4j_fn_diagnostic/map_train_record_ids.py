"""Align REQUEST_ONLY_train.csv rows to raw record_id values.

Replays the original 80/20 split from atrdf4_features.csv. Does not open
REQUEST_ONLY_test.csv and does not write the held-out ids.
"""

import os

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
TRAIN_CSV = os.path.join(ROOT, "data", "raw", "atrdf", "REQUEST_ONLY_train.csv")
FEATURES_CSV = (
    r"C:\Users\jatin\OneDrive\Documents\Desktop\TAG\New Start"
    r"\ATRDF_Research\03_Features\atrdf4_features.csv"
)
FEATURES = [
    "url_entropy", "header_count", "path_length", "url_special_count", "url_length",
    "path_segment_count", "cookie_present", "query_length", "url_digit_count",
    "user_agent_entropy", "query_parameter_count", "request_body_entropy",
    "request_body_digit_count",
]
EXTRA = [
    "request_body_length",
    "request_body_special_count",
    "user_agent_length",
    "content_type_present",
    "authorization_present",
    "decoded_url_length",
]


def main():
    features = pd.read_csv(FEATURES_CSV)
    train = pd.read_csv(TRAIN_CSV)
    missing = [name for name in FEATURES + EXTRA + ["record_id", "label"] if name not in features.columns]
    if missing:
        raise SystemExit("Feature file is missing columns: " + ", ".join(missing))

    predictor = features.drop(columns=["record_id", "label", "is_malicious"])
    ids = features["record_id"].to_numpy()
    x_train, x_test, y_train, y_test, id_train, id_test = train_test_split(
        predictor,
        features["label"],
        ids,
        test_size=0.20,
        random_state=42,
        stratify=features["label"],
    )
    del x_test, y_test, id_test

    aligned = x_train[FEATURES].to_numpy(dtype=np.float64)
    saved = train[FEATURES].to_numpy(dtype=np.float64)
    max_abs = float(np.max(np.abs(aligned - saved)))
    labels_match = bool(np.array_equal(y_train.to_numpy(), train["label"].to_numpy()))
    if max_abs > 1e-8 or not labels_match or len(id_train) != len(train):
        raise SystemExit(
            f"Train alignment failed: max_abs={max_abs} labels_match={labels_match} "
            f"rows={len(id_train)}/{len(train)}"
        )

    id_train = np.asarray(id_train, dtype=np.int64)
    np.save(os.path.join(HERE, "train_record_ids.npy"), id_train)
    np.savez(
        os.path.join(HERE, "train_extra_request_features.npz"),
        **{name: x_train[name].to_numpy(dtype=np.float64) for name in EXTRA},
    )
    print(f"aligned_train_rows={len(id_train)} max_abs_diff={max_abs} labels_match={labels_match}")
    print("held_out_test_csv=not_opened held_out_ids=not_written")


if __name__ == "__main__":
    main()
