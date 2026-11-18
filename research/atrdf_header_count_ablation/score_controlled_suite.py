"""Score Java FeatureExtractor vectors with the saved ATRDF candidates.

Does not fit models, read the held-out test CSV, or write active model files.
specification_label is used only after prediction, for the false-positive tally.
"""

import json
import os

import joblib
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
FEATURES_PATH = os.path.join(HERE, "controlled_suite_features.json")
RESULTS_PATH = os.path.join(HERE, "controlled_suite_results.json")
FEATURES = [
    "url_entropy",
    "header_count",
    "path_length",
    "url_special_count",
    "url_length",
    "path_segment_count",
    "cookie_present",
    "query_length",
    "url_digit_count",
    "user_agent_entropy",
    "query_parameter_count",
    "request_body_entropy",
    "request_body_digit_count",
]
FEATURES_B = [name for name in FEATURES if name != "header_count"]
THRESHOLD = 0.50


def malicious_probability(model, row):
    proba = model.predict_proba(row)[0]
    return float(proba[list(model.classes_).index(1)])


def main():
    with open(FEATURES_PATH, encoding="utf-8") as handle:
        document = json.load(handle)
    model_a = joblib.load(os.path.join(HERE, "candidate_a_binary_rf.joblib"))
    model_b = joblib.load(os.path.join(HERE, "candidate_b_binary_rf_no_header_count.joblib"))

    scored = []
    errors = 0
    fp_a = 0
    fp_b = 0
    for case in document["cases"]:
        features = case.get("features")
        error = case.get("extraction_error")
        if error or not isinstance(features, dict):
            errors += 1
            scored.append({
                "case_id": case["case_id"],
                "route": case["route"],
                "query": case["query"],
                "header_profile": case["header_profile"],
                "header_names": case["header_names"],
                "extraction_error": error or "missing features",
            })
            continue
        values = [float(features[name]) for name in FEATURES]
        vector_a = np.asarray([values], dtype=np.float64)
        columns_b = [FEATURES.index(name) for name in FEATURES_B]
        vector_b = vector_a[:, columns_b]
        p_a = malicious_probability(model_a, vector_a)
        p_b = malicious_probability(model_b, vector_b)
        decision_a = "MALICIOUS" if p_a >= THRESHOLD else "BENIGN"
        decision_b = "MALICIOUS" if p_b >= THRESHOLD else "BENIGN"
        if decision_a == "MALICIOUS":
            fp_a += 1
        if decision_b == "MALICIOUS":
            fp_b += 1
        scored.append({
            "case_id": case["case_id"],
            "route": case["route"],
            "query": case["query"],
            "header_profile": case["header_profile"],
            "header_names": case["header_names"],
            "extracted_header_count": features["header_count"],
            "specification_label": case["specification_label"],
            "candidate_a_p_malicious": p_a,
            "candidate_a_decision": decision_a,
            "candidate_b_p_malicious": p_b,
            "candidate_b_decision": decision_b,
            "extraction_error": None,
        })

    scored_n = len(scored) - errors
    summary = {
        "suite": "controlled benign demo reads",
        "not_population_metrics": True,
        "threshold": THRESHOLD,
        "test_csv": "not read",
        "cases": len(scored),
        "extraction_errors": errors,
        "candidate_a_false_positives": fp_a,
        "candidate_b_false_positives": fp_b,
        "candidate_a_false_positive_rate": (fp_a / scored_n) if scored_n else None,
        "candidate_b_false_positive_rate": (fp_b / scored_n) if scored_n else None,
        "results": scored,
    }
    with open(RESULTS_PATH, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    print(json.dumps({key: summary[key] for key in summary if key != "results"}, indent=2))
    for row in scored:
        print(
            row["case_id"],
            row["header_profile"],
            row["route"],
            row.get("query"),
            row.get("extracted_header_count"),
            row.get("candidate_a_decision"),
            row.get("candidate_a_p_malicious"),
            row.get("candidate_b_decision"),
            row.get("candidate_b_p_malicious"),
            row.get("extraction_error"),
        )


if __name__ == "__main__":
    main()
