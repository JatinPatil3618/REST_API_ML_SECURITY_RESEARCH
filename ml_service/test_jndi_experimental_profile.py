"""Local checks for the experimental 14-feature profile. Does not read the held-out test CSV."""

import json
import os
import sys

import numpy as np
from fastapi import HTTPException

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import jndi_lookup
import main


CASES = [
    ("application/json", 0),
    ("${jndi:example}", 1),
    ("${JnDi:example}", 1),
    ("${  jndi  :example}", 1),
    ("jndi-without-lookup", 0),
    ("%24%7Bjndi:example", 1),
]
SUITE_HEADERS = {
    "H2": ["127.0.0.1:8080", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"],
    "H3": ["127.0.0.1:8080", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "application/json"],
    "H4": ["127.0.0.1:8080", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "application/json", "en-US,en;q=0.9"],
    "H5": ["127.0.0.1:8080", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "application/json", "en-US,en;q=0.9", "gzip, deflate"],
    "H6": ["127.0.0.1:8080", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "application/json", "en-US,en;q=0.9", "gzip, deflate", "keep-alive"],
}


def check(condition, message):
    if not condition:
        raise SystemExit(message)


def payload_from_features(features, marker):
    values = {name: features[name] for name in jndi_lookup.REQUEST_ONLY_13}
    values["jndi_lookup_marker"] = marker
    return main.AtrdfFeaturePayload(**values)


def test_marker_cases():
    for value, expected in CASES:
        found = jndi_lookup.jndi_lookup_marker([value])
        check(found == expected, f"marker({value!r})={found}, expected {expected}")


def test_feature_contract_and_models():
    check(jndi_lookup.EXPERIMENTAL_FEATURES[-1] == "jndi_lookup_marker", "marker is not the last feature")
    check(len(jndi_lookup.EXPERIMENTAL_FEATURES) == 14, "experimental feature list is not length 14")
    check(main.FEATURE_LISTS["atrdf"] == jndi_lookup.REQUEST_ONLY_13, "production feature list changed")
    production = main.MODELS["atrdf_binary"]
    experimental = main.MODELS["atrdf_binary_experimental"]
    experimental_multi = main.MODELS["atrdf_multiclass_experimental"]
    check(int(production.n_features_in_) == 13, "production binary is not 13 features")
    check([int(value) for value in production.classes_] == [0, 1], "production binary classes changed")
    check(int(experimental.n_features_in_) == 14, "experimental binary is not 14 features")
    check([int(value) for value in experimental.classes_] == [0, 1], "experimental binary classes are not [0, 1]")
    check(int(experimental_multi.n_features_in_) == 14, "experimental multiclass is not 14 features")
    check([int(value) for value in experimental_multi.classes_] == list(range(7)), "experimental multiclass classes are not 0-6")
    check(int(main.MODELS["atrdf_multiclass"].n_features_in_) == 13, "production multiclass is not 13 features")


def test_profile_uses_the_matching_model():
    features = {name: 0 for name in jndi_lookup.REQUEST_ONLY_13}
    features["url_entropy"] = 3.8
    features["header_count"] = 3
    features["path_length"] = 10
    features["url_length"] = 31
    seen = {}
    production = main.MODELS["atrdf_binary"]
    experimental = main.MODELS["atrdf_binary_experimental"]
    real_production = production.predict_proba
    real_experimental = experimental.predict_proba

    def watch(store, real):
        def wrapped(rows):
            store["shape"] = tuple(rows.shape)
            return real(rows)
        return wrapped

    production.predict_proba = watch(seen, real_production)
    try:
        result = main.unified_predict(main.UnifiedPredictRequest(
            atrdf_features=payload_from_features(features, 1)
        ))
    finally:
        production.predict_proba = real_production
    check(seen["shape"] == (1, 13), f"default profile shape {seen.get('shape')}")
    check(result["binary_detection"]["model_name"] == "atrdf_binary_rf_request_only", "default profile did not use the production model")

    seen.clear()
    experimental.predict_proba = lambda rows: (seen.update({"shape": tuple(rows.shape), "marker": float(rows[0, -1])}) or np.array([[0.8, 0.2]]))
    try:
        forced = main.unified_predict(main.UnifiedPredictRequest(
            model_profile="experimental-jndi",
            atrdf_features=payload_from_features(features, 1),
        ))
    finally:
        experimental.predict_proba = real_experimental
    check(seen["shape"] == (1, 14), f"experimental shape {seen.get('shape')}")
    check(seen["marker"] == 1.0, "experimental vector dropped the marker")
    check(forced["decision"] == "ALLOW", "marker alone forced a block without the model probability")
    check(forced["binary_detection"]["model_name"] == "candidate_binary_rf_jndi_augmented", "experimental response did not name the candidate")


def test_missing_features_fail_safely():
    try:
        main.unified_predict(main.UnifiedPredictRequest(model_profile="experimental-jndi"))
    except HTTPException as exc:
        check(exc.status_code == 400, f"missing features status {exc.status_code}")
    else:
        raise SystemExit("missing experimental features did not fail")
    try:
        main.unified_predict(main.UnifiedPredictRequest(model_profile="other"))
    except HTTPException as exc:
        check(exc.status_code == 400, f"unknown profile status {exc.status_code}")
    else:
        raise SystemExit("unknown profile did not fail")


def test_legitimate_suite():
    suite_path = os.path.join(ROOT, "research", "atrdf_header_count_ablation", "controlled_suite_features.json")
    with open(suite_path, encoding="utf-8") as handle:
        cases = json.load(handle)["cases"]
    check(len(cases) == 35, f"suite size {len(cases)}")
    required = {"/api/books", "/api/health", "/api/comments/book/101", "/"}
    seen_routes = set()
    blocked = []
    for case in cases:
        seen_routes.add(case["route"])
        marker = jndi_lookup.jndi_lookup_marker(SUITE_HEADERS[case["header_profile"]])
        check(marker == 0, f"{case['case_id']} harness headers match the marker")
        result = main.unified_predict(main.UnifiedPredictRequest(
            model_profile="experimental-jndi",
            request_id=case["case_id"],
            atrdf_features=payload_from_features(case["features"], marker),
        ))
        if result["decision"] != "ALLOW" or result["predicted_class"] != "BENIGN":
            blocked.append(case["case_id"])
    check(required.issubset(seen_routes), f"suite routes missing {required - seen_routes}")
    check(not blocked, "experimental profile blocked legitimate suite cases: " + ", ".join(blocked))


def main_test():
    test_marker_cases()
    test_feature_contract_and_models()
    test_profile_uses_the_matching_model()
    test_missing_features_fail_safely()
    test_legitimate_suite()
    print("python_experimental_profile_checks=PASS")


if __name__ == "__main__":
    main_test()
