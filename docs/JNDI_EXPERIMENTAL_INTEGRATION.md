# Experimental JNDI candidate integration

Staging only. The active 13-feature models are still the default. This run did not retrain models, did not open `REQUEST_ONLY_test.csv`, and does not establish held-out or deployment performance.

## Models

Loaded from their existing paths. Nothing under `models/atrdf/` was replaced.

| Role | Path | Checked contract |
|---|---|---|
| Production binary and multiclass | `models/atrdf/atrdf_binary_rf_request_only.joblib`, `models/atrdf/atrdf_multiclass_rf_request_only.joblib` | 13 features, binary classes `[0, 1]` |
| Experimental binary | `research/atrdf_header_count_ablation/jndi_feature_experiment/augmented/candidate_binary_rf_jndi_augmented.joblib` | 14 features, classes `[0, 1]` |
| Experimental multiclass | `research/atrdf_header_count_ablation/jndi_feature_experiment/augmented/candidate_multiclass_rf_jndi_augmented.joblib` | 14 features, classes `0`–`6` |

Checks used `.venv-repair` and scikit-learn 1.2.2. The fourteenth feature is `jndi_lookup_marker`, after the original 13. The experimental threshold in code is 0.50. A marker of 1 is passed into `predict_proba`; it does not block by itself.

`gateway.atrdf.profile` defaults to `production`. `experimental-jndi` is opt-in. The predict request field `model_profile` also defaults to `production`. An unknown profile returns HTTP 400. A missing feature payload returns HTTP 400. If the experimental files fail to load, that profile returns HTTP 503 and the production models stay available.

## Feature parity

Python `ml_service/jndi_lookup.py` and Java `FeatureExtractor` use the case-insensitive pattern `\$\{\s*jndi\s*:`. Each applies it to the raw header value and to the percent-decoded value. Test-metadata headers (`x-test-*`, `x-experiment-*`, `x-ground-truth`) are not feature inputs. Labels are not read.

The same six examples are asserted in both languages: non-match `0`, literal marker `1`, mixed case `1`, internal whitespace `1`, text without the lookup `0`, and percent-encoded marker `1`.

Production `extractAtrdfFeatures` still returns the 13-feature map. `extractAtrdfExperimentalFeatures` returns those 13 plus `jndi_lookup_marker`.

## Files changed

- `ml_service/jndi_lookup.py`
- `ml_service/main.py`
- `ml_service/test_jndi_experimental_profile.py`
- `gateway/src/main/java/com/apisecurity/gateway/features/FeatureExtractor.java`
- `gateway/src/main/java/com/apisecurity/gateway/ml/MlServiceClient.java`
- `gateway/src/main/java/com/apisecurity/gateway/filter/SecurityGatewayFilter.java`
- `gateway/src/main/resources/application.properties`
- `gateway/src/test/java/com/apisecurity/gateway/features/JndiLookupMarkerTest.java`
- `gateway/src/test/java/com/apisecurity/gateway/filter/MlUnavailableGatewayTest.java`

## Tests

| Command | Result |
|---|---|
| `.venv-repair\Scripts\python.exe ml_service\test_jndi_experimental_profile.py` | PASS |
| `mvn test -Dtest=JndiLookupMarkerTest,MlUnavailableGatewayTest,FeatureExtractorTest,DecisionEngineTest` | PASS, exit 0 |

Java counts from this run: `JndiLookupMarkerTest` 4/4, `MlUnavailableGatewayTest` 3/3, `FeatureExtractorTest` 8/8, `DecisionEngineTest` 5/5. No failures.

The Python check scored all 35 saved legitimate-suite vectors, including `/api/books`, `/api/health`, `/api/comments/book/101`, and `/`, through the experimental profile with marker 0. All 35 were ALLOW / BENIGN. That repeats the candidate's existing suite result through the new inference function. It is not a new held-out measurement.

When the ML client reports that prediction is unavailable, the gateway does not grant the request. The filter still forwards it, and a backend 401 is preserved. The production profile does not call the experimental extractor.

## Known live miss

REQ-1004, `GET /api/books` on the experimental gateway with a synthetic lookup header, used the same 14 feature values in Java and Python. `candidate_binary_rf_jndi_augmented` scored malicious probability 0.43. The 0.50 threshold allowed it. This is a recorded experimental miss. The threshold and the production models were not changed, and the marker was not turned into a block rule.

## Remaining limits

The experimental profile is not the running default. These tests do not start the live gateway, and they do not measure the locked test split. Backend authentication still decides protected routes after an ML failure. Moving or failing to load the research joblib files disables only the experimental profile.
