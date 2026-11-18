# Step 1 Verification Report — Genuine ML Inference & Honest Telemetry

**Project Root**: `E:\New folder\New folder\Downloads\API\REST_API_ML_SECURITY_RESEARCH`  
**Verified Commit**: `ddc61fd` (*Step 1 complete: Repaired genuine ML inference and removed forced predictions*)  
**Execution Environment**:
- Python: `C:\Users\Admin\anaconda3\python.exe` (Python 3.11.7, scikit-learn 1.2.2, FastAPI 0.142.2, Starlette 1.7.0, httpx 0.28.1)
- Java: OpenJDK / Java 21 with Apache Maven 3.9.8

---

## 1. Active Request Path

The end-to-end request flow for live traffic and ML inference is:

1. **Client Request**: An incoming HTTP request hits the Spring Boot Security Gateway (Port 8080) at `SecurityGatewayFilter.java`.
2. **Context & Header Separation**:
   - Headers such as `X-Test-Case-Id`, `X-Experiment-Id`, and `X-Ground-Truth` are isolated for telemetry logging only.
   - `FeatureExtractor.java` explicitly excludes test and experiment headers when calculating header counts and URL entropy.
3. **Feature Extraction**:
   - **ATRDF Route**: Extracts 13 request-only features (URL entropy, special character count, digit count, header count, etc.).
   - **BOLA Route**: `BolaSessionTracker.java` extracts 14 rolling behavioral features ($W=10$) for candidate object routes (`/api/books/\d+.*`).
4. **ML Microservice Dispatch**:
   - `MlServiceClient.java` constructs a clean JSON payload containing only `detection_mode`, `request_id`, and `atrdf_features` or `bola_features`.
   - The payload is dispatched via HTTP POST to `http://localhost:8000/predict`.
5. **Inference Execution (`ml_service/main.py`)**:
   - Microservice runs under FastAPI on port 8000 (launched via `scripts/start-all.ps1`).
   - Predictions and confidence scores are computed strictly and exclusively via `rf.predict_proba()` against frozen scikit-learn Random Forest model artifacts:
     - ATRDF Binary: `models/atrdf/atrdf_binary_rf_request_only.joblib`
     - ATRDF Multiclass: `models/atrdf/atrdf_multiclass_rf_request_only.joblib`
     - BOLA Behavioral: `models/bola/bola_rf_behavioral.joblib`
   - Unrecognized fields or caller metadata (e.g., test IDs, expected outcomes) are neither accepted in the Pydantic schema nor forwarded to the models.
6. **Decision & Mitigation**:
   - `DecisionEngine.java` inspects the genuine model probabilities and confidence from the ML response.
   - No hardcoded confidence values (`0.95` or `0.99`) are used.
   - If `BLOCK`: Gateway returns HTTP 403 (or 401 for Cookie Injection) with structured security mitigation JSON. The backend is never reached.
   - If `ALLOW`: Request is forwarded to the Demo REST API (`demo_api/server.js`, Port 5001).
7. **Backend Authorization Defense**:
   - The Demo REST API independently enforces object-level ownership checks (e.g., verifying user ownership on book update/delete) regardless of gateway classification, ensuring ML predictions cannot bypass authorization.
8. **Telemetry Logging**:
   - `SecurityGatewayFilter.java` records the event to `TelemetryService` with genuine model probabilities and confidence. `event.groundTruth` is set to `null` to prevent ground truth leakage into telemetry.

---

## 2. Executed Verification Commands & Exit Codes

| Step | Command | Working Directory | Exit Code | Result |
|------|---------|-------------------|-----------|--------|
| 1 | `C:\Users\Admin\anaconda3\python.exe scripts\test_step1_regression.py` | `E:\New folder\New folder\Downloads\API\REST_API_ML_SECURITY_RESEARCH` | `0` | **PASS** (10/10 tests) |
| 2 | `mvn -q test "-Dtest=DecisionEngineTest,FeatureExtractorTest"` | `E:\New folder\New folder\Downloads\API\REST_API_ML_SECURITY_RESEARCH\gateway` | `0` | **PASS** (7/7 tests) |

---

## 3. Actual Test Counts & Results

### Python Step 1 Regression Test Suite (`scripts/test_step1_regression.py`)
- **Total Tests Run**: 10
- **Failures**: 0
- **Errors**: 0
- **Skipped**: 0
- **Execution Time**: ~1.03 s
- **Status**: **OK**

Detailed test breakdown:
1. `test_01_models_loaded_successfully`: Confirmed `atrdf_binary`, `atrdf_multiclass`, and `bola_rf` are loaded and possess callable `predict_proba`.
2. `test_02_health_reports_pass_when_models_loaded`: Verified `/health` endpoint returns `PASS` with all three models reported.
3. `test_03_invariance_to_test_ids`: Confirmed identical features, predictions, probabilities, and confidence across 8 distinct test IDs (`None`, `NORMAL_001`, `SQLI_001`, `XSS_001`, `COOKIE_001`, `LOGFORGE_001`, `RCE_001`, `RANDOM_CUSTOM_ID`).
4. `test_04_caller_cannot_force_allow_on_attack_with_normal_id`: Verified attack feature vector with `NORMAL_001` test ID is not forced to ALLOW (decision remains `BLOCK`, prediction `MALICIOUS`).
5. `test_05_caller_cannot_force_block_on_benign_with_sqli_id`: Verified benign feature vector with `SQLI_001` test ID is not forced to BLOCK (decision remains `ALLOW`, prediction `BENIGN`).
6. `test_06_genuine_model_inference_probabilities`: Verified probabilities sum to 1.0, are not hardcoded (e.g. 0.99), and match direct scikit-learn `predict_proba()` output.
7. `test_07_bola_genuine_model_inference`: Verified BOLA probabilities sum to 1.0 and match underlying model `predict_proba()` outputs.
8. `test_08_missing_model_raises_explicit_503`: Confirmed missing model returns HTTP 503 instead of fabricating fallback predictions, and `/health` reports `DEGRADED`.
9. `test_09_ground_truth_decoupling_from_manifest`: Verified request schema excludes `expected_outcome`, `ground_truth`, `category`, and `test_case_id`.
10. `test_10_top_level_honest_confidence_provided`: Confirmed top-level confidence matches exact model class probabilities, strictly differing from fabricated constants (0.95 or 0.99).

### Gateway Java Unit Tests (`gateway`)
- **Total Tests Run**: 7
- **Failures**: 0
- **Errors**: 0
- **Skipped**: 0
- **Status**: **PASS**

#### `DecisionEngineTest` (5 tests, 0.352 s)
1. `testHonestConfidenceExtractedOnBlock`: Validates that on BLOCK decision, confidence extracted equals genuine ML probability (e.g., 0.7845) and is not fabricated to 0.95.
2. `testHonestConfidenceExtractedOnAllow`: Validates that on ALLOW decision, confidence equals genuine ML probability (e.g., 0.6521) and is not fabricated to 0.99.
3. `testNestedMulticlassDetectionConfidenceExtraction`: Validates extraction of confidence from nested multiclass detection maps.
4. `testFailSafeOnMlErrorDoesNotInventPrediction`: Confirms connection or ML error triggers documented fail-safe `ALERT` action with `UNAVAILABLE` class and `0.0` confidence.
5. `testNullResultProducesFailSafe`: Confirms null result safely triggers fail-safe `ALERT`.

#### `FeatureExtractorTest` (2 tests, 0.067 s)
1. `testTestHeadersDoNotAlterExtractedFeatures`: Confirms requests with `NORMAL_001`, `SQLI_999`, and no test ID produce identical feature vectors and identical `header_count`.
2. `testEntropyCalculationIsDeterministic`: Validates Shannon entropy calculation determinism and correctness.

---

## 4. Files Changed & Reasons

No code changes or package installs were required during this verification pass. The implementation delivered in commit `ddc61fd` was verified clean:

- `ml_service/main.py`: Houses the active production FastAPI service; inference and confidence derive exclusively from scikit-learn `predict_proba()`.
- `gateway/src/main/java/com/apisecurity/gateway/decision/DecisionEngine.java`: Extracts honest confidence from ML service responses; fail-safe ALERT produces confidence 0.0.
- `gateway/src/main/java/com/apisecurity/gateway/features/FeatureExtractor.java`: Normalizes header counts without letting test headers perturb features.
- `gateway/src/main/java/com/apisecurity/gateway/filter/SecurityGatewayFilter.java`: Decouples ground truth from incoming test case headers.
- `gateway/src/main/java/com/apisecurity/gateway/ml/MlServiceClient.java`: Sends clean feature vectors to ML service without test ID fields.
- `scripts/test_step1_regression.py`: Test suite verifying model loading, invariance, and honest confidence.
- `docs/STEP1_VERIFICATION.md`: Created to capture this audit report and verification evidence.

---

## 5. Inference Integrity & Anti-Bypass Verification

1. **Invariance**: Caller-controlled headers (`X-Test-Case-Id`, `X-Experiment-Id`, `X-Ground-Truth`) and body fields cannot alter feature vectors, class assignments, or confidence values.
2. **Honest Confidence**: All confidence values represent genuine model class probabilities rounded to 4 decimal places from scikit-learn models; fabricated static values (`0.95`, `0.99`) are eradicated.
3. **Authorization Robustness**: The backend Demo REST API (`demo_api/server.js`) strictly verifies resource ownership for state-changing operations regardless of whether the ML gateway passed the request, ensuring that false negatives from ML cannot bypass core authorization logic.
4. **Missing Model Handling**: A missing or failed model produces an explicit HTTP 503 and gateway fail-safe ALERT (confidence 0.0), never silent synthetic predictions.

---

## 6. Blockers & Operational Notes

- **Blockers for Step 1**: None. Step 1 verification is **100% complete and passing**.
- **Runtime Environment Note**: As established during audit, tests must be executed with `C:\Users\Admin\anaconda3\python.exe` (Python 3.11.7 / scikit-learn 1.2.2). The global Python 3.12 environment lacks `httpx`/`httpx2` and has an incompatible scikit-learn version (1.9.1) that cannot unpickle the frozen tree structures.
