# Machine Learning Model Specification

## 1. Algorithmic Choice: Random Forest vs. Logistic Regression
- **Primary Algorithm**: Random Forest (`RandomForestClassifier`)
  - **Rationale**: The input feature space contains highly non-linear, interacting boundaries between Shannon entropy, character lengths, digit ratios, and structural counters. Random Forest captures these threshold interactions without overfitting and provides microsecond-level CPU inference latency suitable for inline gateway evaluation.
  - **Hyperparameters**:
    - `n_estimators`: 100
    - `max_depth`: 16 (ATRDF) / 12 (BOLA)
    - `min_samples_split`: 5 (ATRDF) / 4 (BOLA)
    - `random_state`: 42
    - `n_jobs`: -1
- **Baseline Algorithm**: Logistic Regression (`LogisticRegression`)
  - **Rationale**: Establishes a standard linear benchmark to quantify the performance gains afforded by non-linear decision forests.
  - **Hyperparameters**: `max_iter=1000`, `random_state=42`, standardized inputs.

---

## 2. Model Inventory & Persistence Artifacts

| Component | Target Artifact | Algorithm | Input Feature Set |
| :--- | :--- | :--- | :--- |
| **ATRDF Binary** | `models/atrdf/atrdf_binary_rf_request_only.joblib` | Random Forest | 13 Request-Only Features |
| **ATRDF Binary Baseline**| `models/atrdf/atrdf_binary_lr_request_only.joblib` | Logistic Regression | 13 Request-Only (Scaled) |
| **ATRDF Multiclass** | `models/atrdf/atrdf_multiclass_rf_request_only.joblib` | Random Forest | 13 Request-Only Features |
| **ATRDF Multiclass Baseline** | `models/atrdf/atrdf_multiclass_lr_request_only.joblib`| Logistic Regression | 13 Request-Only (Scaled) |
| **BOLA Session** | `models/bola/bola_rf_behavioral.joblib` | Random Forest | 14 Behavioral Window Features |
| **BOLA Session Baseline** | `models/bola/bola_lr_behavioral.joblib` | Logistic Regression | 14 Behavioral (Scaled) |

---

## 3. Threshold Calibration Strategy
The test set is completely frozen and untouched during tuning. The ATRDF binary model was calibrated on an independent validation set (15% split of the training corpus). The optimal decision threshold was identified as **0.30**, which maximizes the validation F1-score ($0.9708$).
