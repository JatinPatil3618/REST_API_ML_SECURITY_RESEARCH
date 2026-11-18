# ATRDF binary header_count ablation

Temporary candidates only. The active model `models/atrdf/atrdf_binary_rf_request_only.joblib` was loaded and not overwritten (timestamp remains 08 Oct 2026 16:52). The held-out test CSV was not read. Threshold fixed at 0.50. The two live requests were not used to choose a threshold or a candidate.

## Command

```
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\run_header_count_ablation.py
```

Interpreter packages: scikit-learn 1.2.2, numpy 1.26.4. The active model metadata records scikit-learn 1.2.0.

## Split

Source: `data/raw/atrdf/REQUEST_ONLY_train.csv` only (146,213 rows).

`train_test_split(test_size=0.1, random_state=42, stratify=is_malicious)`.

| Part | Rows | Benign | Malicious |
|---|---:|---:|---:|
| Fit | 131,591 | 103,269 | 28,322 |
| Validation | 14,622 | 11,475 | 3,147 |

Validation label counts: Benign 11,475; XSS 640; SQL Injection 614; Cookie Injection 614; RCE 333; Directory Traversal 323; LOG4J 319; Log Forging 304.

Fit-set label counts: Benign 103,269; XSS 5,774; SQL Injection 5,725; Cookie Injection 5,580; Log Forging 2,926; Directory Traversal 2,828; RCE 2,822; LOG4J 2,667.

## Model settings

Copied from the loaded active forest, then fit again on this inner split:

`RandomForestClassifier(n_estimators=100, max_depth=16, min_samples_split=5, min_samples_leaf=1, max_features="sqrt", class_weight=None, random_state=42, n_jobs=-1)`.

This differs from the current `train_atrdf.py` constructor, which sets `max_depth=20`, `min_samples_leaf=2`, and `class_weight="balanced"`. The candidates follow the loaded artifact.

- Candidate A: all 13 request features. `candidate_a_binary_rf.joblib`
- Candidate B: the same features without `header_count`. `candidate_b_binary_rf_no_header_count.joblib`

## Known request vectors

Recovered from the earlier gateway rescore. Empty query and body, no cookie, user-agent entropy 4.4522.

| Feature | `/api/books` | `/api/comments/book/101` |
|---|---:|---:|
| url_entropy | 3.897587 | 4.091751 |
| path_length | 10 | 22 |
| url_special_count | 9 | 11 |
| url_length | 31 | 43 |
| path_segment_count | 2 | 4 |
| cookie_present | 0 | 0 |
| query_length | 0 | 0 |
| url_digit_count | 10 | 13 |
| user_agent_entropy | 4.4522 | 4.4522 |
| query_parameter_count | 0 | 0 |
| request_body_entropy | 0.0 | 0.0 |
| request_body_digit_count | 0 | 0 |

Missing: the exact live `header_count`. Telemetry did not store the feature map. Frozen-model scores were identical for header counts 0–9. The live gateway range under test is 2–6. Candidate A was scored at each of 2, 3, 4, 5, and 6. No single count was selected.

## Validation at 0.50

Positive class is malicious.

| Metric | Candidate A | Candidate B |
|---|---:|---:|
| Precision | 1.0 | 1.0 |
| Recall | 0.935176 | 0.904671 |
| F1 | 0.966502 | 0.949950 |
| False-positive rate | 0.0 | 0.0 |
| ROC-AUC | 0.978193 | 0.967317 |
| TN, FP, FN, TP | 11475, 0, 204, 2943 | 11475, 0, 300, 2847 |

Candidate A Gini importance for `header_count` is 0.302027, the largest of the 13 features. Next is `url_special_count` at 0.168001.

## Known benign cases at 0.50

| Case | Candidate A, header count 2–6 | Candidate B |
|---|---|---|
| `/api/books` | p=0.52, MALICIOUS at every count 2–6 | p=0.020240, BENIGN |
| `/api/comments/book/101` | p=0.650475, MALICIOUS at every count 2–6 | p=0.021141, BENIGN |

## Result

Removing `header_count` changes both known blocked requests from MALICIOUS to BENIGN at 0.50. On this validation slice, attack recall falls from 0.935176 to 0.904671 (204 false negatives to 300). False positives stay at 0. That zero rate is inside the original training distribution, whose header counts are only 5, 14, 15, and 16. It does not measure live requests with other header counts.

The active models and the 0.50 threshold were not changed.

## Limitations

- These forests are new fits on 90% of the existing training CSV. They are not the deployed model, so their probabilities are not the live scores 0.5344 and 0.75.
- The exact header count of the two gateway requests is still unknown.
- The final test split was not used, so this comparison does not estimate held-out test performance.
- Validation false-positive rate cannot show the live failure, because those short catalog requests are outside the saved header-count distribution.
