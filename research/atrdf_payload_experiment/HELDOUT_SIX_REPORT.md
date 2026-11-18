# Six-family and eight-class held-out models

The 20-feature flag forest is not the review detector. Flags reconstructed labels on the 21,041-row development mask (all binary metrics 1.0). Flags stay as review rules.

`header_count`, `url_special_count`, and `cookie_present` also force precision 1.0. They are omitted. Both forests use the remaining 10 request statistics, 100 trees, depth 16, seed 42, \(\tau = 0.50\), scikit-learn 1.2.2. XSS is dropped for Table VI and kept for Table VII. No synthetic rows. No `jndi_lookup` in the forest.

```
.venv\Scripts\python.exe research\atrdf_payload_experiment/train_six_family_heldout.py
```

## Table VI (live `models/atrdf_six/`)

Train 139,799. Official test 34,951.

| Metric | Value |
|---|---:|
| Accuracy | 0.978913 |
| Precision | 0.998197 |
| Recall | 0.883940 |
| F1 | 0.937601 |
| FPR | 0.000349 |
| TN, FP, FN, TP | 28,677, 10, 727, 5,537 |

Family misses: LOG4J 720 / 747 (recall 0.036145), Log Forging 7 / 807 (recall 0.991326). Cookie Injection, Directory Traversal, RCE, SQL Injection: recall 1.0. Live LOG4J block: `ATRDF-JNDI-LOOKUP`.

Unseen-vector slice (14,840 rows): accuracy 0.974394, precision 0.994138, recall 0.820910, F1 0.899258, TN/FP/FN/TP 12,764 / 10 / 370 / 1,696.

## Table VII (`models/atrdf_eight/`)

Train 146,213. Official test 36,554 including XSS.

| Metric | Value |
|---|---:|
| Accuracy | 0.979811 |
| Precision | 0.998462 |
| Recall | 0.907589 |
| F1 | 0.950859 |
| FPR | 0.000383 |
| TN, FP, FN, TP | 28,676, 11, 727, 7,140 |

Same 727 misses as Table VI. XSS support 1,603, recall 1.0 on this matrix, not used in six-family scope. Production `models/atrdf` was not overwritten.
