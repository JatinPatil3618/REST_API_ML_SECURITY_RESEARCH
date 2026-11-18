# Leave-overlap-out augmentation

Exact 13-feature comparison found three augmentation vectors that match the controlled suite. Those rows were removed and one new forest was fit. The original augmentation files and candidate were not overwritten. `REQUEST_ONLY_test.csv` was not read.

## Command

```
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\benign_augmentation\leave_overlap_out\train_leave_overlap_out.py
```

Threshold 0.50. Random seed 42. Same forest settings as the earlier candidate: 100 trees, `max_depth=16`, `min_samples_leaf=1`, `max_features="sqrt"`. Fit rows: the original 131,591 plus 23 retained benign examples.

## Exact overlaps removed

Each match is equal on all 13 features. No other augmentation vector matches a suite vector.

| Removed | Augmentation request | Suite case | Suite request |
|---|---|---|---|
| A06 | `/api/books?search=database`, H2 | C30 | `/api/books?search=protocol`, H2 |
| A19 | `/api/comments/book/202`, H3 | C28 | `/api/comments/book/201`, H3 |
| A24 | `/api/comments/book/502`, H6 | C34 | `/api/comments/book/302`, H6 |

## Dataset validation, 14,622 rows

| Metric | This candidate | Candidate A |
|---|---:|---:|
| Precision | 1.0 | 1.0 |
| Recall | 0.9351763584366063 | 0.9351763584366063 |
| F1 | 0.9665024630541872 | 0.9665024630541872 |
| False-positive rate | 0.0 | 0.0 |
| TN, FP, FN, TP | 11475, 0, 204, 2943 | 11475, 0, 204, 2943 |

Per-attack binary recall: Cookie Injection, Directory Traversal, RCE, SQL Injection, and XSS are 1.0. LOG4J is 0.363636 (203 of 319 missed). Log Forging is 0.996711 (1 of 304 missed).

## Controlled suite, not a population rate

False positives: 0 of 35. With the three colliding training rows removed, none of these 35 vectors is in the retained augmentation set.

No-query probabilities for the two previously blocked routes are the same at header counts 2–6:

| Route | Probability | Decision |
|---|---:|---|
| `/api/books` | 0.1 | BENIGN |
| `/api/comments/book/101` | 0.03031828184667733 | BENIGN |

## Recommendation

More validation is needed before selection. This suite is clear after the overlap removal, and validation attack detection is unchanged from Candidate A, including LOG4J. The untouched test split has not been scored.
