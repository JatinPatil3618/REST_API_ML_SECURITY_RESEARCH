# Augmented 14-feature JNDI candidate

Temporary candidates only. `REQUEST_ONLY_test.csv` was not opened. Production models and gateway code were not changed. Threshold fixed at 0.50. Results are limited to this validation split and the 35-case suite.

## Command

```
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\jndi_feature_experiment\augmented\run_augmented_jndi_candidate.py
```

scikit-learn 1.2.2. Original fit rows 131591. Added benign rows 23. Validation rows 14622.

The 23 leave-overlap-out vectors keep their saved 13 features. `jndi_lookup_marker` was set to 0 only after the harness header values for each row's profile were checked with `\$\{\s*jndi\s*:`. None matched. Labels were not used to set the feature.

## Validation binary metrics

| Model | Precision | Recall | F1 | FPR | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Current 14-feature | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 11475 | 0 | 0 | 3147 |
| Augmented 14-feature | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 11475 | 0 | 0 | 3147 |

## Validation attack families

| Family | Current P | Current R | Current F1 | Current missed | Augmented P | Augmented R | Augmented F1 | Augmented missed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Benign | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |
| Cookie Injection | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |
| Directory Traversal | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |
| LOG4J | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |
| Log Forging | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |
| RCE | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |
| SQL Injection | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |
| XSS | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |

The 13-feature baseline still identifies 203 validation LOG4J misses. The augmented candidate detects 203 of them at the binary stage and labels 203 as LOG4J.

## Legitimate suite, case by case

Blocked: current 12 of 35, augmented 0 of 35. Marker 1 on the suite: 0.

| Case | Route | Profile | Current score | Current label | Augmented score | Augmented label |
|---|---|---|---:|---|---:|---|
| C01 | `/api/books` | H2 | 0.320000 | Benign | 0.010000 | Benign |
| C02 | `/api/comments/book/101` | H2 | 0.540000 | LOG4J | 0.000000 | Benign |
| C03 | `/api/health` | H2 | 0.390000 | Benign | 0.160000 | Benign |
| C04 | `/api/books` | H3 | 0.320000 | Benign | 0.010000 | Benign |
| C05 | `/api/comments/book/101` | H3 | 0.540000 | LOG4J | 0.000000 | Benign |
| C06 | `/api/health` | H3 | 0.390000 | Benign | 0.160000 | Benign |
| C07 | `/api/books` | H4 | 0.320000 | Benign | 0.010000 | Benign |
| C08 | `/api/comments/book/101` | H4 | 0.540000 | LOG4J | 0.000000 | Benign |
| C09 | `/api/health` | H4 | 0.390000 | Benign | 0.160000 | Benign |
| C10 | `/api/books` | H5 | 0.320000 | Benign | 0.010000 | Benign |
| C11 | `/api/comments/book/101` | H5 | 0.540000 | LOG4J | 0.000000 | Benign |
| C12 | `/api/health` | H5 | 0.390000 | Benign | 0.160000 | Benign |
| C13 | `/api/books` | H6 | 0.320000 | Benign | 0.010000 | Benign |
| C14 | `/api/comments/book/101` | H6 | 0.540000 | LOG4J | 0.000000 | Benign |
| C15 | `/api/health` | H6 | 0.390000 | Benign | 0.160000 | Benign |
| C16 | `/` | H2 | 0.652500 | XSS | 0.068000 | Benign |
| C17 | `/` | H3 | 0.652500 | XSS | 0.068000 | Benign |
| C18 | `/` | H6 | 0.652500 | XSS | 0.068000 | Benign |
| C19 | `/api/books` | H3 | 0.430000 | Benign | 0.000000 | Benign |
| C20 | `/api/books` | H3 | 0.430000 | Benign | 0.000000 | Benign |
| C21 | `/api/books` | H3 | 0.440000 | Benign | 0.000000 | Benign |
| C22 | `/api/books` | H3 | 0.430000 | Benign | 0.000000 | Benign |
| C23 | `/api/books` | H3 | 0.430000 | Benign | 0.000000 | Benign |
| C24 | `/api/books` | H3 | 0.430000 | Benign | 0.000000 | Benign |
| C25 | `/api/books` | H3 | 0.460000 | Benign | 0.037778 | Benign |
| C26 | `/api/books` | H3 | 0.430000 | Benign | 0.000000 | Benign |
| C27 | `/api/books` | H3 | 0.430000 | Benign | 0.000000 | Benign |
| C28 | `/api/comments/book/201` | H3 | 0.540000 | LOG4J | 0.000000 | Benign |
| C29 | `/api/comments/book/302` | H3 | 0.540000 | LOG4J | 0.010000 | Benign |
| C30 | `/api/books` | H2 | 0.430000 | Benign | 0.000000 | Benign |
| C31 | `/api/books` | H6 | 0.430000 | Benign | 0.000000 | Benign |
| C32 | `/api/books` | H5 | 0.440000 | Benign | 0.000000 | Benign |
| C33 | `/api/comments/book/201` | H4 | 0.540000 | LOG4J | 0.000000 | Benign |
| C34 | `/api/comments/book/302` | H6 | 0.540000 | LOG4J | 0.010000 | Benign |
| C35 | `/api/books` | H4 | 0.430000 | Benign | 0.000000 | Benign |

## Remaining false positives

The augmented candidate blocks no validation benign row and none of the 35 legitimate cases.

## Checks

- 23 retained augmentation rows use profiles H2-H6 and none of those header values match the JNDI pattern.
- jndi_lookup_marker was set to 0 on those 23 rows after that check.
- None of the 23 vectors matches a 35-case suite vector on the original 13 features.
- Previously missed LOG4J validation rows: 203. Augmented binary detections among them: 203. Augmented pipeline LOG4J labels among them: 203.
- Held-out test CSV was not opened. Active model files were loaded and not written.
