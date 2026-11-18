# Locked ATRDF test evaluation

One scoring pass. No model was fit and no threshold was changed. The 35-case suite is not part of these numbers.

## Provenance

`run_header_count_ablation.py`, `run_multiclass_pipeline.py`, `train_augmented_binary.py`, and `train_leave_overlap_out.py` open only `data/raw/atrdf/REQUEST_ONLY_train.csv`. None of those scripts references `REQUEST_ONLY_test.csv`. The production artifacts were already frozen; this run only loaded them.

## Command

```
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\final_test_evaluation\evaluate_final_test.py
```

Exit code 0. scikit-learn 1.2.2. Threshold 0.50 for every system.

## Test split

36,554 rows. Columns are the 13 request features, then `label` and `is_malicious`. Those two label fields agree on every row.

| Label | Rows |
|---|---:|
| Benign | 28687 |
| Cookie Injection | 1548 |
| Directory Traversal | 788 |
| LOG4J | 747 |
| Log Forging | 807 |
| RCE | 789 |
| SQL Injection | 1585 |
| XSS | 1603 |

Malicious rows: 7,867. Benign rows: 28,687.

The 23 benign vectors used to train the leave-overlap-out candidate have no exact 13-feature match in this test split. No test row was removed.

## Systems

- Production: active binary forest and active multiclass forest. Multiclass `classes_` are `[0, 1, 2, 3, 4, 5, 6]`, mapped in that order to Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection, XSS.
- Candidate A: saved 13-feature binary forest plus the corrected seven-class Candidate A multiclass forest.
- Leave-overlap-out: augmented 13-feature binary forest plus the same Candidate A multiclass forest.

Binary probability is class `1`. Below 0.50 the pipeline label is Benign. Otherwise it is the multiclass attack family. No binary-malicious row was labeled Benign.

## Result

All three systems produced the same test counts.

| Metric | Value |
|---|---:|
| Binary precision | 1.0 |
| Binary recall | 0.9389856362018558 |
| Binary F1 | 0.9685328438442375 |
| Binary false-positive rate | 0.0 |
| TN, FP, FN, TP | 28687, 0, 480, 7387 |
| Benign requests blocked | 0 |
| Attacks missed at the binary stage | 480 |

Those 480 misses are 479 LOG4J and 1 Log Forging.

Combined matrix for each system. Rows are true labels and columns are predicted labels: Benign, Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection, XSS.

```
28687 0 0 0 0 0 0 0
0 1548 0 0 0 0 0 0
0 0 788 0 0 0 0 0
479 0 0 268 0 0 0 0
1 0 0 0 806 0 0 0
0 0 0 0 0 789 0 0
0 0 0 0 0 0 1585 0
0 0 0 0 0 0 0 1603
```

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Benign | 0.983543 | 1.0 | 0.991703 | 28687 |
| Cookie Injection | 1.0 | 1.0 | 1.0 | 1548 |
| Directory Traversal | 1.0 | 1.0 | 1.0 | 788 |
| LOG4J | 1.0 | 0.358768 | 0.528079 | 747 |
| Log Forging | 1.0 | 0.998761 | 0.999380 | 807 |
| RCE | 1.0 | 1.0 | 1.0 | 789 |
| SQL Injection | 1.0 | 1.0 | 1.0 | 1585 |
| XSS | 1.0 | 1.0 | 1.0 | 1603 |

## Separate controlled suite

Not used in this scoring pass. On that 35-case suite, Candidate A blocked 34 reads and the leave-overlap-out candidate blocked 0. This test split does not contain those short-header gateway requests, so the identical test counts do not measure that difference.

## Files

`research/atrdf_header_count_ablation/final_test_evaluation/evaluate_final_test.py`

`research/atrdf_header_count_ablation/final_test_evaluation/final_test_metrics.json`

`research/atrdf_header_count_ablation/final_test_evaluation/FINAL_TEST_REPORT.md`

No deployment model was selected. Active artifacts were not written.
