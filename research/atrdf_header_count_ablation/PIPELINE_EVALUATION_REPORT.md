# Corrected ATRDF pipeline evaluation

Multiclass candidates were refit on attack-labeled fit rows only and encoded as production indices 0–6. Binary candidates and the 0.50 threshold were not refit. `REQUEST_ONLY_test.csv` was not read. Active files in `models/atrdf/` were not written.

These figures replace the earlier eight-class multiclass fit. Validation-split results and the 35-case suite are separate. Neither is a population-wide accuracy.

## Command

```
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\run_multiclass_pipeline.py
```

scikit-learn 1.2.2. The script checked that both saved binary confusion matrices still match, that the attack-only fit has 28,322 rows and no Benign labels, and that both new multiclass `classes_` values are exactly `[0, 1, 2, 3, 4, 5, 6]`.

Encoding, matching `ml_service` metadata:

| Index | Family |
|---:|---|
| 0 | Cookie Injection |
| 1 | Directory Traversal |
| 2 | LOG4J |
| 3 | Log Forging |
| 4 | RCE |
| 5 | SQL Injection |
| 6 | XSS |

Pipeline: final label Benign when binary probability is below 0.50; otherwise `ATTACK_CLASSES[argmax]`. A binary-malicious request cannot be labeled Benign.

Split: `train_test_split(test_size=0.1, random_state=42, stratify=is_malicious)` on `REQUEST_ONLY_train.csv`. Fit rows 131,591. Attack-only multiclass rows 28,322. Validation rows 14,622.

## Dataset validation

| | Pipeline A | Pipeline B |
|---|---:|---:|
| Binary precision | 1.0 | 1.0 |
| Binary recall | 0.9351763584366063 | 0.9046711153479504 |
| Binary F1 | 0.9665024630541872 | 0.94994994994995 |
| Binary false-positive rate | 0.0 | 0.0 |
| TN, FP, FN, TP | 11475, 0, 204, 2943 | 11475, 0, 300, 2847 |
| Attacks missed at the binary stage | 204 | 300 |
| Binary-malicious rows then labeled Benign | 0 | 0 |
| Benign validation rows blocked | 0 | 0 |

Binary misses: A is LOG4J 203 and Log Forging 1. B is LOG4J 299 and Log Forging 1.

Combined matrices. Rows are true labels and columns are predicted labels: Benign, Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection, XSS.

Pipeline A:

```
11475 0 0 0 0 0 0 0
0 614 0 0 0 0 0 0
0 0 323 0 0 0 0 0
203 0 0 116 0 0 0 0
1 0 0 0 303 0 0 0
0 0 0 0 0 333 0 0
0 0 0 0 0 0 614 0
0 0 0 0 0 0 0 640
```

Pipeline B:

```
11475 0 0 0 0 0 0 0
0 614 0 0 0 0 0 0
0 0 323 0 0 0 0 0
299 0 0 20 0 0 0 0
1 0 0 0 303 0 0 0
0 0 0 0 0 333 0 0
0 0 0 0 0 0 614 0
0 0 0 0 0 0 0 640
```

| Class | A precision | A recall | A F1 | B precision | B recall | B F1 | Support |
|---|---:|---:|---:|---:|---:|---:|---:|
| Benign | 0.982533 | 1.0 | 0.991189 | 0.974522 | 1.0 | 0.987097 | 11475 |
| Cookie Injection | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 614 |
| Directory Traversal | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 323 |
| LOG4J | 1.0 | 0.363636 | 0.533333 | 1.0 | 0.062696 | 0.117994 | 319 |
| Log Forging | 1.0 | 0.996711 | 0.998353 | 1.0 | 0.996711 | 0.998353 | 304 |
| RCE | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 333 |
| SQL Injection | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 614 |
| XSS | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 640 |

## Controlled suite

35 specification-benign reads. Labels were not model inputs.

| Pipeline | Benign requests blocked | Rate |
|---|---:|---:|
| A | 34 / 35 | 0.971429 |
| B | 3 / 35 | 0.085714 |

Pipeline A labels 31 blocked catalog, comment, and health reads as LOG4J, and C16–C18 (`GET /`) as XSS. C26 stays Benign. Pipeline B allows every case except C16–C18, which it labels XSS.

## Updated files

Under `research/atrdf_header_count_ablation/`:

- `run_multiclass_pipeline.py`
- `candidate_a_multiclass_rf.joblib`
- `candidate_b_multiclass_rf.joblib`
- `pipeline_validation_metrics.json`
- `controlled_suite_pipeline_results.json`
- `PIPELINE_EVALUATION_REPORT.md`

The binary candidate joblibs were not rewritten. No Java files were changed.

## Recommendation

Do not select a deployment model from this comparison. Removing `header_count` still lowers validation attack recall, and the gap remains LOG4J: 116 of 319 for A versus 20 of 319 for B. The controlled suite is not a substitute for the untouched test split. The next measurement is one pre-registered scoring of both corrected pipelines on that split, with the threshold left at 0.50.
