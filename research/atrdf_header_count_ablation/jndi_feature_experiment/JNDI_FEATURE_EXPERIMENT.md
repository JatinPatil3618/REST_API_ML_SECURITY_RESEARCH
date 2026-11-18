# JNDI header-value feature experiment

Temporary candidates only. `REQUEST_ONLY_test.csv` was not opened. Files in `models/atrdf/` and the gateway were not modified. Threshold fixed at 0.50.

## Command

```
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\jndi_feature_experiment\run_jndi_feature_experiment.py
```

scikit-learn 1.2.2. Fit rows 131591. Validation rows 14622.

## Feature

`jndi_lookup_marker` is 1 when any request header value matches `\$\{\s*jndi\s*:` without regard to case. The pattern is also applied after percent-decoding. Attack labels are not read while the feature is extracted. The column is aligned with `train_record_ids.npy` (`record_id` is the 1-based JSON position).

Training rows with the marker: 3148 of 146213. Rows whose match appeared only after percent-decoding: 0.

| Label | Rows | Marker 1 |
|---|---:|---:|
| Benign | 114744 | 0 |
| Cookie Injection | 6194 | 23 |
| Directory Traversal | 3151 | 25 |
| LOG4J | 2986 | 2986 |
| Log Forging | 3230 | 19 |
| RCE | 3155 | 16 |
| SQL Injection | 6339 | 46 |
| XSS | 6414 | 33 |

The 13-feature baseline is the existing Candidate A binary model and the existing attack-only seven-class Candidate A multiclass model, scored again on this validation split. The 14-feature candidate was fit on the same fit indices. Random Forest settings were copied from the active artifacts and not otherwise changed.

Copied binary parameters: `{"n_estimators": 100, "max_depth": 16, "min_samples_split": 5, "min_samples_leaf": 1, "class_weight": null, "max_features": "sqrt", "random_state": 42}`.
Copied multiclass parameters: `{"n_estimators": 100, "max_depth": 16, "min_samples_split": 5, "min_samples_leaf": 1, "class_weight": null, "max_features": "sqrt", "random_state": 42}`.

## Validation binary metrics

| Model | Precision | Recall | F1 | FPR | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 13-feature baseline | 1.000000 | 0.935176 | 0.966502 | 0.000000 | 11475 | 0 | 204 | 2943 |
| 14-feature candidate | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 11475 | 0 | 0 | 3147 |

## Validation attack-family pipeline

A row is Benign when the binary score is below 0.50. Otherwise the attack-only multiclass label is used.

| Family | Baseline P | Baseline R | Baseline F1 | Baseline missed | Candidate P | Candidate R | Candidate F1 | Candidate missed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Benign | 0.982533 | 1.000000 | 0.991189 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |
| Cookie Injection | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |
| Directory Traversal | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |
| LOG4J | 1.000000 | 0.363636 | 0.533333 | 203 | 1.000000 | 1.000000 | 1.000000 | 0 |
| Log Forging | 1.000000 | 0.996711 | 0.998353 | 1 | 1.000000 | 1.000000 | 1.000000 | 0 |
| RCE | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |
| SQL Injection | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |
| XSS | 1.000000 | 1.000000 | 1.000000 | 0 | 1.000000 | 1.000000 | 1.000000 | 0 |

LOG4J missed at the binary stage: baseline 203, candidate 0.
LOG4J pipeline recall: baseline 0.363636 (116/319), candidate 1.000000 (319/319).
Binary-malicious rows then labeled Benign by multiclass: baseline 0, candidate 0.

## Controlled legitimate suite

The 35 saved Java feature vectors are scored unchanged on the first 13 features. `jndi_lookup_marker` for the candidate is computed from the harness header values that built those vectors (Host, User-Agent, and the Accept headers for profiles H3–H6). Specification labels are not model inputs.

Marker 1 on the suite: 0 of 35.
Blocked requests: baseline 34 of 35, candidate 12 of 35.

The 12 remaining blocks all have `jndi_lookup_marker` 0:

| Case | Route | Profile | Score | Label |
|---|---|---|---:|---|
| C02, C05, C08, C11, C14 | `/api/comments/book/101` | H2–H6 | 0.54 | LOG4J |
| C28 | `/api/comments/book/201` | H3 | 0.54 | LOG4J |
| C33 | `/api/comments/book/201` | H4 | 0.54 | LOG4J |
| C29 | `/api/comments/book/302` | H3 | 0.54 | LOG4J |
| C34 | `/api/comments/book/302` | H6 | 0.54 | LOG4J |
| C16, C17, C18 | `/` | H2, H3, H6 | 0.6525 | XSS |

`/api/books` and `/api/health` are allowed on this suite. The comments routes and `GET /` are still blocked by the other 13 features.

## Comparison

On this validation split the candidate misses 0 LOG4J rows against the baseline's 203. The other binary miss, one Log Forging row, is also recovered (FN 204 to 0). Validation benign blocks stay at 0. The 35-case suite blocks 12 requests against the baseline's 34, so legitimate-suite blocks decreased and did not increase.

Every training-split LOG4J row has the marker (2,986/2,986) and no training-split benign row has it (0/114,744). Other attack labels carry it on 162 training rows. The validation scores measure that separation. They were not measured on the locked test split, and the 12 suite blocks show that a marker of 0 does not by itself make short-header legitimate requests benign.

## Checks

- Replayed 13-feature Candidate A validation confusion matrix matches TN 11475, FP 0, FN 204, TP 2943.
- Candidate binary classes_ [0, 1]; candidate multiclass classes_ 0-6; attack-only fit rows 28322.
- Held-out test CSV was not opened. Active model files were loaded and not written.
