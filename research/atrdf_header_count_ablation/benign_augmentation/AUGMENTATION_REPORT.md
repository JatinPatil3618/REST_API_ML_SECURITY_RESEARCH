# Benign-augmentation binary candidate

This is one temporary forest. It is not a selected deployment model. Dataset-validation numbers and the 35-case suite are separate, and neither is a population-wide accuracy.

## Commands

From `gateway`:

```
"C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2024.1.4\plugins\maven\lib\maven3\bin\mvn.cmd" -Dtest=BenignAugmentationExtractorTest test
```

Result: Tests run 1, Failures 0, Errors 0, BUILD SUCCESS. Features came from `FeatureExtractor`.

Then:

```
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\benign_augmentation\train_augmented_binary.py
```

Threshold 0.50. `REQUEST_ONLY_test.csv` was not read. The original fit/validation indices were not changed. The multiclass stage is the existing attack-only Candidate A model, loaded and not refit.

## Augmentation

26 GET requests to `http://127.0.0.1:8080`. Labels sit only in `augmentation_manifest.json`. Fit rows are the original 131,591 plus these 26 benign rows (131,617). Validation remains 14,622 rows.

`/api/health` at header profiles H2–H6 is already the controlled suite, so it was not added to training. `/` was added only at H4 and H5. The other rows are catalog searches and comment reads for seeded books 102, 202, 301, 401, 402, 501, and 502, with header counts 2–6.

No augmentation row repeats a suite route, query, and header profile. Three rows have the same 13-feature vector as a suite case:

| Augmentation | Request | Suite case | Suite request |
|---|---|---|---|
| A06 | `/api/books?search=database`, H2 | C30 | `/api/books?search=protocol`, H2 |
| A19 | `/api/comments/book/202`, H3 | C28 | `/api/comments/book/201`, H3 |
| A24 | `/api/comments/book/502`, H6 | C34 | `/api/comments/book/302`, H6 |

The other 32 suite vectors do not appear in the augmentation set.

## Dataset validation

| Metric | Augmented candidate | Saved Candidate A |
|---|---:|---:|
| Precision | 1.0 | 1.0 |
| Recall | 0.9351763584366063 | 0.9351763584366063 |
| F1 | 0.9665024630541872 | 0.9665024630541872 |
| False-positive rate | 0.0 | 0.0 |
| TN, FP, FN, TP | 11475, 0, 204, 2943 | 11475, 0, 204, 2943 |
| Benign rows blocked | 0 | 0 |

Binary misses remain LOG4J 203 of 319 (recall 0.363636) and Log Forging 1 of 304 (recall 0.996711). The other five attack families have recall 1.0. With Candidate A’s multiclass model, combined per-attack recall matches those binary recalls.

## Controlled suite

False positives: 0 of 35. Candidate A blocked 34 of 35 on this same suite. All 32 suite vectors that do not overlap the augmentation set were allowed, as were the three overlapping vectors.

## Recommendation

Do not select this candidate because the suite is now clear. Validation attack detection did not improve, and it also did not drop. Three suite vectors were not independent of training. The untouched test split is still unscored. The next check is to remove A06, A19, and A24, refit only this temporary forest, and rescore the suite before any test-split measurement.
