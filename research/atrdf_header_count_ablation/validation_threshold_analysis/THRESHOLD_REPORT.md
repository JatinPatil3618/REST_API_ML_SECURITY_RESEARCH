# Validation threshold sweep

The test split was not opened. No model was fit. The production threshold was not changed.

Saved validation probabilities did not exist, so both frozen forests were scored again on the experiment split: `REQUEST_ONLY_train.csv`, `train_test_split(test_size=0.1, random_state=42, stratify=is_malicious)`, 14,622 validation rows. The 35-case suite was scored afterwards and was not used to choose a threshold.

Production metadata records a different split, 124,241 fit rows and 21,972 validation rows. Scores for the production forest on these 14,622 rows are therefore not that model's original holdout.

## Command

```
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\validation_threshold_analysis\sweep_validation_thresholds.py
```

Exit code 0.

## Selection rule

Use only validation rows. Among thresholds with false-positive rate 0, maximize attack recall. If several thresholds make the same decisions, keep the largest. That threshold is the lowest attack score that is still above every benign score.

## Leave-overlap-out candidate

Maximum benign malicious-probability: 0.2065472576063678. Recommended threshold: 0.47264203198043175. It catches 2,944 attacks. The other 203 attacks score at or below the highest benign score, so they cannot be caught while validation FPR stays 0. All 203 are LOG4J.

| Threshold | Precision | Recall | F1 | FPR | Benign blocked | LOG4J recall | LOG4J missed |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.05 | 0.925949 | 0.937718 | 0.931797 | 0.020566 | 236 | 0.385580 | 196 |
| 0.10 | 0.987588 | 0.935494 | 0.960836 | 0.003224 | 37 | 0.363636 | 203 |
| 0.20 | 0.998643 | 0.935494 | 0.966038 | 0.000349 | 4 | 0.363636 | 203 |
| 0.25 | 1.0 | 0.935494 | 0.966672 | 0.0 | 0 | 0.363636 | 203 |
| 0.472642 | 1.0 | 0.935494 | 0.966672 | 0.0 | 0 | 0.363636 | 203 |
| 0.50 | 1.0 | 0.935176 | 0.966502 | 0.0 | 0 | 0.363636 | 203 |

At 0.472642 the confusion matrix is TN 11475, FP 0, FN 203, TP 2944. At 0.50 it is TN 11475, FP 0, FN 204, TP 2943. The one extra detection is Log Forging. Cookie Injection, Directory Traversal, RCE, SQL Injection, and XSS stay at recall 1.0 at both points.

The controlled suite, not used for selection, blocks 0 of 35 cases at 0.472642 and at 0.50. It blocks 4 validation-benign-equivalent cases only once the threshold drops to 0.20, where validation already has 4 benign blocks and LOG4J is still 203 misses.

## Production forest on this same split

Maximum benign score: 0.28379954875719887. The same rule gives 0.49861489707420636. LOG4J recall stays 0.363636. The only change from 0.50 is the same single Log Forging catch. At 0.05, LOG4J recall rises only to 0.592476, while 174 benign validation rows are blocked.

On the 35-case suite this forest blocks all 35 cases at every listed threshold through 0.50, and still blocks 29 at 0.55. That comparison is diagnostic. It was not the selection rule.

## Recommendation

For the leave-overlap-out candidate, the validation rule selects 0.47264203198043175. Measured against 0.50, it adds one Log Forging detection and blocks no additional validation benign row. It does not recover any of the 203 missed LOG4J rows. Those scores are not separable from benign scores on this split. Do not lower the threshold to chase LOG4J, and do not change the production threshold.
