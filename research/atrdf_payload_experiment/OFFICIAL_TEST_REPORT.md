# Official test for Table VI and Table VII

Use `HELDOUT_SIX_REPORT.md`, `models/atrdf_six/`, and `models/atrdf_eight/`. The 20-feature flag forest is not the live detector. The 14-feature JNDI forest is not used.

Both tables use the 10 request statistics that are not family proxies. Threshold is 0.50.

Table VI, official test after XSS drop, 34,951 rows:

| Metric | Value |
|---|---:|
| Accuracy | 0.978913 |
| Precision | 0.998197 |
| Recall | 0.883940 |
| F1 | 0.937601 |
| FPR | 0.000349 |
| TN, FP, FN, TP | 28,677, 10, 727, 5,537 |

The 727 misses are 720 LOG4J and 7 Log Forging.

Table VII, official test with XSS kept, 36,554 rows:

| Metric | Value |
|---|---:|
| Accuracy | 0.979811 |
| Precision | 0.998462 |
| Recall | 0.907589 |
| F1 | 0.950859 |
| FPR | 0.000383 |
| TN, FP, FN, TP | 28,676, 11, 727, 7,140 |

The 727 misses are 720 LOG4J and 7 Log Forging. Production `models/atrdf` was not overwritten.
