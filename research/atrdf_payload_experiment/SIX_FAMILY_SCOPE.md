# Six-family experimental ATRDF scope

XSS is excluded from the evaluated classes. The reason is recorded in `XSS_RECALL_LIMIT.md`: many labeled XSS rows are payload-free `GET /forum` requests. Those labels were not rewritten as benign, and the original dataset files were not edited.

The reported detector is the held-out 10-feature forest. Structural flags and the three family-proxy statistics are not model inputs. The older 20-feature flag forest in `context_six/` is kept only as a legacy artifact. Its 1.0 development-mask scores are not Table VI.

Classes, indices 0 through 5:

1. Cookie Injection
2. Directory Traversal
3. LOG4J
4. Log Forging
5. RCE
6. SQL Injection

Artifacts:

- `heldout_six/candidate_binary_rf_six_heldout.joblib`
- `heldout_six/candidate_multiclass_rf_six_heldout.joblib`
- `heldout_six/metrics.json`

Threshold 0.50. scikit-learn 1.2.2. Train rows 139,799. Official test rows after XSS drop 34,951.

Table VI (official test): accuracy 0.978913, precision 0.998197, recall 0.883940, F1 0.937601, FPR 0.000349, TN 28,677, FP 10, FN 727, TP 5,537. Misses are 720 LOG4J and 7 Log Forging. LOG4J recall is 0.036145.

Train with:

```text
.venv-repair\Scripts\python.exe research\atrdf_payload_experiment\train_six_family_heldout.py
```
