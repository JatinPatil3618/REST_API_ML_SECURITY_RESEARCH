# Leakage-controlled offline algorithm comparison

Reproduces Tables VIII and IX in `submission/report/SIMULATION_AND_RESULTS.md`.

```
py -3 research/offline_algorithm_comparison/run_comparison.py
```

Does not write anything under `models/`.

## Why the old 1.0 tables were invalid

- 59.39% of `REQUEST_ONLY_test.csv` rows share a request-only vector with train.
- `cross_owner_ratio_recent > 0` has precision 1.0 on VAmPI (synthetic BOLA generation).

## ATRDF protocol

Train on all of `REQUEST_ONLY_train.csv`. Score only test rows whose 12-feature vector is not in train. `header_count` is omitted.

## BOLA protocol

Session-disjoint 80/10/10 split, seed 42. Owner-proxy features omitted: unique owners, owner switch, cross-owner count/ratio, same-owner ratio.
