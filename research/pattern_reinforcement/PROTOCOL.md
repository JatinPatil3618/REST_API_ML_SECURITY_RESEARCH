# Paper comparison protocol (not the easy in-distribution split)

```
py -3 research/pattern_reinforcement/run_hard_evaluation.py
```

## ATRDF Table VIII

Leave-one-family-out. Drop `header_count`, `url_special_count`, `cookie_present`. Macro-average seven families. Threshold: 1% FPR on benign validation.

## BOLA Table IX

Mixed sessions + extra legitimate sessions. Features: frequency, object switch, inter-arrival, burst, hour. Threshold: max F1 on validation.
