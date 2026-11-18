"""Checks the live SPR detector without opening the held-out ATRDF test CSV."""

import numpy as np

from pattern_reinforcement import SequentialPatternReinforcer, ATRDF_FEATURES


def check(cond, msg):
    if not cond:
        raise SystemExit(msg)


def main():
    rng = np.random.RandomState(0)
    n = 80
    X_ben = rng.normal(0.0, 1.0, size=(n, len(ATRDF_FEATURES)))
    X_sql = rng.normal(2.5, 1.0, size=(n, len(ATRDF_FEATURES)))
    X = np.vstack([X_ben, X_sql])
    y = np.array([0] * n + [1] * n)
    labels = np.array(["Benign"] * n + ["SQL Injection"] * n)
    spr = SequentialPatternReinforcer(n_estimators=20, max_depth=6, random_state=0)
    spr.fit_base(X, y, labels, ATRDF_FEATURES)
    spr.mix = 0.7
    spr.threshold = 0.5
    check("SQL Injection" in spr.prototypes, "prototype memory missing SQL Injection")
    attack = spr.decide(X_sql[:1])
    benign = spr.decide(X_ben[:1])
    check(attack["positive"], f"attack not flagged: {attack}")
    check(not benign["positive"], f"benign flagged: {benign}")
    check(attack["nearest_family"] == "SQL Injection", attack)
    before = spr.proto_n["SQL Injection"]
    spr.update_online(X_sql[1:2], "SQL Injection")
    check(spr.proto_n["SQL Injection"] == before + 1, "online update did not increment")
    print("SPR live detector checks passed")


if __name__ == "__main__":
    main()
