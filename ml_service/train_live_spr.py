"""Train live SPR models for the gateway profile `pattern-reinforcement`.

Uses the same 13 ATRDF and 14 BOLA features the Java extractors emit.
Does not overwrite models/atrdf or models/bola.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from pattern_reinforcement import (  # noqa: E402
    ATRDF_FEATURES,
    BOLA_FEATURES,
    SequentialPatternReinforcer,
    save_spr,
)

OUT = ROOT / "models" / "spr"
RANDOM_SEED = 42


def vector_key(df, cols):
    return df[cols].round(6).astype(str).agg("|".join, axis=1)


def unique_rows(df, cols, label_col, binary_col):
    work = df.copy()
    work["_k"] = vector_key(work, cols)
    rows = []
    for _, g in work.groupby("_k", sort=False):
        if g[binary_col].nunique() > 1:
            continue
        rec = g.iloc[0][cols].to_dict()
        rec[label_col] = g[label_col].mode().iloc[0]
        rec[binary_col] = int(g[binary_col].iloc[0])
        rows.append(rec)
    return pd.DataFrame(rows)


def max_f1_threshold(y, scores):
    best_t, best_f = 0.5, -1.0
    for t in np.linspace(0.20, 0.80, 25):
        f = f1_score(y, (scores >= t).astype(int), zero_division=0)
        if f > best_f:
            best_t, best_f = float(t), float(f)
    return best_t, best_f


def tune(model, X_val, y_val):
    best = None
    for mix in (0.55, 0.70, 0.85, 1.0):
        model.mix = mix
        sc = model.scores(X_val)
        thr, f = max_f1_threshold(y_val, sc)
        if best is None or f > best[0]:
            best = (f, mix, thr)
    model.mix, model.threshold = best[1], best[2]
    return best


def train_atrdf():
    df = pd.read_csv(ROOT / "data/raw/atrdf/REQUEST_ONLY_train.csv")
    df = unique_rows(df, ATRDF_FEATURES, "label", "is_malicious")
    idx = np.arange(len(df))
    tr, va = train_test_split(idx, test_size=0.15, random_state=RANDOM_SEED, stratify=df["is_malicious"])
    X = df[ATRDF_FEATURES].to_numpy(float)
    y = df["is_malicious"].to_numpy(int)
    labels = df["label"].to_numpy()
    spr = SequentialPatternReinforcer()
    spr.fit_base(X[tr], y[tr], labels[tr], ATRDF_FEATURES)
    f, mix, thr = tune(spr, X[va], y[va])
    save_spr(spr, OUT / "atrdf_spr.joblib")
    print(f"ATRDF SPR mix={mix:.2f} threshold={thr:.3f} val_f1={f:.4f} families={list(spr.prototypes)}")
    return spr


def train_bola():
    df = pd.read_csv(ROOT / "data/raw/vampi/vampi_v6_2_50000_ML_READY.csv")
    sessions = np.array(df["session_id"].astype(str).unique())
    rng = np.random.RandomState(RANDOM_SEED)
    rng.shuffle(sessions)
    n = len(sessions)
    n_tr = int(n * 0.80)
    n_va = int(n * 0.10)
    s_tr, s_va = set(sessions[:n_tr]), set(sessions[n_tr : n_tr + n_va])
    tr = df[df["session_id"].isin(s_tr)]
    va = df[df["session_id"].isin(s_va)]
    Xtr = tr[BOLA_FEATURES].to_numpy(float)
    ytr = tr["target"].to_numpy(int)
    lab_tr = np.where(ytr == 1, "BOLA", "NORMAL")
    spr = SequentialPatternReinforcer(max_depth=8)
    spr.fit_base(Xtr, ytr, lab_tr, BOLA_FEATURES)
    f, mix, thr = tune(spr, va[BOLA_FEATURES].to_numpy(float), va["target"].to_numpy(int))
    save_spr(spr, OUT / "bola_spr.joblib")
    print(f"BOLA SPR mix={mix:.2f} threshold={thr:.3f} val_f1={f:.4f}")
    return spr


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    train_atrdf()
    train_bola()
    meta = {
        "profile": "pattern-reinforcement",
        "atrdf_features": ATRDF_FEATURES,
        "bola_features": BOLA_FEATURES,
        "replaces_production": False,
    }
    with open(OUT / "model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print("Wrote", OUT)


if __name__ == "__main__":
    main()
