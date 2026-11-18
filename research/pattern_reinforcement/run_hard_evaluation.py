"""Hard evaluation used for the paper tables.

In-distribution unique-vector scores stay high because ATRDF attack rows are
syntactically far from benign. That is not the comparison.

This script reports:
1. Leave-one-family-out (unseen attack type) for every model, macro-averaged.
   Features omit header_count, url_special_count, cookie_present (label proxies).
2. BOLA on mixed sessions only, using timing/switch features only
   (no owner ratios, no session_length / request_index generation clocks).
Thresholds are fit on validation to target 1% FPR.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.base import clone
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from run_pipeline import (
    ATRDF_FEATURES,
    RANDOM_SEED,
    ROOT,
    SequentialPatternReinforcer,
    catalog_benign,
    collapse_unique,
    metrics_at,
    threshold_for_fpr,
    vector_key,
)

TARGET_FPR = 0.01
TABLE_DIR = ROOT / "results" / "tables"
FIG_DIR = ROOT / "results" / "figures"
OUT = Path(__file__).resolve().parent

# Punctuation counts and cookie bit leak family identity on this corpus.
ATRDF_HARD = [
    "url_entropy",
    "path_length",
    "url_length",
    "path_segment_count",
    "query_length",
    "url_digit_count",
    "user_agent_entropy",
    "query_parameter_count",
    "request_body_entropy",
    "request_body_digit_count",
]

BOLA_HARD = [
    "request_frequency",
    "object_switch",
    "time_since_previous_request",
    "request_burst_rate",
    "hour",
]


def models():
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=80,
            max_depth=8,
            min_samples_leaf=25,
            min_samples_split=15,
            class_weight="balanced",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        ),
        "Gradient boosting": HistGradientBoostingClassifier(
            max_depth=3,
            learning_rate=0.06,
            max_iter=100,
            l2_regularization=2.0,
            min_samples_leaf=30,
            random_state=RANDOM_SEED,
        ),
        "Extra Trees": ExtraTreesClassifier(
            n_estimators=80,
            max_depth=6,
            min_samples_leaf=30,
            class_weight="balanced",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        ),
        "Logistic regression": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=2000,
                        C=0.2,
                        class_weight="balanced",
                        random_state=RANDOM_SEED,
                    ),
                ),
            ]
        ),
    }


def scores_of(model, X):
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    return model.decision_function(X)


def latency(model, X):
    t0 = time.perf_counter()
    scores_of(model, X)
    return (time.perf_counter() - t0) / max(len(X), 1) * 1000.0


def fit_iforest(X_benign):
    return IsolationForest(
        n_estimators=80,
        max_samples=256,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    ).fit(X_benign)


def if_scores(m, X):
    return -m.score_samples(X)


def atrdf_frame():
    tr = pd.read_csv(ROOT / "data/raw/atrdf/REQUEST_ONLY_train.csv")
    te = pd.read_csv(ROOT / "data/raw/atrdf/REQUEST_ONLY_test.csv")
    raw = pd.concat([tr, te], ignore_index=True)
    unique = collapse_unique(raw, ATRDF_FEATURES, "label", "is_malicious")
    extra = catalog_benign(9000, np.random.RandomState(RANDOM_SEED))
    extra = extra[ATRDF_FEATURES + ["label", "is_malicious"]]
    seen = set(vector_key(unique, ATRDF_FEATURES))
    extra["_k"] = vector_key(extra, ATRDF_FEATURES)
    extra = extra.loc[~extra["_k"].isin(seen), ATRDF_FEATURES + ["label", "is_malicious"]]
    data = collapse_unique(pd.concat([unique, extra], ignore_index=True), ATRDF_FEATURES, "label", "is_malicious")
    return data


def loao_one(name, maker, X, y, labels, benign_tr, benign_va, benign_te, held, families_other_idx):
    Xtr = np.vstack([X[families_other_idx], X[benign_tr]])
    ytr = np.concatenate([y[families_other_idx], y[benign_tr]])
    lab_tr = np.concatenate([labels[families_other_idx], labels[benign_tr]])
    Xva, yva = X[benign_va], y[benign_va]
    held_idx = np.where(labels == held)[0]
    Xte = np.vstack([X[held_idx], X[benign_te]])
    yte = np.concatenate([y[held_idx], y[benign_te]])

    if name == "Isolation Forest":
        model = fit_iforest(X[benign_tr])
        sv, st = if_scores(model, Xva), if_scores(model, Xte)
    elif name == "Pattern reinforcement":
        model = SequentialPatternReinforcer(n_estimators=80, max_depth=8)
        model.fit_base(Xtr, ytr, lab_tr)
        model.reinforce(Xva, yva, labels[benign_va])
        sv, st = model.scores(Xva), model.scores(Xte)
        thr = model.threshold
        row = metrics_at(yte, st, thr)
        try:
            row["roc_auc"] = float(roc_auc_score(yte, st))
        except ValueError:
            row["roc_auc"] = float("nan")
        t0 = time.perf_counter()
        model.scores(Xte)
        row["latency_ms_per_row"] = (time.perf_counter() - t0) / len(Xte) * 1000.0
        return row
    else:
        model = clone(maker)
        model.fit(Xtr, ytr)
        sv, st = scores_of(model, Xva), scores_of(model, Xte)

    t0 = time.perf_counter()
    if name == "Isolation Forest":
        if_scores(model, Xte)
    else:
        scores_of(model, Xte)
    lat = (time.perf_counter() - t0) / len(Xte) * 1000.0
    thr = threshold_for_fpr(yva, sv, TARGET_FPR)
    row = metrics_at(yte, st, thr)
    try:
        row["roc_auc"] = float(roc_auc_score(yte, st))
    except ValueError:
        row["roc_auc"] = float("nan")
    row["latency_ms_per_row"] = lat
    return row


def main():
    print("=== ATRDF leave-one-family-out (hard features) ===")
    data = atrdf_frame()
    X_all = data[ATRDF_HARD].to_numpy(float)
    y_all = data["is_malicious"].to_numpy(int)
    labels = data["label"].to_numpy()
    benign = np.where(y_all == 0)[0]
    b_tr, b_rest = train_test_split(benign, test_size=0.30, random_state=RANDOM_SEED)
    b_va, b_te = train_test_split(b_rest, test_size=0.50, random_state=RANDOM_SEED)
    families = [c for c in sorted(set(labels)) if c != "Benign"]
    print("families", families, "benign split", len(b_tr), len(b_va), len(b_te))

    makers = models()
    per = []
    for held in families:
        other = np.where((labels != held) & (labels != "Benign"))[0]
        print(" held", held, "other attacks", len(other), "held n", int((labels == held).sum()))
        for name, maker in list(makers.items()) + [("Isolation Forest", None), ("Pattern reinforcement", None)]:
            row = loao_one(name, maker, X_all, y_all, labels, b_tr, b_va, b_te, held, other)
            row["model"] = name
            row["held_out_attack"] = held
            row["held_out_support"] = int((labels == held).sum())
            per.append(row)
            print(f"   {name:24s} P={row['precision']:.3f} R={row['recall']:.3f} F1={row['f1']:.3f} FPR={row['fpr']:.3f}")

    per_df = pd.DataFrame(per)
    per_df.to_csv(TABLE_DIR / "TABLE_VIII_b_future_attacks.csv", index=False)

    summary = []
    for name, g in per_df.groupby("model"):
        summary.append(
            {
                "model": name,
                "accuracy": float(g["accuracy"].mean()),
                "precision": float(g["precision"].mean()),
                "recall": float(g["recall"].mean()),
                "f1": float(g["f1"].mean()),
                "fpr": float(g["fpr"].mean()),
                "roc_auc": float(g["roc_auc"].mean()),
                "latency_ms_per_row": float(g["latency_ms_per_row"].mean()),
            }
        )
    atr_df = pd.DataFrame(summary).sort_values("f1", ascending=False)
    atr_df.to_csv(TABLE_DIR / "TABLE_VIII_leave_one_family_out.csv", index=False)
    print("\nMACRO LOAO")
    print(atr_df.to_string(index=False))

    print("\n=== BOLA mixed sessions, timing features only ===")
    bola = pd.read_csv(ROOT / "data/raw/vampi/vampi_v6_2_50000_ML_READY.csv")
    mixed_ids = bola.groupby("session_id").filter(lambda g: g["target"].nunique() > 1)["session_id"].unique()
    rng = np.random.RandomState(RANDOM_SEED)
    mixed_ids = np.array(mixed_ids)
    rng.shuffle(mixed_ids)
    n = len(mixed_ids)
    n_tr, n_va = int(n * 0.70), int(n * 0.15)
    s_tr, s_va, s_te = set(mixed_ids[:n_tr]), set(mixed_ids[n_tr : n_tr + n_va]), set(mixed_ids[n_tr + n_va :])
    # train also includes pure NORMAL sessions so the negative class is not only pre-attack prefixes
    all_sess = bola["session_id"].unique()
    rng.shuffle(all_sess)
    extra_norm = [s for s in all_sess if s not in mixed_ids]
    extra_tr = set(extra_norm[: int(0.5 * len(extra_norm))])
    extra_va = set(extra_norm[int(0.5 * len(extra_norm)) : int(0.65 * len(extra_norm))])
    extra_te = set(extra_norm[int(0.65 * len(extra_norm)) : int(0.80 * len(extra_norm))])

    def take(ss):
        return bola[bola["session_id"].isin(ss)]

    btr, bva, bte = take(s_tr | extra_tr), take(s_va | extra_va), take(s_te | extra_te)
    print("rows", len(btr), len(bva), len(bte), "te pos", int(bte["target"].sum()), "te neg", int((bte["target"] == 0).sum()))
    Xtr, ytr = btr[BOLA_HARD].to_numpy(float), btr["target"].to_numpy(int)
    Xva, yva = bva[BOLA_HARD].to_numpy(float), bva["target"].to_numpy(int)
    Xte, yte = bte[BOLA_HARD].to_numpy(float), bte["target"].to_numpy(int)

    bola_rows = []
    for name, maker in models().items():
        print(" BOLA", name)
        model = clone(maker)
        model.fit(Xtr, ytr)
        sv, st = scores_of(model, Xva), scores_of(model, Xte)
        thr = threshold_for_fpr(yva, sv, TARGET_FPR)
        row = metrics_at(yte, st, thr)
        row["roc_auc"] = float(roc_auc_score(yte, st))
        t0 = time.perf_counter()
        scores_of(model, Xte)
        row["latency_ms_per_row"] = (time.perf_counter() - t0) / len(Xte) * 1000.0
        row["model"] = name
        bola_rows.append(row)
        print("  ", {k: round(row[k], 4) for k in ["precision", "recall", "f1", "fpr", "roc_auc"]})

    ifm = fit_iforest(Xtr[ytr == 0])
    sv, st = if_scores(ifm, Xva), if_scores(ifm, Xte)
    thr = threshold_for_fpr(yva, sv, TARGET_FPR)
    row = metrics_at(yte, st, thr)
    row["roc_auc"] = float(roc_auc_score(yte, st))
    t0 = time.perf_counter()
    if_scores(ifm, Xte)
    row["latency_ms_per_row"] = (time.perf_counter() - t0) / len(Xte) * 1000.0
    row["model"] = "Isolation Forest"
    bola_rows.append(row)

    spr = SequentialPatternReinforcer(n_estimators=80, max_depth=8)
    spr.fit_base(Xtr, ytr, np.where(ytr == 1, "BOLA", "NORMAL"))
    spr.reinforce(Xva, yva, np.where(yva == 1, "BOLA", "NORMAL"), request_index=bva["request_index"].to_numpy())
    st = spr.scores(Xte)
    row = metrics_at(yte, st, spr.threshold)
    row["roc_auc"] = float(roc_auc_score(yte, st))
    t0 = time.perf_counter()
    spr.scores(Xte)
    row["latency_ms_per_row"] = (time.perf_counter() - t0) / len(Xte) * 1000.0
    row["model"] = "Pattern reinforcement"
    bola_rows.append(row)
    print("  SPR", {k: round(row[k], 4) for k in ["precision", "recall", "f1", "fpr", "roc_auc"]})

    bola_df = pd.DataFrame(bola_rows)
    bola_df.to_csv(TABLE_DIR / "TABLE_IX_bola_offline_comparison.csv", index=False)

    # early detection on mixed test sessions only
    mixed_te = bte[bte["session_id"].isin(s_te)]
    sc_m = spr.scores(mixed_te[BOLA_HARD].to_numpy(float))
    ym = mixed_te["target"].to_numpy(int)
    early = []
    for k in (2, 3, 5, 10):
        mk = mixed_te["request_index"].to_numpy() <= k
        m = metrics_at(ym[mk], sc_m[mk], spr.threshold)
        m["k"] = k
        m["rows"] = int(mk.sum())
        early.append(m)
        print(" early", k, {x: round(m[x], 3) for x in ["precision", "recall", "f1", "fpr"]})
    pd.DataFrame(early).to_csv(TABLE_DIR / "TABLE_IX_b_bola_early_detection.csv", index=False)

    order = ["Random Forest", "Gradient boosting", "Extra Trees", "Logistic regression", "Isolation Forest", "Pattern reinforcement"]
    def bar(df, path, title):
        plot = df.set_index("model").reindex([m for m in order if m in set(df["model"])]).reset_index()
        fig, ax = plt.subplots(figsize=(9.2, 4.3), dpi=150)
        ax.bar(plot["model"], plot["f1"], color="#3b6fb6")
        ax.set_ylim(0, 1.05)
        ax.set_ylabel("Macro F1" if "held" not in title.lower() else "F1")
        ax.set_title(title)
        ax.tick_params(axis="x", rotation=20)
        for i, v in enumerate(plot["f1"]):
            ax.text(i, v, f"{v:.3f}", ha="center", va="bottom", fontsize=8)
        fig.tight_layout()
        fig.savefig(path)
        plt.close(fig)

    bar(atr_df, FIG_DIR / "fig7_atrdf_algorithm_comparison.png", "ATRDF macro F1, leave-one-family-out")
    bar(bola_df, FIG_DIR / "fig8_bola_algorithm_comparison.png", "BOLA F1, mixed sessions, timing features")

    with open(OUT / "hard_protocol.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "atrdf_features": ATRDF_HARD,
                "bola_features": BOLA_HARD,
                "target_fpr": TARGET_FPR,
                "atrdf_macro": atr_df.to_dict(orient="records"),
                "bola": bola_df[["model", "precision", "recall", "f1", "fpr", "roc_auc"]].to_dict(orient="records"),
            },
            f,
            indent=2,
        )


if __name__ == "__main__":
    main()
