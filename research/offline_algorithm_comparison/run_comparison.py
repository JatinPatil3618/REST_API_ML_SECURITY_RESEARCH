"""Leakage-controlled offline algorithm comparison for ATRDF and BOLA.

The previous Table VIII/IX scores were not research-valid:
- 58.99% of ATRDF test rows reuse a request-only vector already present in train.
- A single BOLA rule (cross_owner_ratio_recent > 0) has precision 1.0.
  Owner-ratio features are generation proxies, not authorization.

This script does not overwrite models/atrdf or models/bola.
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
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

RANDOM_SEED = 42
THRESHOLD = 0.50
ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = Path(__file__).resolve().parent
TABLE_DIR = ROOT / "results" / "tables"
FIG_DIR = ROOT / "results" / "figures"
TABLE_DIR.mkdir(parents=True, exist_ok=True)
FIG_DIR.mkdir(parents=True, exist_ok=True)

ATRDF_FEATURES = [
    "url_entropy",
    "header_count",
    "path_length",
    "url_special_count",
    "url_length",
    "path_segment_count",
    "cookie_present",
    "query_length",
    "url_digit_count",
    "user_agent_entropy",
    "query_parameter_count",
    "request_body_entropy",
    "request_body_digit_count",
]

# Keep header_count out of the comparison. It is a collection artifact
# (largest Gini in the 13-feature forest) and is not a payload signal.
ATRDF_COMPARE_FEATURES = [f for f in ATRDF_FEATURES if f != "header_count"]

BOLA_OWNER_PROXY = [
    "unique_owners_recent",
    "owner_switch",
    "cross_owner_count_recent",
    "cross_owner_ratio_recent",
    "same_owner_ratio_recent",
]

BOLA_COMPARE_FEATURES = [
    "request_frequency",
    "unique_objects_recent",
    "object_switch",
    "same_object_repeat_ratio",
    "time_since_previous_request",
    "request_burst_rate",
    "hour",
    "session_length",
    "request_index",
]


def vector_key(df: pd.DataFrame, cols: list[str]) -> pd.Series:
    return df[cols].round(6).astype(str).agg("|".join, axis=1)


def binary_metrics(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    n_neg = tn + fp
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": float(fp / n_neg) if n_neg else 0.0,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def supervised_models():
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_split=5,
            max_features="sqrt",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        ),
        "Gradient boosting": HistGradientBoostingClassifier(
            max_depth=4,
            learning_rate=0.08,
            max_iter=120,
            l2_regularization=1.0,
            random_state=RANDOM_SEED,
        ),
        "Extra Trees": ExtraTreesClassifier(
            n_estimators=100,
            max_depth=8,
            min_samples_split=8,
            max_features="sqrt",
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
                        C=0.5,
                        solver="lbfgs",
                        random_state=RANDOM_SEED,
                    ),
                ),
            ]
        ),
    }


def predict_supervised(model, X) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        return (model.predict_proba(X)[:, 1] >= THRESHOLD).astype(int)
    clf = model.named_steps["clf"] if isinstance(model, Pipeline) else model
    if hasattr(model, "predict_proba"):
        return (model.predict_proba(X)[:, 1] >= THRESHOLD).astype(int)
    if hasattr(clf, "predict_proba"):
        Xt = model.named_steps["scaler"].transform(X) if isinstance(model, Pipeline) else X
        return (clf.predict_proba(Xt)[:, 1] >= THRESHOLD).astype(int)
    return model.predict(X).astype(int)


def latency_ms(predict_fn, X, repeats: int = 3) -> float:
    predict_fn(X[: min(32, len(X))])
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        predict_fn(X)
        times.append(time.perf_counter() - t0)
    return float(np.median(times) / len(X) * 1000.0)


def fit_iforest(X_benign: np.ndarray) -> IsolationForest:
    return IsolationForest(
        n_estimators=100,
        max_samples=256,
        contamination="auto",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    ).fit(X_benign)


def iforest_predict(model: IsolationForest, X) -> np.ndarray:
    return (model.predict(X) == -1).astype(int)


def session_split(df: pd.DataFrame, seed: int = RANDOM_SEED):
    sessions = df["session_id"].unique()
    rng = np.random.RandomState(seed)
    rng.shuffle(sessions)
    n = len(sessions)
    n_tr = int(n * 0.80)
    n_va = int(n * 0.10)
    train_s = set(sessions[:n_tr])
    val_s = set(sessions[n_tr : n_tr + n_va])
    test_s = set(sessions[n_tr + n_va :])
    return (
        df[df["session_id"].isin(train_s)].copy(),
        df[df["session_id"].isin(val_s)].copy(),
        df[df["session_id"].isin(test_s)].copy(),
        len(train_s),
        len(val_s),
        len(test_s),
    )


def session_fpr(df: pd.DataFrame, preds: np.ndarray) -> float:
    work = df.copy()
    work["pred"] = preds
    legit = work.groupby("session_id").filter(lambda g: (g["target"] == 0).all())
    if legit.empty:
        return float("nan")
    flagged = legit.groupby("session_id")["pred"].max()
    return float(flagged.mean())


def run_family(name: str, X_train, y_train, X_test, y_test, X_benign_train):
    rows = []
    pred_map = {}
    for model_name, model in supervised_models().items():
        print(f"  [{name}] {model_name}")
        model.fit(X_train, y_train)

        def _pred(X, m=model):
            return predict_supervised(m, X)

        preds = _pred(X_test)
        lat = latency_ms(_pred, X_test)
        metrics = binary_metrics(y_test, preds)
        metrics.update({"model": model_name, "latency_ms_per_row": lat})
        rows.append(metrics)
        pred_map[model_name] = preds
        print(
            f"    acc={metrics['accuracy']:.4f} p={metrics['precision']:.4f} "
            f"r={metrics['recall']:.4f} f1={metrics['f1']:.4f} fpr={metrics['fpr']:.4f}"
        )

    print(f"  [{name}] Isolation Forest")
    iforest = fit_iforest(X_benign_train)

    def _if_pred(X, m=iforest):
        return iforest_predict(m, X)

    preds = _if_pred(X_test)
    lat = latency_ms(_if_pred, X_test)
    metrics = binary_metrics(y_test, preds)
    metrics.update({"model": "Isolation Forest", "latency_ms_per_row": lat})
    rows.append(metrics)
    pred_map["Isolation Forest"] = preds
    print(
        f"    acc={metrics['accuracy']:.4f} p={metrics['precision']:.4f} "
        f"r={metrics['recall']:.4f} f1={metrics['f1']:.4f} fpr={metrics['fpr']:.4f}"
    )
    return rows, pred_map


def plot_f1_latency(df: pd.DataFrame, title: str, path: Path):
    order = [
        "Random Forest",
        "Gradient boosting",
        "Extra Trees",
        "Logistic regression",
        "Isolation Forest",
    ]
    df = df.set_index("model").loc[order].reset_index()
    fig, axes = plt.subplots(1, 2, figsize=(10.2, 4.2), dpi=160)
    axes[0].bar(df["model"], df["f1"], color="#3b6fb6")
    axes[0].set_ylim(0, 1.05)
    axes[0].set_ylabel("F1")
    axes[0].set_title("F1")
    axes[0].tick_params(axis="x", rotation=25)
    for i, v in enumerate(df["f1"]):
        axes[0].text(i, v + 0.02, f"{v:.3f}", ha="center", fontsize=8)
    axes[1].bar(df["model"], df["latency_ms_per_row"], color="#7a4ea3")
    axes[1].set_ylabel("ms / row")
    axes[1].set_title("Latency")
    axes[1].tick_params(axis="x", rotation=25)
    fig.suptitle(title, fontsize=11)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def format_table(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(
        {
            "Model": df["model"],
            "Accuracy": df["accuracy"].map(lambda x: f"{x:.6f}"),
            "Precision": df["precision"].map(lambda x: f"{x:.6f}"),
            "Recall": df["recall"].map(lambda x: f"{x:.6f}"),
            "F1": df["f1"].map(lambda x: f"{x:.6f}"),
            "FPR": df["fpr"].map(lambda x: f"{x:.6f}"),
            "Latency (ms/row)": df["latency_ms_per_row"].map(lambda x: f"{x:.6f}"),
        }
    )
    return out


def main():
    print("=== ATRDF unseen-vector comparison (no header_count) ===")
    atr_tr = pd.read_csv(ROOT / "data/raw/atrdf/REQUEST_ONLY_train.csv")
    atr_te = pd.read_csv(ROOT / "data/raw/atrdf/REQUEST_ONLY_test.csv")
    feats = ATRDF_COMPARE_FEATURES
    train_keys = set(vector_key(atr_tr, feats))
    te_keys = vector_key(atr_te, feats)
    atr_te_unseen = atr_te.loc[~te_keys.isin(train_keys)].copy()
    print(
        f"train={len(atr_tr)} test={len(atr_te)} unseen_test={len(atr_te_unseen)} "
        f"overlap_frac={1.0 - len(atr_te_unseen) / len(atr_te):.4f}"
    )
    print("unseen labels", atr_te_unseen["label"].value_counts().to_dict())

    X_tr = atr_tr[feats].to_numpy(dtype=float)
    y_tr = atr_tr["is_malicious"].to_numpy(dtype=int)
    X_te = atr_te_unseen[feats].to_numpy(dtype=float)
    y_te = atr_te_unseen["is_malicious"].to_numpy(dtype=int)
    X_benign = atr_tr.loc[atr_tr["is_malicious"] == 0, feats].to_numpy(dtype=float)

    atr_rows, _ = run_family("ATRDF", X_tr, y_tr, X_te, y_te, X_benign)
    atr_df = pd.DataFrame(atr_rows)
    atr_df.to_csv(TABLE_DIR / "TABLE_VIII_unseen_vector.csv", index=False)
    format_table(atr_df).to_csv(OUT_DIR / "table_viii_formatted.csv", index=False)
    plot_f1_latency(
        atr_df,
        "ATRDF binary F1 and latency (unseen request vectors)",
        FIG_DIR / "fig7_atrdf_algorithm_comparison.png",
    )

    print("\n=== BOLA session-disjoint comparison (no owner-proxy features) ===")
    bola = pd.read_csv(ROOT / "data/raw/vampi/vampi_v6_2_50000_ML_READY.csv")
    df_tr, df_va, df_te, n_tr_s, n_va_s, n_te_s = session_split(bola)
    print(f"sessions train/val/test={n_tr_s}/{n_va_s}/{n_te_s}")
    print(f"rows train/val/test={len(df_tr)}/{len(df_va)}/{len(df_te)}")
    bfeats = BOLA_COMPARE_FEATURES
    Xb_tr = df_tr[bfeats].to_numpy(dtype=float)
    yb_tr = df_tr["target"].to_numpy(dtype=int)
    Xb_te = df_te[bfeats].to_numpy(dtype=float)
    yb_te = df_te["target"].to_numpy(dtype=int)
    Xb_benign = df_tr.loc[df_tr["target"] == 0, bfeats].to_numpy(dtype=float)

    bola_rows, bola_preds = run_family("BOLA", Xb_tr, yb_tr, Xb_te, yb_te, Xb_benign)
    for row in bola_rows:
        row["session_fpr_legit"] = session_fpr(df_te, bola_preds[row["model"]])
    bola_df = pd.DataFrame(bola_rows)
    bola_df.to_csv(TABLE_DIR / "TABLE_IX_bola_offline_comparison.csv", index=False)
    format_table(bola_df).to_csv(OUT_DIR / "table_ix_formatted.csv", index=False)
    plot_f1_latency(
        bola_df,
        "BOLA offline F1 and latency (session-disjoint, no owner proxies)",
        FIG_DIR / "fig8_bola_algorithm_comparison.png",
    )

    # Diagnostic: owner-proxy rule on the same test sessions.
    rule = (df_te["cross_owner_ratio_recent"] > 0).astype(int).to_numpy()
    rule_m = binary_metrics(yb_te, rule)
    rule_m["model"] = "Rule: cross_owner_ratio>0"
    print("  owner-proxy rule on same test", {k: rule_m[k] for k in ["accuracy", "precision", "recall", "f1", "fpr"]})

    protocol = {
        "random_seed": RANDOM_SEED,
        "threshold": THRESHOLD,
        "atrdf": {
            "protocol": "Train on REQUEST_ONLY_train.csv; score only test rows whose 12-feature vector (header_count removed) does not appear in train.",
            "features": feats,
            "dropped_feature": "header_count",
            "train_rows": int(len(atr_tr)),
            "official_test_rows": int(len(atr_te)),
            "unseen_test_rows": int(len(atr_te_unseen)),
            "official_test_overlap_fraction": float(1.0 - len(atr_te_unseen) / len(atr_te)),
            "unseen_label_counts": atr_te_unseen["label"].value_counts().to_dict(),
        },
        "bola": {
            "protocol": "Session-disjoint 80/10/10 split. Owner-proxy features removed because cross_owner_ratio>0 has precision 1.0 on the corpus.",
            "features": bfeats,
            "dropped_features": BOLA_OWNER_PROXY,
            "train_sessions": int(n_tr_s),
            "val_sessions": int(n_va_s),
            "test_sessions": int(n_te_s),
            "test_rows": int(len(df_te)),
            "owner_proxy_rule_on_test": {
                k: rule_m[k] for k in ["accuracy", "precision", "recall", "f1", "fpr"]
            },
        },
        "note": "Production joblib files under models/ were not modified.",
    }
    with open(OUT_DIR / "protocol.json", "w", encoding="utf-8") as f:
        json.dump(protocol, f, indent=2)
    with open(TABLE_DIR / "offline_algorithm_comparison_protocol.json", "w", encoding="utf-8") as f:
        json.dump(protocol, f, indent=2)

    print("\nWrote tables and figures.")
    print(atr_df[["model", "accuracy", "precision", "recall", "f1", "fpr", "latency_ms_per_row"]])
    print(bola_df[["model", "accuracy", "precision", "recall", "f1", "fpr", "latency_ms_per_row", "session_fpr_legit"]])


if __name__ == "__main__":
    main()
