"""Research-grade leakage-safe comparison + sequential pattern reinforcement.

Evaluation protocol (IDS-standard):
- Collapse duplicate request vectors so the same sample cannot sit in train and test.
- Add catalog-like benign REST traffic that overlaps the syntactic range of real APIs.
- Split unique vectors 70/15/15 (seed 42), stratified by binary label.
- Choose the decision threshold on validation to target 1% FPR; freeze it; score test.
- Report ROC-AUC and PR-AUC (threshold-free) plus precision/recall/F1 at that operating point.

Sequential Pattern Reinforcement (SPR):
- Keeps a prototype (running mean) per historical attack family.
- Combines Random Forest probability with similarity to stored patterns.
- Adapts the mix weight and threshold from a delayed-label reward on the validation stream
  (early true positives rewarded, false positives and misses penalised).
- Future-attack protocol: leave one family out of training, then detect it as an unseen pattern.
"""

from __future__ import annotations

import json
import math
import time
from collections import Counter
from pathlib import Path

import joblib
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
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

RANDOM_SEED = 42
TARGET_FPR = 0.01
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
TABLE_DIR = ROOT / "results" / "tables"
FIG_DIR = ROOT / "results" / "figures"
ART = OUT / "artifacts"
TABLE_DIR.mkdir(parents=True, exist_ok=True)
FIG_DIR.mkdir(parents=True, exist_ok=True)
ART.mkdir(parents=True, exist_ok=True)

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

BOLA_FEATURES = [
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

SPECIALS = set("<>'\" ;-/\\%=(){}$`&|!?")
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 Firefox/142.0",
    "python-requests/2.32.5",
    "PostmanRuntime/7.43.0",
]


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_request(url: str, ua: str, body: str = "", header_count: int = 6, cookie: int = 0) -> dict:
    if "?" in url:
        path, query = url.split("?", 1)
    else:
        path, query = url, ""
    segs = [p for p in path.split("/") if p]
    return {
        "url_entropy": shannon(url),
        "header_count": int(header_count),
        "path_length": len(path),
        "url_special_count": sum(ch in SPECIALS for ch in url),
        "url_length": len(url),
        "path_segment_count": len(segs),
        "cookie_present": int(cookie),
        "query_length": len(query),
        "url_digit_count": sum(ch.isdigit() for ch in url),
        "user_agent_entropy": shannon(ua),
        "query_parameter_count": 0 if not query else query.count("&") + 1,
        "request_body_entropy": shannon(body),
        "request_body_digit_count": sum(ch.isdigit() for ch in body),
        "label": "Benign",
        "is_malicious": 0,
    }


def catalog_benign(n: int, rng: np.random.RandomState) -> pd.DataFrame:
    books = [101, 102, 201, 202, 301, 401, 402, 501, 502]
    searches = [
        "protocol",
        "database",
        "machine-learning",
        "O'Reilly",
        "C++ primer",
        "TLS 1.3",
        "public-key",
        "REST API",
        "a+b",
        "sort=title",
        "view=list",
        "q=network security",
    ]
    paths = [
        "/api/books",
        "/api/health",
        "/api/comments",
        "/",
        "/login",
        "/api/books/{id}",
        "/api/comments/book/{id}",
    ]
    bodies = ["", "username=user01&password=demo123", '{"title":"Applied ML"}', "rating=5"]
    rows = []
    for i in range(n):
        path = rng.choice(paths)
        if "{id}" in path:
            path = path.replace("{id}", str(int(rng.choice(books))))
        q = ""
        if rng.rand() < 0.55:
            term = searches[int(rng.randint(0, len(searches)))]
            key = rng.choice(["search", "q", "filter", "sort"])
            q = f"{key}={term}"
            if rng.rand() < 0.3:
                q += f"&page={int(rng.randint(1, 8))}"
        url = path if not q else f"{path}?{q}"
        ua = USER_AGENTS[int(rng.randint(0, len(USER_AGENTS)))]
        body = bodies[int(rng.randint(0, len(bodies)))] if rng.rand() < 0.25 else ""
        rows.append(
            extract_request(
                url,
                ua,
                body,
                header_count=int(rng.randint(3, 12)),
                cookie=int(rng.rand() < 0.35),
            )
        )
    return pd.DataFrame(rows)


def vector_key(df: pd.DataFrame, cols: list[str]) -> pd.Series:
    return df[cols].round(6).astype(str).agg("|".join, axis=1)


def collapse_unique(df: pd.DataFrame, cols: list[str], label_col: str, binary_col: str) -> pd.DataFrame:
    work = df.copy()
    work["_k"] = vector_key(work, cols)
    rows = []
    for _, g in work.groupby("_k", sort=False):
        if g[binary_col].nunique() > 1:
            continue
        mode_label = g[label_col].mode().iloc[0]
        rec = g.iloc[0][cols].to_dict()
        rec[label_col] = mode_label
        rec[binary_col] = int(g[binary_col].iloc[0])
        rows.append(rec)
    return pd.DataFrame(rows)


def metrics_at(y_true, scores, thresh: float) -> dict:
    pred = (scores >= thresh).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    n_neg = tn + fp
    return {
        "threshold": float(thresh),
        "accuracy": float(accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "fpr": float(fp / n_neg) if n_neg else 0.0,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def threshold_for_fpr(y_true, scores, target=TARGET_FPR) -> float:
    neg = scores[y_true == 0]
    if len(neg) == 0:
        return 0.5
    return float(np.quantile(neg, 1.0 - target))


def roc_pr(y_true, scores) -> dict:
    return {
        "roc_auc": float(roc_auc_score(y_true, scores)),
        "pr_auc": float(average_precision_score(y_true, scores)),
    }


def latency_ms(fn, X) -> float:
    fn(X[: min(16, len(X))])
    t0 = time.perf_counter()
    fn(X)
    return float((time.perf_counter() - t0) / len(X) * 1000.0)


def supervised_models():
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=120,
            max_depth=10,
            min_samples_leaf=15,
            min_samples_split=10,
            max_features="sqrt",
            class_weight="balanced",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        ),
        "Gradient boosting": HistGradientBoostingClassifier(
            max_depth=4,
            learning_rate=0.07,
            max_iter=140,
            l2_regularization=1.5,
            min_samples_leaf=20,
            random_state=RANDOM_SEED,
        ),
        "Extra Trees": ExtraTreesClassifier(
            n_estimators=120,
            max_depth=8,
            min_samples_leaf=20,
            min_samples_split=12,
            max_features="sqrt",
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
                        max_iter=2500,
                        C=0.35,
                        class_weight="balanced",
                        solver="lbfgs",
                        random_state=RANDOM_SEED,
                    ),
                ),
            ]
        ),
    }


class SequentialPatternReinforcer:
    """RF + historical attack prototypes + reward-tuned mix/threshold."""

    def __init__(self, n_estimators=120, max_depth=10):
        self.rf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_leaf=15,
            min_samples_split=10,
            max_features="sqrt",
            class_weight="balanced",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.prototypes: dict[str, np.ndarray] = {}
        self.proto_n: dict[str, int] = {}
        self.gamma = 1.0
        self.mix = 0.75
        self.threshold = 0.50

    def _rbf(self, X_scaled: np.ndarray) -> np.ndarray:
        if not self.prototypes:
            return np.zeros(len(X_scaled))
        sims = []
        for mu in self.prototypes.values():
            d2 = np.sum((X_scaled - mu) ** 2, axis=1)
            sims.append(np.exp(-self.gamma * d2))
        return np.max(np.vstack(sims), axis=0)

    def fit_base(self, X, y, labels):
        self.rf.fit(X, y)
        Xs = self.scaler.fit_transform(X)
        self.gamma = 1.0 / X.shape[1]
        for fam in sorted(set(labels)):
            if fam in ("Benign", "NORMAL"):
                continue
            mask = np.array(labels) == fam
            if mask.sum() < 8:
                continue
            self.prototypes[fam] = Xs[mask].mean(axis=0)
            self.proto_n[fam] = int(mask.sum())
        return self

    def scores(self, X) -> np.ndarray:
        p = self.rf.predict_proba(X)[:, 1]
        sim = self._rbf(self.scaler.transform(X))
        return self.mix * p + (1.0 - self.mix) * sim

    def reinforce(self, X_val, y_val, labels_val, request_index=None):
        mixes = [0.55, 0.7, 0.85, 1.0]
        best = None
        y_val = np.asarray(y_val)
        for mix in mixes:
            self.mix = mix
            sc = self.scores(X_val)
            thr = threshold_for_fpr(y_val, sc, TARGET_FPR)
            m = metrics_at(y_val, sc, thr)
            reward = 2.0 * m["recall"] - 3.0 * max(0.0, m["fpr"] - TARGET_FPR) + 0.5 * m["precision"]
            if request_index is not None:
                pred = (sc >= thr).astype(int)
                early = (np.asarray(request_index) <= 3) & (y_val == 1)
                if early.any():
                    reward += 0.75 * pred[early].mean()
            if best is None or reward > best[0]:
                best = (reward, mix, thr, m)
        self.mix, self.threshold = best[1], best[2]
        return {"mix": self.mix, "threshold": self.threshold, "val": best[3], "reward": best[0]}

    def update_online(self, X, y, labels, lr=0.08):
        Xs = self.scaler.transform(X)
        for i, yi in enumerate(y):
            if yi != 1:
                continue
            fam = labels[i]
            if fam in ("Benign", "NORMAL"):
                fam = "UNNAMED"
            if fam not in self.prototypes:
                self.prototypes[fam] = Xs[i]
                self.proto_n[fam] = 1
            else:
                n = self.proto_n[fam] + 1
                self.prototypes[fam] = (1 - lr) * self.prototypes[fam] + lr * Xs[i]
                self.proto_n[fam] = n


def split_unique(df, stratify, seed=RANDOM_SEED):
    idx = np.arange(len(df))
    tr, rest, ytr, yrest = train_test_split(
        idx, stratify, test_size=0.30, random_state=seed, stratify=stratify
    )
    va, te, _, _ = train_test_split(
        rest, yrest, test_size=0.50, random_state=seed, stratify=yrest
    )
    return tr, va, te


def eval_model(name, scores_val, scores_te, y_val, y_te, pred_fn, X_te):
    thr = threshold_for_fpr(y_val, scores_val, TARGET_FPR)
    row = metrics_at(y_te, scores_te, thr)
    row.update(roc_pr(y_te, scores_te))
    row["model"] = name
    row["latency_ms_per_row"] = latency_ms(pred_fn, X_te)
    return row, thr


def plot_bars(df, ycol, title, path, ylim=None):
    fig, ax = plt.subplots(figsize=(9.2, 4.3), dpi=150)
    ax.bar(df["model"], df[ycol], color="#3b6fb6")
    if ylim:
        ax.set_ylim(*ylim)
    ax.set_ylabel(ycol)
    ax.set_title(title)
    ax.tick_params(axis="x", rotation=20)
    for i, v in enumerate(df[ycol]):
        ax.text(i, v, f"{v:.3f}", ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def fmt6(x):
    return f"{x:.6f}"


def main():
    rng = np.random.RandomState(RANDOM_SEED)

    print("=== ATRDF unique-vector split + catalog benign ===")
    atr_tr = pd.read_csv(ROOT / "data/raw/atrdf/REQUEST_ONLY_train.csv")
    atr_te = pd.read_csv(ROOT / "data/raw/atrdf/REQUEST_ONLY_test.csv")
    raw = pd.concat([atr_tr, atr_te], ignore_index=True)
    unique = collapse_unique(raw, ATRDF_FEATURES, "label", "is_malicious")
    extra = catalog_benign(9000, rng)
    extra = extra[ATRDF_FEATURES + ["label", "is_malicious"]]
    extra["_k"] = vector_key(extra, ATRDF_FEATURES)
    seen = set(vector_key(unique, ATRDF_FEATURES))
    extra = extra.loc[~extra["_k"].isin(seen), ATRDF_FEATURES + ["label", "is_malicious"]]
    data = pd.concat([unique, extra], ignore_index=True)
    data = collapse_unique(data, ATRDF_FEATURES, "label", "is_malicious")
    print("unique rows", len(data), data["label"].value_counts().to_dict())

    y = data["is_malicious"].to_numpy(dtype=int)
    tr, va, te = split_unique(data, y)
    X = data[ATRDF_FEATURES].to_numpy(dtype=float)
    labels = data["label"].to_numpy()
    Xtr, Xva, Xte = X[tr], X[va], X[te]
    ytr, yva, yte = y[tr], y[va], y[te]
    lab_tr, lab_va, lab_te = labels[tr], labels[va], labels[te]
    print("split", len(tr), len(va), len(te), "pos_te", int(yte.sum()), "neg_te", int((yte == 0).sum()))

    atr_rows = []
    atr_scores = {}
    for name, model in supervised_models().items():
        print(" ATRDF", name)
        model.fit(Xtr, ytr)

        def _sc(Xm, m=model):
            return m.predict_proba(Xm)[:, 1]

        row, thr = eval_model(name, _sc(Xva), _sc(Xte), yva, yte, _sc, Xte)
        row["val_threshold"] = thr
        atr_rows.append(row)
        atr_scores[name] = _sc
        print("   ", {k: round(row[k], 4) for k in ["precision", "recall", "f1", "fpr", "roc_auc"]})

    print(" ATRDF Isolation Forest")
    iforest = IsolationForest(
        n_estimators=120, max_samples=256, contamination="auto", random_state=RANDOM_SEED, n_jobs=-1
    ).fit(Xtr[ytr == 0])

    def _if(Xm, m=iforest):
        return -m.score_samples(Xm)

    row, thr = eval_model("Isolation Forest", _if(Xva), _if(Xte), yva, yte, _if, Xte)
    row["val_threshold"] = thr
    atr_rows.append(row)
    print("   ", {k: round(row[k], 4) for k in ["precision", "recall", "f1", "fpr", "roc_auc"]})

    print(" ATRDF Sequential Pattern Reinforcer")
    spr = SequentialPatternReinforcer()
    spr.fit_base(Xtr, ytr, lab_tr)
    info = spr.reinforce(Xva, yva, lab_va)
    spr.update_online(Xva, yva, lab_va)
    spr_te = spr.scores(Xte)
    row = metrics_at(yte, spr_te, spr.threshold)
    row.update(roc_pr(yte, spr_te))
    row["model"] = "Pattern reinforcement"
    row["val_threshold"] = spr.threshold
    row["latency_ms_per_row"] = latency_ms(spr.scores, Xte)
    atr_rows.append(row)
    print("   mix", info["mix"], {k: round(row[k], 4) for k in ["precision", "recall", "f1", "fpr", "roc_auc"]})

    atr_df = pd.DataFrame(atr_rows)
    atr_df.to_csv(TABLE_DIR / "TABLE_VIII_unique_vector.csv", index=False)

    print("\n=== Future-attack leave-one-family-out (SPR + RF) ===")
    families = [c for c in sorted(data["label"].unique()) if c != "Benign"]
    loao = []
    for held in families:
        mask_tr = lab_tr != held
        if mask_tr.sum() < 200:
            continue
        rf = RandomForestClassifier(
            n_estimators=80,
            max_depth=10,
            min_samples_leaf=15,
            class_weight="balanced",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
        rf.fit(Xtr[mask_tr], ytr[mask_tr])
        spr_f = SequentialPatternReinforcer(n_estimators=80)
        spr_f.fit_base(Xtr[mask_tr], ytr[mask_tr], lab_tr[mask_tr])
        hold_va = (lab_va == held) | (yva == 0)
        hold_te = (lab_te == held) | (yte == 0)
        spr_f.reinforce(Xva[hold_va], yva[hold_va], lab_va[hold_va])
        sc_te = spr_f.scores(Xte[hold_te])
        m = metrics_at(yte[hold_te], sc_te, spr_f.threshold)
        m["held_out_attack"] = held
        m["model"] = "Pattern reinforcement"
        m["held_out_support"] = int((lab_te == held).sum())
        loao.append(m)
        sc_rf = rf.predict_proba(Xte[hold_te])[:, 1]
        thr_rf = threshold_for_fpr(yva[hold_va], rf.predict_proba(Xva[hold_va])[:, 1], TARGET_FPR)
        m2 = metrics_at(yte[hold_te], sc_rf, thr_rf)
        m2["held_out_attack"] = held
        m2["model"] = "Random Forest"
        m2["held_out_support"] = int((lab_te == held).sum())
        loao.append(m2)
        print(f"  {held}: SPR rec={m['recall']:.3f} prec={m['precision']:.3f}  RF rec={m2['recall']:.3f} prec={m2['precision']:.3f}")
    loao_df = pd.DataFrame(loao)
    loao_df.to_csv(TABLE_DIR / "TABLE_VIII_b_future_attacks.csv", index=False)

    print("\n=== BOLA session-disjoint, no owner proxies, 1% FPR ===")
    bola = pd.read_csv(ROOT / "data/raw/vampi/vampi_v6_2_50000_ML_READY.csv")
    sessions = bola["session_id"].unique()
    rng.shuffle(sessions)
    n = len(sessions)
    n_tr, n_va = int(n * 0.70), int(n * 0.15)
    s_tr, s_va, s_te = set(sessions[:n_tr]), set(sessions[n_tr : n_tr + n_va]), set(sessions[n_tr + n_va :])
    btr = bola[bola["session_id"].isin(s_tr)]
    bva = bola[bola["session_id"].isin(s_va)]
    bte = bola[bola["session_id"].isin(s_te)]
    Xbtr = btr[BOLA_FEATURES].to_numpy(float)
    Xbva = bva[BOLA_FEATURES].to_numpy(float)
    Xbte = bte[BOLA_FEATURES].to_numpy(float)
    ybtr = btr["target"].to_numpy(int)
    ybva = bva["target"].to_numpy(int)
    ybte = bte["target"].to_numpy(int)
    print("sessions", len(s_tr), len(s_va), len(s_te), "rows te", len(bte))

    bola_rows = []
    for name, model in supervised_models().items():
        print(" BOLA", name)
        model.fit(Xbtr, ybtr)

        def _sc(Xm, m=model):
            return m.predict_proba(Xm)[:, 1]

        row, thr = eval_model(name, _sc(Xbva), _sc(Xbte), ybva, ybte, _sc, Xbte)
        row["val_threshold"] = thr
        bola_rows.append(row)
        print("   ", {k: round(row[k], 4) for k in ["precision", "recall", "f1", "fpr", "roc_auc"]})

    iforest_b = IsolationForest(
        n_estimators=120, max_samples=256, contamination="auto", random_state=RANDOM_SEED, n_jobs=-1
    ).fit(Xbtr[ybtr == 0])

    def _ifb(Xm, m=iforest_b):
        return -m.score_samples(Xm)

    row, thr = eval_model("Isolation Forest", _ifb(Xbva), _ifb(Xbte), ybva, ybte, _ifb, Xbte)
    row["val_threshold"] = thr
    bola_rows.append(row)

    spr_b = SequentialPatternReinforcer()
    lab_btr = np.where(ybtr == 1, "BOLA", "NORMAL")
    lab_bva = np.where(ybva == 1, "BOLA", "NORMAL")
    spr_b.fit_base(Xbtr, ybtr, lab_btr)
    spr_b.reinforce(Xbva, ybva, lab_bva, request_index=bva["request_index"].to_numpy())
    spr_b.update_online(Xbva, ybva, lab_bva)
    scb = spr_b.scores(Xbte)
    row = metrics_at(ybte, scb, spr_b.threshold)
    row.update(roc_pr(ybte, scb))
    row["model"] = "Pattern reinforcement"
    row["val_threshold"] = spr_b.threshold
    row["latency_ms_per_row"] = latency_ms(spr_b.scores, Xbte)
    bola_rows.append(row)
    bola_df = pd.DataFrame(bola_rows)
    bola_df.to_csv(TABLE_DIR / "TABLE_IX_bola_offline_comparison.csv", index=False)

    print("\n=== BOLA early detection (request_index <= k), SPR ===")
    early_rows = []
    for k in (2, 3, 5, 10):
        mk = bte["request_index"].to_numpy() <= k
        m = metrics_at(ybte[mk], scb[mk], spr_b.threshold)
        m["k"] = k
        m["rows"] = int(mk.sum())
        early_rows.append(m)
        print(f"  k={k} prec={m['precision']:.3f} rec={m['recall']:.3f} f1={m['f1']:.3f} fpr={m['fpr']:.3f}")
    early_df = pd.DataFrame(early_rows)
    early_df.to_csv(TABLE_DIR / "TABLE_IX_b_bola_early_detection.csv", index=False)

    plot_bars(atr_df, "f1", "ATRDF F1 at 1% validation FPR", FIG_DIR / "fig7_atrdf_algorithm_comparison.png", (0, 1.05))
    plot_bars(bola_df, "f1", "BOLA F1 at 1% validation FPR", FIG_DIR / "fig8_bola_algorithm_comparison.png", (0, 1.05))
    if not loao_df.empty:
        spr_loao = loao_df[loao_df["model"] == "Pattern reinforcement"]
        fig, ax = plt.subplots(figsize=(9.2, 4.3), dpi=150)
        ax.bar(spr_loao["held_out_attack"], spr_loao["recall"], color="#6b4c9a")
        ax.set_ylim(0, 1.05)
        ax.set_ylabel("Recall of held-out family")
        ax.set_title("Future-attack detection (leave-one-family-out, SPR)")
        ax.tick_params(axis="x", rotation=25)
        fig.tight_layout()
        fig.savefig(FIG_DIR / "fig7b_future_attack_recall.png")
        plt.close(fig)

    joblib.dump(spr, ART / "atrdf_pattern_reinforcer.joblib")
    joblib.dump(spr_b, ART / "bola_pattern_reinforcer.joblib")
    rf_live = RandomForestClassifier(
        n_estimators=120,
        max_depth=10,
        min_samples_leaf=15,
        min_samples_split=10,
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    rf_live.fit(Xtr, ytr)
    joblib.dump(rf_live, ART / "atrdf_binary_rf_regularized.joblib")

    protocol = {
        "target_fpr_validation": TARGET_FPR,
        "random_seed": RANDOM_SEED,
        "atrdf_unique_rows": int(len(data)),
        "atrdf_split": {"train": int(len(tr)), "val": int(len(va)), "test": int(len(te))},
        "atrdf_test_prevalence": float(yte.mean()),
        "spr_atrdf": {"mix": spr.mix, "threshold": spr.threshold},
        "spr_bola": {"mix": spr_b.mix, "threshold": spr_b.threshold},
        "note": "Production models/ joblib files were not overwritten.",
    }
    with open(OUT / "protocol.json", "w", encoding="utf-8") as f:
        json.dump(protocol, f, indent=2)

    def compact(df):
        cols = ["model", "accuracy", "precision", "recall", "f1", "fpr", "roc_auc", "pr_auc", "threshold", "latency_ms_per_row"]
        return df[cols]

    print("\nTABLE VIII")
    print(compact(atr_df).to_string(index=False))
    print("\nTABLE IX")
    print(compact(bola_df).to_string(index=False))
    with open(OUT / "summary.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "atrdf": compact(atr_df).to_dict(orient="records"),
                "bola": compact(bola_df).to_dict(orient="records"),
            },
            f,
            indent=2,
        )


if __name__ == "__main__":
    main()
