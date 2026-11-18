"""Live Sequential Pattern Reinforcement detector.

Combines a Random Forest with per-family prototypes that update when a
confirmed attack label arrives. The gateway profile name is
`pattern-reinforcement`. Feature names match the Java extractors.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

PROFILE_SPR = "pattern-reinforcement"

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
    "unique_owners_recent",
    "owner_switch",
    "cross_owner_count_recent",
    "cross_owner_ratio_recent",
    "same_owner_ratio_recent",
    "same_object_repeat_ratio",
    "time_since_previous_request",
    "request_burst_rate",
    "hour",
    "session_length",
    "request_index",
]


class SequentialPatternReinforcer:
    def __init__(self, n_estimators=100, max_depth=10, random_state=42):
        self.rf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_leaf=15,
            min_samples_split=10,
            max_features="sqrt",
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.prototypes = {}
        self.proto_n = {}
        self.gamma = 1.0
        self.mix = 0.75
        self.threshold = 0.50
        self.feature_names = []
        self._lock = threading.Lock()

    def __getstate__(self):
        state = self.__dict__.copy()
        state.pop("_lock", None)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._lock = threading.Lock()

    def fit_base(self, X, y, labels, feature_names):
        self.feature_names = list(feature_names)
        self.rf.fit(X, y)
        Xs = self.scaler.fit_transform(X)
        self.gamma = 1.0 / max(X.shape[1], 1)
        self.prototypes = {}
        self.proto_n = {}
        labels = np.asarray(labels)
        for fam in sorted(set(labels)):
            if fam in ("Benign", "NORMAL", "BENIGN"):
                continue
            mask = labels == fam
            if mask.sum() < 8:
                continue
            self.prototypes[fam] = Xs[mask].mean(axis=0)
            self.proto_n[fam] = int(mask.sum())
        return self

    def _rbf_all(self, X_scaled: np.ndarray) -> np.ndarray:
        if not self.prototypes:
            return np.zeros(len(X_scaled))
        sims = []
        for mu in self.prototypes.values():
            d2 = np.sum((X_scaled - mu) ** 2, axis=1)
            sims.append(np.exp(-self.gamma * d2))
        return np.max(np.vstack(sims), axis=0)

    def scores(self, X) -> np.ndarray:
        p = self.rf.predict_proba(X)[:, 1]
        sim = self._rbf_all(self.scaler.transform(X))
        return self.mix * p + (1.0 - self.mix) * sim

    def nearest_family(self, X_one) -> tuple[str | None, float]:
        Xs = self.scaler.transform(X_one)
        best_name, best = None, -1.0
        for name, mu in self.prototypes.items():
            sim = float(np.exp(-self.gamma * np.sum((Xs[0] - mu) ** 2)))
            if sim > best:
                best_name, best = name, sim
        return best_name, best

    def decide(self, X_one) -> dict:
        score = float(self.scores(X_one)[0])
        p_rf = float(self.rf.predict_proba(X_one)[0, 1])
        family, sim = self.nearest_family(X_one)
        is_pos = score >= self.threshold
        return {
            "score": score,
            "rf_probability": p_rf,
            "pattern_similarity": sim if family else 0.0,
            "nearest_family": family,
            "positive": is_pos,
            "threshold": self.threshold,
            "mix": self.mix,
        }

    def update_online(self, X_one, label: str, lr=0.08):
        """Update prototypes from a confirmed attack. Benign labels are ignored."""
        if label in ("Benign", "BENIGN", "NORMAL", None, ""):
            return False
        fam = label
        if fam.upper() == "MALICIOUS":
            fam = self.nearest_family(X_one)[0] or "UNNAMED"
        with self._lock:
            Xs = self.scaler.transform(X_one)[0]
            if fam not in self.prototypes:
                self.prototypes[fam] = Xs.copy()
                self.proto_n[fam] = 1
            else:
                self.prototypes[fam] = (1 - lr) * self.prototypes[fam] + lr * Xs
                self.proto_n[fam] = int(self.proto_n[fam]) + 1
        return True

    def prototype_summary(self) -> dict:
        return {
            "families": list(self.prototypes.keys()),
            "counts": {k: int(v) for k, v in self.proto_n.items()},
            "mix": self.mix,
            "threshold": self.threshold,
            "feature_names": self.feature_names,
        }


def save_spr(model: SequentialPatternReinforcer, path: Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    meta = model.prototype_summary()
    with open(path.with_suffix(".json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


def load_spr(path: Path) -> SequentialPatternReinforcer:
    model = joblib.load(path)
    if not hasattr(model, "_lock"):
        model._lock = threading.Lock()
    return model
