import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

atr_tr = pd.read_csv(r"data/raw/atrdf/REQUEST_ONLY_train.csv")
atr_te = pd.read_csv(r"data/raw/atrdf/REQUEST_ONLY_test.csv")
feats = [c for c in atr_tr.columns if c not in ["label", "is_malicious"]]
print("ATRDF train", len(atr_tr), "test", len(atr_te))
print("train labels", atr_tr["label"].value_counts().to_dict())
print("test labels", atr_te["label"].value_counts().to_dict())

key_tr = atr_tr[feats].round(6).astype(str).agg("|".join, axis=1)
key_te = atr_te[feats].round(6).astype(str).agg("|".join, axis=1)
overlap = len(set(key_tr) & set(key_te))
print("unique train vectors", key_tr.nunique(), "unique test", key_te.nunique(), "overlapping vectors", overlap)
print("test rows whose vector appears in train", float(key_te.isin(set(key_tr)).mean()))
print("header_count mean by label:")
print(atr_tr.groupby("label")["header_count"].mean().round(3))
print("header_count corr", float(atr_tr["header_count"].corr(atr_tr["is_malicious"])))

bola = pd.read_csv(r"data/raw/vampi/vampi_v6_2_50000_ML_READY.csv")
print("\nBOLA", len(bola), "sessions", bola["session_id"].nunique())
print("label", bola["label"].value_counts().to_dict())
print("classification", bola["classification"].value_counts().to_dict())
print("session_type", bola["session_type"].value_counts().to_dict())
print("mixed-label sessions", int((bola.groupby("session_id")["label"].nunique() > 1).sum()))

cols = [
    "unique_owners_recent", "owner_switch", "cross_owner_count_recent",
    "cross_owner_ratio_recent", "same_owner_ratio_recent", "request_frequency",
    "unique_objects_recent", "object_switch", "same_object_repeat_ratio",
    "time_since_previous_request", "request_burst_rate", "hour",
    "session_length", "request_index",
]
print("\nBOLA corr with target:")
for c in cols:
    print(f"  {c:30s} {bola[c].corr(bola['target']): .4f}")

y = bola["target"].values
for name, pred in [
    ("cross_owner_ratio>0", (bola["cross_owner_ratio_recent"] > 0).astype(int)),
    ("cross_owner_count>0", (bola["cross_owner_count_recent"] > 0).astype(int)),
    ("same_owner_ratio<1", (bola["same_owner_ratio_recent"] < 1).astype(int)),
]:
    print(
        name,
        round(accuracy_score(y, pred), 4),
        round(precision_score(y, pred), 4),
        round(recall_score(y, pred), 4),
        round(f1_score(y, pred), 4),
    )
